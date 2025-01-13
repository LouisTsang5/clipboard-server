use std::io::Read;

use aes_gcm::{
    aead::{rand_core::RngCore, Aead, OsRng},
    Aes256Gcm, KeyInit,
};

const KEY_LEN: usize = 32;
const SALT_LEN: usize = 8;
const KEY_GEN_ROUNDS: u32 = 10_000;
const NONCE_LEN: usize = 12;
const AES_GCM_AUTH_TAG_LEN: usize = 16;

struct EncryptionBlock<'a> {
    ciphertext: &'a [u8],
    padding_len: usize,
}

impl<'a> EncryptionBlock<'a> {
    fn enc_block_size(plaintext_block_size: usize) -> usize {
        plaintext_block_size + AES_GCM_AUTH_TAG_LEN + std::mem::size_of::<usize>()
    }

    fn iter(&'a self) -> EncryptionBlockIter<'a> {
        EncryptionBlockIter {
            is_done_iter_padding: false,
            padding_iter: self.padding_len.to_le_bytes().into_iter(),
            ciphertext_iter: self.ciphertext.iter(),
        }
    }

    fn from_bytes(bytes: &'a [u8]) -> Result<Self, std::array::TryFromSliceError> {
        let padding_len_size = std::mem::size_of::<usize>();
        let padding_len = usize::from_le_bytes(bytes[..padding_len_size].try_into()?);
        let ciphertext = &bytes[padding_len_size..];
        Ok(Self {
            ciphertext,
            padding_len,
        })
    }
}

const PADDING_ARR_SIZE: usize = std::mem::size_of::<usize>();
struct EncryptionBlockIter<'a> {
    is_done_iter_padding: bool,
    padding_iter: std::array::IntoIter<u8, PADDING_ARR_SIZE>,
    ciphertext_iter: std::slice::Iter<'a, u8>,
}

impl Iterator for EncryptionBlockIter<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_done_iter_padding {
            return self.ciphertext_iter.next().copied();
        }

        match self.padding_iter.next() {
            None => {
                self.is_done_iter_padding = true;
                self.ciphertext_iter.next().copied()
            }
            Some(n) => Some(n),
        }
    }
}

#[test]
fn test_enc_block_to_bytes() {
    let ciphertext = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
    let padding_len = 4;
    let eb = EncryptionBlock {
        ciphertext: &ciphertext,
        padding_len,
    };

    let mut expected = Vec::with_capacity(12);
    expected.extend_from_slice(&padding_len.to_le_bytes());
    expected.extend_from_slice(&ciphertext);
    assert_eq!(eb.iter().collect::<Vec<u8>>(), expected);
}

#[test]
fn test_enc_block_from_bytes() {
    let ciphertext = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
    let padding_len = 4usize;
    let mut bytes = Vec::with_capacity(12);
    bytes.extend_from_slice(&padding_len.to_le_bytes());
    bytes.extend_from_slice(&ciphertext);
    let eb = EncryptionBlock::from_bytes(&bytes);

    assert!(match eb {
        Ok(_) => true,
        Err(_) => false,
    });

    let eb = eb.unwrap();

    let expected_eb = EncryptionBlock {
        ciphertext: &ciphertext,
        padding_len,
    };
    assert_eq!(eb.ciphertext, expected_eb.ciphertext);
    assert_eq!(eb.padding_len, expected_eb.padding_len);
}

type Key = [u8; KEY_LEN];
type Salt = [u8; SALT_LEN];
type Nonce = [u8; NONCE_LEN];

fn derive_key(password: &str, salt: Option<Salt>) -> (Key, Salt) {
    let mut key = [0u8; KEY_LEN];
    let salt: Salt = match salt {
        Some(s) => s,
        None => {
            let mut s: Salt = [0u8; SALT_LEN];
            OsRng.fill_bytes(&mut s);
            s
        }
    };
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
        password.as_bytes(),
        &salt,
        KEY_GEN_ROUNDS,
        key.as_mut(),
    )
    .unwrap();
    (key, salt)
}

pub struct EncryptionStream<T: Read> {
    cipher: Aes256Gcm,
    nonce: Nonce,
    block_size: usize,
    stream: T,
    encrypted_buff: Vec<u8>,
    plaintext_buff: Box<[u8]>,
}

impl<T: Read> EncryptionStream<T> {
    pub fn new(password: &str, stream: T, block_size: usize) -> Self {
        // Derive key and cipher
        let (key, salt) = derive_key(password, None);
        let cipher = Aes256Gcm::new(&key.into());

        // Derive nonce
        let mut nonce = [0; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        // Put salt and nonce into the intermediate buffer first
        let mut encrypted_buff = Vec::with_capacity(EncryptionBlock::enc_block_size(block_size));
        encrypted_buff.extend_from_slice(&salt);
        encrypted_buff.extend_from_slice(&nonce);
        encrypted_buff.extend_from_slice(&block_size.to_le_bytes());

        // Construct the stream
        EncryptionStream {
            cipher,
            nonce,
            block_size,
            stream,
            encrypted_buff,
            plaintext_buff: vec![0u8; block_size].into(),
        }
    }
}

impl<T: Read> Read for EncryptionStream<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // If intermediate buffer is empty, encrypt and push to buffer
        if self.encrypted_buff.is_empty() {
            // Read plain text into buffer
            let bytes_read = self.stream.read(&mut self.plaintext_buff)?;
            if bytes_read == 0 {
                return Ok(0);
            }
            let padding_len = self.block_size - bytes_read;

            // Encrypt text
            let ciphertext = self
                .cipher
                .encrypt(&self.nonce.into(), &self.plaintext_buff[..])
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            // Format and store ciphertexgt
            let enc_block = EncryptionBlock {
                ciphertext: &ciphertext,
                padding_len,
            };
            self.encrypted_buff.extend(enc_block.iter());
        }

        // Fill the buffer
        let read_len = std::cmp::min(self.encrypted_buff.len(), buf.len());
        for (i, b) in self.encrypted_buff.drain(..read_len).enumerate() {
            buf[i] = b;
        }

        Ok(read_len)
    }
}

pub struct DecryptionStream<T: Read> {
    cipher: Aes256Gcm,
    nonce: Nonce,
    block_size: usize,
    stream: T,
    plaintext_buff: Vec<u8>,
    encrypted_buff: Box<[u8]>,
}

impl<T: Read> DecryptionStream<T> {
    pub fn new(password: &str, mut stream: T) -> std::io::Result<Self> {
        // Read salt
        let mut salt: Salt = [0; SALT_LEN];
        stream.read_exact(&mut salt).map_err(|e| {
            std::io::Error::new(e.kind(), format!("Unable to determine salt. ({})", e))
        })?;

        // Read nonce
        let mut nonce: Nonce = [0; NONCE_LEN];
        stream.read_exact(&mut nonce).map_err(|e| {
            std::io::Error::new(e.kind(), format!("Unable to determine nonce. ({})", e))
        })?;

        // Read block size
        let mut block_size = [0u8; std::mem::size_of::<usize>()];
        stream.read_exact(&mut block_size).map_err(|e| {
            std::io::Error::new(e.kind(), format!("Unable to determine block size. ({})", e))
        })?;
        let block_size = usize::from_le_bytes(block_size);

        // Derive key and cipher
        let (key, _) = derive_key(password, Some(salt));
        let cipher = Aes256Gcm::new(&key.into());

        // Construct the stream
        Ok(DecryptionStream {
            cipher,
            nonce,
            block_size,
            stream,
            plaintext_buff: Vec::with_capacity(block_size),
            encrypted_buff: vec![0u8; EncryptionBlock::enc_block_size(block_size)].into(),
        })
    }

    pub fn block_size(&self) -> usize {
        self.block_size
    }
}

impl<T: Read> Read for DecryptionStream<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Decrypt a block and store it to inter buff
        if self.plaintext_buff.is_empty() {
            // Read encrypted bytes
            let enc_block_size = EncryptionBlock::enc_block_size(self.block_size);
            let mut total_bytes_read = 0;
            loop {
                let bytes_read = self
                    .stream
                    .read(&mut self.encrypted_buff[total_bytes_read..])?;
                total_bytes_read += bytes_read;
                if bytes_read == 0 || total_bytes_read >= enc_block_size {
                    break;
                }
            }

            // Return EOF if no bytes can be read
            if total_bytes_read == 0 {
                return Ok(0);
            }

            // Return Unexpected EOF if total bytes are not equal to enc_block_size
            if total_bytes_read < enc_block_size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("Unexpected EOF while reading ciphertext (Expected {} bytes. Read {} bytes instead)", enc_block_size, total_bytes_read),
                ));
            }

            // Decrypt bytes and store it to inter buff
            let EncryptionBlock {
                ciphertext,
                padding_len,
            } = match EncryptionBlock::from_bytes(&self.encrypted_buff) {
                Ok(eb) => eb,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("{}", e),
                    ))
                }
            };
            let dec_bytes = self
                .cipher
                .decrypt(&self.nonce.into(), ciphertext)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            self.plaintext_buff
                .extend_from_slice(&dec_bytes[..dec_bytes.len() - padding_len]);
        }

        // Fill the buffer
        let read_len = std::cmp::min(self.plaintext_buff.len(), buf.len());
        for (i, b) in self.plaintext_buff.drain(..read_len).enumerate() {
            buf[i] = b;
        }

        Ok(read_len)
    }
}
