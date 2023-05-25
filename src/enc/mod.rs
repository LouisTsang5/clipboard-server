use aes_gcm::{
    aead::{generic_array::GenericArray, rand_core::RngCore, Aead, OsRng},
    Aes256Gcm, KeyInit,
};

const KEY_LEN: usize = 32;
const SALT_LEN: usize = 8;
const KEY_GEN_ROUNDS: u32 = 10_000;
const NONCE_LEN: usize = 12;

struct EncryptionBlock {
    ciphertext: Vec<u8>,
    padding_len: usize,
}

impl EncryptionBlock {
    fn enc_block_size(plaintext_block_size: usize) -> usize {
        plaintext_block_size + 16 + std::mem::size_of::<usize>()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.ciphertext.len() + std::mem::size_of::<usize>());
        bytes.extend_from_slice(&self.padding_len.to_le_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, std::array::TryFromSliceError> {
        let padding_len_size = std::mem::size_of::<usize>();
        let padding_len = usize::from_le_bytes(bytes[..padding_len_size].try_into()?);
        let ciphertext = bytes[padding_len_size..].to_vec();
        Ok(Self {
            ciphertext,
            padding_len,
        })
    }
}

#[test]
fn test_enc_block_to_bytes() {
    let ciphertext = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
    let padding_len = 4;
    let eb = EncryptionBlock {
        ciphertext: ciphertext.clone(),
        padding_len,
    };

    let mut expected = Vec::with_capacity(12);
    expected.extend_from_slice(&padding_len.to_le_bytes());
    expected.extend_from_slice(&ciphertext);
    assert_eq!(eb.to_bytes(), expected);
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
        ciphertext,
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

pub struct EncryptionStream<'a, R: std::io::Read> {
    cipher: Aes256Gcm,
    nonce: Nonce,
    block_size: usize,
    stream: &'a mut R,
    inter_buff: Vec<u8>,
}

impl<'a, R: std::io::Read> EncryptionStream<'a, R> {
    pub fn new(password: &str, stream: &'a mut R, block_size: usize) -> Self {
        // Derive key and cipher
        let (key, salt) = derive_key(password, None);
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));

        // Derive nonce
        let mut nonce = [0; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        // Put salt and nonce into the intermediate buffer first
        let mut inter_buff = Vec::with_capacity(EncryptionBlock::enc_block_size(block_size));
        inter_buff.extend_from_slice(&salt);
        inter_buff.extend_from_slice(&nonce);
        inter_buff.extend_from_slice(&block_size.to_le_bytes());

        // Construct the stream
        EncryptionStream {
            cipher,
            nonce,
            block_size,
            stream,
            inter_buff,
        }
    }
}

impl<'a, R: std::io::Read> std::io::Read for EncryptionStream<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // If intermediate buffer is empty, encrypt and push to buffer
        if self.inter_buff.len() <= 0 {
            // Read plain text into buffer
            let mut plaintext_buff = vec![0u8; self.block_size];
            let bytes_read = self.stream.read(&mut plaintext_buff)?;
            if bytes_read <= 0 {
                return Ok(0);
            }
            let padding_len = self.block_size - bytes_read;

            // Encrypt text
            let ciphertext = match self
                .cipher
                .encrypt(GenericArray::from_slice(&self.nonce), &plaintext_buff[..])
            {
                Ok(b) => b,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("{}", e),
                    ))
                }
            };

            // Format and store ciphertexgt
            let enc_block = EncryptionBlock {
                ciphertext,
                padding_len,
            };
            self.inter_buff.extend(enc_block.to_bytes());
        }

        // Fill the buffer
        let read_len = match buf.len() > self.inter_buff.len() {
            true => self.inter_buff.len(),
            false => buf.len(),
        };
        buf[..read_len].copy_from_slice(&self.inter_buff[..read_len]);

        // Trim the intermediate buffer
        self.inter_buff.drain(0..read_len);

        Ok(read_len)
    }
}

pub struct DecryptionStream<'a, R: std::io::Read> {
    cipher: Aes256Gcm,
    nonce: Nonce,
    block_size: usize,
    stream: &'a mut R,
    inter_buff: Vec<u8>,
}

impl<'a, R: std::io::Read> DecryptionStream<'a, R> {
    pub fn new(password: &str, stream: &'a mut R) -> Result<Self, Box<dyn std::error::Error>> {
        // Read salt
        let mut salt: Salt = [0; SALT_LEN];
        if let Err(e) = stream.read_exact(&mut salt) {
            return Err(
                std::io::Error::new(e.kind(), format!("Unable to determine salt. ({e})")).into(),
            );
        }

        // Read nonce
        let mut nonce: Nonce = [0; NONCE_LEN];
        if let Err(e) = stream.read_exact(&mut nonce) {
            return Err(
                std::io::Error::new(e.kind(), format!("Unable to determine nonce. ({e})")).into(),
            );
        }

        // Read block size
        let mut block_size = [0u8; std::mem::size_of::<usize>()];
        if let Err(e) = stream.read_exact(&mut block_size) {
            return Err(std::io::Error::new(
                e.kind(),
                format!("Unable to determine block size. ({e})"),
            )
            .into());
        }
        let block_size = usize::from_le_bytes(block_size);

        // Derive key and cipher
        let (key, _) = derive_key(password, Some(salt));
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));

        // Construct the stream
        Ok(DecryptionStream {
            cipher,
            nonce,
            block_size,
            stream,
            inter_buff: Vec::with_capacity(block_size),
        })
    }
}

impl<'a, R: std::io::Read> std::io::Read for DecryptionStream<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Decrypt a block and store it to inter buff
        if self.inter_buff.len() <= 0 {
            // Read encrypted bytes
            let enc_block_size = EncryptionBlock::enc_block_size(self.block_size);
            let mut buff = vec![0u8; enc_block_size];
            let bytes_read = self.stream.read(&mut buff)?;
            if bytes_read <= 0 {
                return Ok(0);
            }
            if bytes_read < enc_block_size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!(
                        "Unexpected end of stream. Expected {} bytes. Read {} bytes instead",
                        enc_block_size, bytes_read
                    ),
                ));
            }

            // Decrypt bytes and store it to inter buff
            let EncryptionBlock {
                ciphertext,
                padding_len,
            } = match EncryptionBlock::from_bytes(&buff) {
                Ok(eb) => eb,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("{}", e),
                    ))
                }
            };
            let dec_bytes = match self
                .cipher
                .decrypt(GenericArray::from_slice(&self.nonce), &ciphertext[..])
            {
                Ok(b) => b,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("{}", e),
                    ))
                }
            };
            self.inter_buff
                .extend_from_slice(&dec_bytes[..dec_bytes.len() - padding_len]);
        }

        // Fill the buffer
        let read_len = match buf.len() > self.inter_buff.len() {
            true => self.inter_buff.len(),
            false => buf.len(),
        };
        buf[..read_len].copy_from_slice(&self.inter_buff[..read_len]);

        // Trim the intermediate buffer
        self.inter_buff.drain(0..read_len);

        Ok(read_len)
    }
}
