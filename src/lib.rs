use aes_gcm::aead::rand_core::RngCore;
use std::{error::Error, io::Write, mem::size_of};

pub const END_OF_MSG: u8 = 0;
pub const END_OF_MSG_SIZE: usize = std::mem::size_of::<u8>();

pub mod enc;
pub mod tar;

pub fn rand_alphanumeric(len: usize) -> String {
    const CHARS: [(u8, u8); 3] = [(b'a', b'z'), (b'A', b'Z'), (b'0', b'9')];
    let chars: Vec<u8> = CHARS.iter().flat_map(|(s, e)| *s..=*e).collect();
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        let mut rand_index = [0u8; size_of::<usize>()];
        aes_gcm::aead::OsRng.fill_bytes(&mut rand_index);
        let rand_index = usize::from_le_bytes(rand_index) % chars.len();
        s.push(chars[rand_index] as char);
    }
    s
}

pub fn log(msg: &str) {
    println!(
        "[{}] {}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        msg
    );
}

pub fn print_progress(percentage: f32, bar_width: usize) {
    let num_bars = (percentage * bar_width as f32) as usize;
    let bar_str = format!(
        "\r{:.1}%[{}{}]",
        percentage * 100 as f32,
        "=".repeat(num_bars),
        " ".repeat(bar_width - num_bars),
    );
    let mut stdout = std::io::stdout();
    stdout.write(&bar_str.as_bytes()).unwrap();
    stdout.flush().unwrap();
}

#[derive(Debug)]
pub enum Metadata {
    Text { size: usize },
    File { size: usize, name: String },
}

const TYPE_TEXT: u8 = 0;
const TYPE_FILE: u8 = 1;
const TYPE_SIZE: usize = std::mem::size_of::<u8>();
pub const COMMON_HEADER_SIZE: usize = TYPE_SIZE + std::mem::size_of::<usize>();
pub const INIT_METADATA_BUFF_SIZE: usize = COMMON_HEADER_SIZE + 64; // +64 byte buffer for filename

impl Metadata {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(INIT_METADATA_BUFF_SIZE); // +64 byte buffer for filename
        let (type_byte, size_bytes, file_name_bytes) = match self {
            Metadata::Text { size } => (TYPE_TEXT, size.to_le_bytes(), None),
            Metadata::File { name, size } => (TYPE_FILE, size.to_le_bytes(), Some(name.as_bytes())),
        };
        bytes.push(type_byte);
        bytes.extend_from_slice(&size_bytes);
        if let Some(f_bytes) = file_name_bytes {
            bytes.extend_from_slice(f_bytes);
        }
        bytes
    }

    pub fn size(&self) -> usize {
        match self {
            Self::File { size, name: _ } => *size,
            Self::Text { size } => *size,
        }
    }
}

impl TryFrom<&[u8]> for Metadata {
    type Error = Box<dyn Error>;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < COMMON_HEADER_SIZE {
            return Err("Metadata malformed (Invalid data size)".into());
        }
        let type_byte = value[0];
        let size = usize::from_le_bytes(value[TYPE_SIZE..COMMON_HEADER_SIZE].try_into()?);
        match type_byte {
            TYPE_TEXT => Ok(Metadata::Text { size }),
            TYPE_FILE => {
                if value.len() <= COMMON_HEADER_SIZE {
                    return Err("Metadata malformed (Cannot determine file name)".into());
                }
                let name = String::from_utf8(value[COMMON_HEADER_SIZE..].to_vec())?;
                Ok(Metadata::File { name, size })
            }
            _ => return Err("Metadata malformed (Invalid metadata type)".into()),
        }
    }
}
