use std::{
    env,
    error::Error,
    fs::{self, File},
    io::{self, Cursor, Read},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
};

use clipboard_server::{
    enc::EncryptionStream, log, rand_alphanumeric, tar::tar_dir, Metadata, END_OF_MSG,
};
use flate2::{read::ZlibEncoder, Compression};

#[derive(Debug)]
enum ClipboardContent {
    Text(String),
    File(String),
    Dir {
        path: String,
        archive_file: Option<String>,
    },
}

impl ClipboardContent {
    fn metadata(&self) -> Result<Metadata, io::Error> {
        match self {
            ClipboardContent::Text(text) => Ok(Metadata::Text { size: text.len() }),
            ClipboardContent::File(path) => {
                let path = Path::new(path);
                let f_metadata = fs::metadata(path)?;
                Ok(Metadata::File {
                    size: f_metadata.len() as usize,
                    name: path.file_name().unwrap().to_str().unwrap().to_string(),
                })
            }
            ClipboardContent::Dir { path, archive_file } => match archive_file {
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "Cannot find archive file",
                )),
                Some(f) => {
                    let mut name = Path::new(path)
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .to_string();
                    name.push_str(".tar");
                    let size = fs::metadata(Path::new(f))?.len() as usize;
                    Ok(Metadata::File { size, name })
                }
            },
        }
    }

    fn content_stream(&self) -> Result<Box<dyn Read>, io::Error> {
        match self {
            ClipboardContent::Text(text) => Ok(Box::new(Cursor::new(text.to_owned()))),
            ClipboardContent::File(path) => Ok(Box::new(File::open(path)?)),
            ClipboardContent::Dir {
                path: _,
                archive_file,
            } => match archive_file {
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "Cannot find archive file",
                )),
                Some(f) => Ok(Box::new(File::open(f)?)),
            },
        }
    }
}

fn get_clipboard_content() -> Result<ClipboardContent, Box<dyn Error>> {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg("pbpaste -Prefer 'public.file-url'")
        .output()?
        .stdout;
    let clipboard = String::from_utf8(output)?;

    const FILE_URL_PREFIX: &str = "file://";

    if clipboard.len() >= FILE_URL_PREFIX.len()
        && &clipboard[0..FILE_URL_PREFIX.len()] == FILE_URL_PREFIX
    {
        let path = urlencoding::decode(&clipboard[FILE_URL_PREFIX.len()..])?.to_string();
        let metadata = fs::metadata(&path)?;
        match metadata.is_dir() {
            true => {
                log!("Clipboard points to the directory {}", path);
                Ok(ClipboardContent::Dir {
                    path,
                    archive_file: None,
                })
            }
            false => {
                log!("Clipboard points to the file {}", path);
                Ok(ClipboardContent::File(path))
            }
        }
    } else {
        log!("Clipboard contains text with length {}", clipboard.len());
        Ok(ClipboardContent::Text(clipboard))
    }
}

const RAND_FILE_NAME_LEN: usize = 32;

fn send_clipboard_content(
    mut client_stream: TcpStream,
    client_addr: SocketAddr,
    enc_key: &str,
    enc_block_size: usize,
) -> Result<(), Box<dyn Error>> {
    // Read the current clipboard
    let mut clipboard_content = get_clipboard_content()?;

    // Create a tar file in tmp dir
    if let ClipboardContent::Dir { path, archive_file } = &mut clipboard_content {
        let tar_file = Path::join(&env::temp_dir(), rand_alphanumeric(RAND_FILE_NAME_LEN));
        tar_dir(Path::new(path), &tar_file)?;
        *archive_file = Some(tar_file.to_string_lossy().to_string());
    };

    // Obtain metadata and content streams
    let metadata = clipboard_content.metadata()?;
    let meta_stream = {
        let mut bytes = metadata.to_bytes();
        bytes.push(END_OF_MSG); // EOM between metadata and the actual content
        Cursor::new(bytes)
    };
    let content_stream = clipboard_content.content_stream()?;

    // Construct the output stream
    // Data -> Encryption -> Compression
    let stream = meta_stream.chain(content_stream);
    let stream = EncryptionStream::new(enc_key, stream, enc_block_size);
    let mut stream = ZlibEncoder::new(stream, Compression::default());

    // Stream the message
    match &clipboard_content {
        ClipboardContent::Text(_) => log!("Sending text to {}", &client_addr),
        ClipboardContent::File(p) => log!("Sending file {} to {}", p, &client_addr),
        ClipboardContent::Dir {
            path,
            archive_file: _,
        } => log!("Sending directory {} to {}", path, &client_addr),
    };
    let bytes_written = io::copy(&mut stream, &mut client_stream)?;
    log!("Sent {} bytes to {}", bytes_written, &client_addr);

    // Delete the tmp tar file
    if let ClipboardContent::Dir {
        path: _,
        archive_file: Some(f),
    } = &clipboard_content
    {
        fs::remove_file(f)?;
        log!("Removed temporary file {}", f);
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // Read env
    dotenvy::dotenv()?;
    let enc_key = env::var("KEY").expect("Variable KEY is not set");
    let enc_block_size = env::var("ENC_BLOCK_SIZE").unwrap_or("1024".to_string());
    let enc_block_size = enc_block_size
        .parse::<usize>()
        .unwrap_or_else(|_| panic!("{} is not a valid block size", enc_block_size));
    log!("Encryption block size: {}", enc_block_size);
    let port = env::var("PORT")
        .expect("Variable PORT is not set")
        .parse::<u16>()
        .expect("PORT must be a non negative integer");

    // Start server
    log!("Listening on port {}...", port);
    let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port)))
        .unwrap_or_else(|e| panic!("Failed to listen on port {} ({})", port, e));
    for stream in listener.incoming() {
        let stream = stream?;
        let sock_addr = stream.peer_addr()?;
        if let Err(e) = send_clipboard_content(stream, sock_addr, &enc_key, enc_block_size) {
            eprintln!("Error: {}", e);
        }
    }
    Ok(())
}
