use std::{
    env,
    error::Error,
    fs::{self, File},
    io::{self, Cursor, Read},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
};

use clipboard_server::{enc::EncryptionStream, log, Metadata, END_OF_MSG};
use flate2::{read::ZlibEncoder, Compression};

#[derive(Debug)]
enum ClipboardContent {
    Text(String),
    File(String),
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
        }
    }

    fn content_stream(&self) -> Result<Box<dyn Read>, io::Error> {
        match self {
            ClipboardContent::Text(text) => Ok(Box::new(Cursor::new(text.to_owned()))),
            ClipboardContent::File(path) => Ok(Box::new(File::open(path)?)),
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
        let path = urlencoding::decode(&clipboard[7..]).unwrap();
        Ok(ClipboardContent::File(String::from(path)))
    } else {
        Ok(ClipboardContent::Text(clipboard))
    }
}

fn send_clipboard_content(
    mut client_stream: TcpStream,
    client_addr: SocketAddr,
    enc_key: &str,
    enc_block_size: usize,
) -> Result<(), Box<dyn Error>> {
    // Read the current clipboard
    let clipboard_content = get_clipboard_content()?;

    // Obtain metadata and content streams
    let meta_stream = Cursor::new(clipboard_content.metadata()?.to_bytes());
    let content_stream = clipboard_content.content_stream()?;

    // Construct the output stream
    // Data -> Encryption -> Compression
    let stream = meta_stream
        .chain(Cursor::new([END_OF_MSG])) // EOF between metadata and the actual content
        .chain(content_stream);
    let stream = EncryptionStream::new(enc_key, stream, enc_block_size);
    let mut stream = ZlibEncoder::new(stream, Compression::default());

    // Stream the message
    log(&match &clipboard_content {
        ClipboardContent::Text(_) => format!("Sending text to {}", &client_addr),
        ClipboardContent::File(p) => format!("Sending file {} to {}", p, &client_addr),
    });
    let bytes_written = io::copy(&mut stream, &mut client_stream)?;
    log(&format!("Sent {} bytes to {}", bytes_written, &client_addr));
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // Read env
    dotenvy::dotenv()?;
    let enc_key = env::var("KEY").expect("Variable KEY is not set");
    let enc_block_size = env::var("ENC_BLOCK_SIZE").unwrap_or("1024".to_string());
    let enc_block_size = enc_block_size
        .parse::<usize>()
        .expect(&format!("{} is not a valid block size", enc_block_size));
    log(&format!("Encryption block size: {}", enc_block_size));
    let port = env::var("PORT")
        .expect("Variable PORT is not set")
        .parse::<u16>()
        .expect("PORT must be a non negative integer");

    // Start server
    log(&format!("Listening on port {}...", port));
    let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port)))
        .expect(&format!("Failed to listen on port {}", port));
    for stream in listener.incoming() {
        let stream = stream?;
        let sock_addr = stream.peer_addr()?;
        if let Err(e) = send_clipboard_content(stream, sock_addr, &enc_key, enc_block_size) {
            eprintln!("Error: {}", e);
        }
    }
    Ok(())
}
