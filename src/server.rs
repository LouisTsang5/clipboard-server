use std::{
    error::Error,
    io::{self, Cursor, Read},
};

use clipboard_server::{enc::EncryptionStream, Metadata, END_OF_MSG};
use flate2::{read::ZlibEncoder, Compression};

#[derive(Debug)]
enum ClipboardContent {
    Text(String),
    File(String),
}

impl ClipboardContent {
    fn to_metadata(&self) -> Result<Metadata, Box<dyn Error>> {
        match self {
            ClipboardContent::Text(text) => Ok(Metadata::Text { size: text.len() }),
            ClipboardContent::File(path) => {
                let path = std::path::Path::new(path);
                let f_metadata = std::fs::metadata(path)?;
                Ok(Metadata::File {
                    size: f_metadata.len() as usize,
                    name: path.file_name().unwrap().to_str().unwrap().to_string(),
                })
            }
        }
    }

    fn to_stream(&self) -> Result<Box<dyn Read>, Box<dyn Error>> {
        match self {
            ClipboardContent::Text(text) => Ok(Box::new(std::io::Cursor::new(text.to_owned()))),
            ClipboardContent::File(path) => Ok(Box::new(std::fs::File::open(path)?)),
        }
    }
}

fn get_clipboard_content() -> Result<ClipboardContent, Box<dyn std::error::Error>> {
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

fn handle_conn(
    mut stream: std::net::TcpStream,
    enc_key: &str,
    enc_block_size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read the current clipboard
    let clipboard_content = get_clipboard_content()?;

    // Construct the message stream
    let meta_stream = Cursor::new(clipboard_content.to_metadata()?.to_bytes());
    let content_stream = clipboard_content.to_stream()?;
    let mut msg_stream = meta_stream
        .chain(Cursor::new([END_OF_MSG])) // EOF between metadata and the actual content
        .chain(content_stream);

    // Construct the stream
    // Data -> Encryption -> Compression
    let enc_stream = EncryptionStream::new(enc_key, &mut msg_stream, enc_block_size);
    let mut cmp_stream = ZlibEncoder::new(enc_stream, Compression::default());

    // Stream the message
    match &clipboard_content {
        ClipboardContent::Text(s) => log(&format!(
            "Sending text to {} (Length: {})",
            &stream.peer_addr()?,
            s.len()
        )),
        ClipboardContent::File(p) => {
            log(&format!("Sending file {} to {}", p, &stream.peer_addr()?))
        }
    }
    let bytes_written = io::copy(&mut cmp_stream, &mut stream)?;
    log(&format!("Sent {} bytes.", bytes_written));
    Ok(())
}

fn log(msg: &str) {
    println!(
        "[{}] {}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        msg
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read env
    dotenvy::dotenv()?;
    let enc_key = std::env::var("KEY").expect("Variable KEY is not set");
    let enc_block_size = std::env::var("ENC_BLOCK_SIZE").unwrap_or("1024".to_string());
    let enc_block_size = enc_block_size
        .parse::<usize>()
        .expect(&format!("{} is not a valid block size", enc_block_size));
    log(&format!("Encryption block size: {}", enc_block_size));
    let port = std::env::var("PORT")
        .expect("Variable PORT is not set")
        .parse::<u16>()
        .expect("PORT must be a non negative integer");

    // Start server
    log(&format!("Listening on port {}...", port));
    let listener = std::net::TcpListener::bind(std::net::SocketAddr::from(([0, 0, 0, 0], port)))
        .expect(&format!("Failed to listen on port {}", port));
    for stream in listener.incoming() {
        if let Err(e) = handle_conn(stream?, &enc_key, enc_block_size) {
            eprintln!("Error: {}", e);
        }
    }
    Ok(())
}
