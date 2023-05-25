use std::io::Read;

use clipboard_server::{
    enc::EncryptionStream, ENC_BLOCK_SIZE, END_OF_MSG, NEW_LINE, PASSWORD, TYPE_FILE, TYPE_TEXT,
};

#[derive(Debug)]
enum ClipboardContent {
    Text(String),
    File(String),
}

impl ClipboardContent {
    fn write_metadata(
        &self,
        stream: &mut std::net::TcpStream,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Construct message
        let msg = match self {
            ClipboardContent::Text(text) => {
                format!("{}{}{}{}", TYPE_TEXT, NEW_LINE, text.len(), END_OF_MSG)
            }
            ClipboardContent::File(path) => {
                let path = std::path::Path::new(path);
                let metadata = std::fs::metadata(path)?;
                format!(
                    "{}{}{}{}{}{}", // 1 file_size file_name
                    TYPE_FILE,
                    NEW_LINE,
                    metadata.len(),
                    NEW_LINE,
                    path.file_name().unwrap().to_str().unwrap(),
                    END_OF_MSG
                )
            }
        };

        // Encrypt message
        let mut meta_stream = std::io::Cursor::new(msg);
        let mut meta_stream = EncryptionStream::new(PASSWORD, &mut meta_stream, ENC_BLOCK_SIZE);
        std::io::copy(&mut meta_stream, stream)?;
        Ok(())
    }

    fn write_content(
        &self,
        stream: &mut std::net::TcpStream,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let mut msg_stream: Box<dyn Read> = match self {
            ClipboardContent::Text(text) => Box::new(std::io::Cursor::new(text)),
            ClipboardContent::File(path) => Box::new(std::fs::File::open(path)?),
        };
        let mut msg_stream = EncryptionStream::new(PASSWORD, &mut msg_stream, ENC_BLOCK_SIZE);
        let bytes_sent = std::io::copy(&mut msg_stream, stream)?;
        Ok(bytes_sent as usize)
    }
}

fn get_clipboard_content() -> Result<ClipboardContent, Box<dyn std::error::Error>> {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg("pbpaste -Prefer 'public.file-url'")
        .output()?
        .stdout;
    let clipboard =
        String::from_utf8(output).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

    const FILE_URL_PREFIX: &str = "file://";

    if clipboard.len() >= FILE_URL_PREFIX.len()
        && &clipboard[0..FILE_URL_PREFIX.len()] == FILE_URL_PREFIX
    {
        let path = urlencoding::decode(&clipboard[7..]).unwrap();
        Ok(ClipboardContent::File(String::from(path)))
    } else {
        Ok(ClipboardContent::Text(clipboard.to_string()))
    }
}

fn handle_conn(mut stream: std::net::TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    // Read the current clipboard
    let clipboard_content = get_clipboard_content()?;

    // Send the metadata
    clipboard_content.write_metadata(&mut stream)?;

    // Read client response of if it wants to get the content or not
    let mut response: [u8; 1] = [0];
    stream.read_exact(&mut response)?;

    // Stream the content if true
    match &clipboard_content {
        ClipboardContent::Text(s) => log(format!(
            "Sending text to {} (Length: {})",
            &stream.peer_addr()?,
            s.len()
        )
        .as_str()),
        ClipboardContent::File(p) => {
            log(format!("Sending file {} to {}", p, &stream.peer_addr()?).as_str())
        }
    }
    if response[0] != 0 {
        clipboard_content.write_content(&mut stream)?;
    }

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
    let port = std::env::var("PORT")
        .expect("Variable PORT is not set")
        .parse::<u16>()
        .expect("PORT must be a non negative integer");

    // Start server
    log(format!("Listening on port {}...", port).as_str());
    let listener = std::net::TcpListener::bind(std::net::SocketAddr::from(([0, 0, 0, 0], port)))
        .expect(&format!("Failed to listen on port {}", port));
    for stream in listener.incoming() {
        handle_conn(stream?)?;
    }
    Ok(())
}
