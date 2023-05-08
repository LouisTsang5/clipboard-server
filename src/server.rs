use std::io::{Read, Write};

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
        match self {
            ClipboardContent::Text(text) => {
                stream.write(format!("0\r\n{}", text.len()).as_bytes())?; // 0 text_length
                Ok(())
            }
            ClipboardContent::File(path) => {
                let path = std::path::Path::new(path);
                let metadata = std::fs::metadata(path)?;
                stream.write(
                    format!(
                        "1\r\n{}\r\n{}", // 1 file_size file_name
                        metadata.len(),
                        path.file_name().unwrap().to_str().unwrap()
                    )
                    .as_bytes(),
                )?;
                Ok(())
            }
        }
    }

    fn write_content(
        &self,
        stream: &mut std::net::TcpStream,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            ClipboardContent::Text(text) => {
                stream.write_all(text.as_bytes())?;
                Ok(())
            }
            ClipboardContent::File(path) => {
                let mut file = std::fs::File::open(path)?;
                std::io::copy(&mut file, stream)?;
                Ok(())
            }
        }
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
        Ok(ClipboardContent::File(String::from(&clipboard[7..])))
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
    dbg!(response);

    // Stream the content if true
    if response[0] != 0 {
        clipboard_content.write_content(&mut stream)?;
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read env
    dotenvy::dotenv()?;
    let port = std::env::var("PORT")
        .expect("Variable PORT is not set")
        .parse::<u16>()
        .expect("PORT must be a non negative integer");

    // Start server
    println!("Listening on port {}...", port);
    let listener = std::net::TcpListener::bind(std::net::SocketAddr::from(([0, 0, 0, 0], port)))
        .expect(&format!("Failed to listen on port {}", port));
    for stream in listener.incoming() {
        handle_conn(stream?)?;
    }
    Ok(())
}
