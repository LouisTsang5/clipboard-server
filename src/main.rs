use std::io::Write;

#[derive(Debug)]
enum ClipboardContent {
    String(String),
    File(String),
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
        Ok(ClipboardContent::String(clipboard.to_string()))
    }
}

fn handle_conn(mut stream: std::net::TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let msg = get_clipboard_content()?;
    let msg = format!("{:?}", msg);
    stream.write(msg.as_bytes())?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = 3001;
    let listener = std::net::TcpListener::bind(std::net::SocketAddr::from(([0, 0, 0, 0], port)))
        .expect(&format!("Failed to listen on port {}", port));
    for stream in listener.incoming() {
        handle_conn(stream?)?;
    }
    Ok(())
}
