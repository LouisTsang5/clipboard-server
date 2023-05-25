use std::io::{self, Read, Write};

use clipboard_server::{
    enc::DecryptionStream, find_indices, print_progress, END_OF_MSG, NEW_LINE, TYPE_TEXT,
};

#[derive(Debug)]
enum Metadata {
    Text { size: usize },
    File { name: String, size: usize },
}

fn get_size(metadata_str: &str) -> Result<usize, Box<dyn std::error::Error>> {
    let newline_indices = find_indices(&metadata_str, NEW_LINE);
    if newline_indices.len() < 2 {
        return Err("Metadata malformed".to_string().into());
    }
    let length = &metadata_str[newline_indices[0] + NEW_LINE.len()..newline_indices[1]]; // length is between first and second line break
    Ok(length.parse::<usize>()?)
}

fn get_filename(metadata_str: &str) -> Result<String, String> {
    let newline_indices = find_indices(&metadata_str, NEW_LINE);
    if newline_indices.len() < 3 {
        return Err("Metadata malformed".to_string());
    }
    let filename = &metadata_str[newline_indices[1] + NEW_LINE.len()..newline_indices[2]]; // filename is between second and third line break
    Ok(filename.to_string())
}

fn read_metadata(stream: &mut dyn Read) -> Result<Metadata, Box<dyn std::error::Error>> {
    // Read until end of message to buffer
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let mut chunk = [0; 128];
        let bytes_read = stream.read(&mut chunk)?;
        buf.extend(&chunk[..bytes_read]);
        if buf.ends_with(END_OF_MSG.as_bytes()) {
            break;
        }
    }

    // Deserialize the buffer to metadata
    let metadata = String::from_utf8(buf)?;
    if &metadata[..TYPE_TEXT.len()] == TYPE_TEXT {
        Ok(Metadata::Text {
            size: get_size(&metadata)?,
        })
    } else {
        Ok(Metadata::File {
            name: get_filename(&metadata)?,
            size: get_size(&metadata)?,
        })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read env
    dotenvy::dotenv()?;
    let dec_key = std::env::var("KEY").expect("Variable KEY is not set");
    let target = std::env::var("TARGET").expect("Variable TARGET is not set");
    let target = target
        .parse::<std::net::SocketAddr>()
        .expect("Illegal TARGET address");

    // Open connection
    let mut stream = std::net::TcpStream::connect(target)?;

    // Read metadata
    let metadata = {
        let mut dec_stream = DecryptionStream::new(&dec_key, &mut stream)?;
        read_metadata(&mut dec_stream)?
    };

    // Send response
    stream.write("1".as_bytes())?;

    // Handle binary
    let mut dec_stream = DecryptionStream::new(&dec_key, &mut stream)?;
    match metadata {
        Metadata::Text { size } => {
            let mut stdout = std::io::stdout();
            std::io::copy(&mut dec_stream, &mut stdout)?;
            println!("\nMessage len: {}", size);
        }
        Metadata::File { name, size } => {
            println!("Getting {}...", name);
            let cur_dir = std::env::current_dir()?;
            let file_path = cur_dir.join(&name);
            let mut file = std::fs::File::create(file_path)?;

            let mut buff = [0; 1024];
            let mut total_bytes_read = 0;
            while total_bytes_read < size {
                let bytes_read = dec_stream.read(&mut buff)?;
                if bytes_read == 0 {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
                }
                file.write(&buff[..bytes_read])?;
                total_bytes_read += bytes_read;
                print_progress(total_bytes_read as f32 / size as f32, 50);
            }
            println!("");
        }
    }

    Ok(())
}
