use std::io::{Read, Write};

use clipboard_server::{END_OF_MSG, NEW_LINE, TYPE_TEXT};

#[derive(Debug)]
enum Metadata {
    Text { size: usize },
    File { name: String, size: usize },
}

fn find_indices(s: &str, target: &str) -> Vec<usize> {
    let mut indices = Vec::new();
    let mut start = 0;
    while let Some(pos) = s[start..].find(target) {
        let index = start + pos;
        indices.push(index);
        start = index + target.len();
    }
    indices
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

fn read_metadata(stream: &mut std::net::TcpStream) -> Result<Metadata, Box<dyn std::error::Error>> {
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

fn print_progress(percentage: f32, bar_width: usize) {
    // dbg!(percentage);
    let num_bars = (percentage * bar_width as f32) as usize;
    let bar_str = format!(
        "{:.1}%[{}{}{}]\r",
        percentage * 100 as f32,
        "=".repeat(num_bars),
        ">",
        " ".repeat(bar_width - num_bars)
    );
    let mut stdout = std::io::stdout();
    stdout.write(&bar_str.as_bytes()).unwrap();
    stdout.flush().unwrap();
}

fn write_to_file(
    stream: &mut std::net::TcpStream,
    name: &str,
    size: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    let cur_dir = std::env::current_dir()?;
    let file_path = cur_dir.join(name);
    let mut file = std::fs::File::create(file_path)?;

    let mut buff = [0; 1024];
    let mut total_bytes_read = 0;
    while total_bytes_read < size {
        let bytes_read = stream.read(&mut buff)?;
        file.write(&buff[..bytes_read])?;
        total_bytes_read += bytes_read;
        print_progress(total_bytes_read as f32 / size as f32, 50);
    }

    Ok(total_bytes_read)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read env
    dotenvy::dotenv()?;
    let target = std::env::var("TARGET").expect("Variable TARGET is not set");
    let target = target
        .parse::<std::net::SocketAddr>()
        .expect("Illegal TARGET address");

    // Open connection
    let mut stream = std::net::TcpStream::connect(target)?;
    let metadata = read_metadata(&mut stream)?;

    // Send response
    stream.write("1".as_bytes())?;

    // Handle binary
    match metadata {
        Metadata::Text { size: _ } => {
            let mut stdout = std::io::stdout();
            std::io::copy(&mut stream, &mut stdout)?;
            stdout.write("\n".as_bytes())?;
        }
        Metadata::File { name, size } => {
            println!("File: {}", name);
            write_to_file(&mut stream, &name, size)?;
        }
    }

    Ok(())
}
