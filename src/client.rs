use std::io::{self, Read, Write};

use clipboard_server::{
    enc::DecryptionStream, print_progress, Metadata, COMMON_HEADER_SIZE, END_OF_MSG,
    END_OF_MSG_SIZE, INIT_METADATA_BUFF_SIZE,
};

fn read_metadata(stream: &mut dyn Read) -> Result<Metadata, Box<dyn std::error::Error>> {
    // Read until end of message to buffer
    let mut buf: Vec<u8> = Vec::with_capacity(INIT_METADATA_BUFF_SIZE + END_OF_MSG_SIZE);
    let mut total_bytes_read = 0;
    loop {
        let mut byte = [0; 1];
        stream.read_exact(&mut byte)?;
        total_bytes_read += 1;
        if total_bytes_read > COMMON_HEADER_SIZE && byte[0] == END_OF_MSG {
            break;
        }
        buf.push(byte[0]);
    }

    // Deserialize the buffer to metadata
    Metadata::try_from(&buf as &[u8])
}

fn request() -> Result<(), Box<dyn std::error::Error>> {
    // Read env
    dotenvy::dotenv()?;
    let dec_key = std::env::var("KEY").expect("Variable KEY is not set");
    let target = std::env::var("TARGET").expect("Variable TARGET is not set");
    let target = target
        .parse::<std::net::SocketAddr>()
        .expect("Illegal TARGET address");

    // Open connection
    let mut stream = std::net::TcpStream::connect(target)?;
    let mut stream = DecryptionStream::new(&dec_key, &mut stream)?;

    // Read content
    let metadata = read_metadata(&mut stream)?;
    match metadata {
        Metadata::Text { size } => {
            let mut stdout = std::io::stdout();
            std::io::copy(&mut stream.take(size as u64), &mut stdout)?;
            println!("\nMessage len: {}", size);
        }
        Metadata::File { name, size } => {
            println!("Getting {}...", name);
            let cur_dir = std::env::current_dir()?;
            let file_path = cur_dir.join(&name);
            let mut file = std::fs::File::create(file_path)?;

            // Get the file while printing the progression
            let mut buff = [0; 1024];
            let mut total_bytes_read = 0;
            while total_bytes_read < size {
                let bytes_read = stream.read(&mut buff)?;
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

fn main() {
    // Main logic
    if let Err(e) = request() {
        eprintln!("Error: {}", e);
    }

    // Halt to show result
    let mut stdout = io::stdout();
    stdout
        .write("Press Enter to exit the program...".as_bytes())
        .unwrap();
    stdout.flush().unwrap();
    let mut stdin = io::stdin();
    let mut tmp_buff = [0u8];
    stdin.read(&mut tmp_buff).unwrap();
}
