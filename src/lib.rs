use std::io::Write;

pub const TYPE_TEXT: &str = "0";
pub const TYPE_FILE: &str = "1";
pub const END_OF_MSG: &str = "\r\n\r\n";
pub const NEW_LINE: &str = "\r\n";
pub const ENC_BLOCK_SIZE: usize = 1024;

pub mod enc;

pub fn find_indices(s: &str, target: &str) -> Vec<usize> {
    let mut indices = Vec::new();
    let mut start = 0;
    while let Some(pos) = s[start..].find(target) {
        let index = start + pos;
        indices.push(index);
        start = index + target.len();
    }
    indices
}

pub fn print_progress(percentage: f32, bar_width: usize) {
    let num_bars = (percentage * bar_width as f32) as usize;
    let bar_str = format!(
        " {:.1}%[{}{}{}]\r",
        percentage * 100 as f32,
        "=".repeat(num_bars),
        ">",
        " ".repeat(bar_width - num_bars),
    );
    let mut stdout = std::io::stdout();
    stdout.write(&bar_str.as_bytes()).unwrap();
    stdout.flush().unwrap();
}
