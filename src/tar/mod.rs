use std::{
    fs::{self, File},
    io,
    path::Path,
};

use crate::log;

fn list_dir(dir: &Path, list: &mut Vec<String>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            list.push(path.to_str().unwrap().to_string());
        } else {
            list_dir(&path, list)?;
        }
    }
    Ok(())
}

pub fn tar_dir(dir: &Path, output_path: &Path) -> Result<(), io::Error> {
    log!(
        "Creating tar archive {} for {}",
        output_path.to_string_lossy(),
        dir.to_string_lossy()
    );

    let files = {
        const DEFAULT_FILE_LIST_CAPACITY: usize = 256;
        let mut files = Vec::with_capacity(DEFAULT_FILE_LIST_CAPACITY);
        list_dir(dir, &mut files)?;
        files
    };
    log!("Found {} files in {}", files.len(), dir.to_string_lossy());

    let tar_file = File::create(output_path)?;
    let mut tar_file = tar::Builder::new(tar_file);
    for f in files {
        let relative_path = Path::new(&f).strip_prefix(dir).unwrap();
        let mut file = File::open(&f)?;
        log!("Appending {}", relative_path.to_string_lossy());
        tar_file.append_file(relative_path, &mut file)?;
    }

    log!("Tar archive created as {}", output_path.to_string_lossy());
    tar_file.finish()
}
