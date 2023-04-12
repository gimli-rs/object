//! Example that uses the lower level read API.

use object_examples::readobj;
use std::{env, fs, io, process};

fn main() {
    let arg_len = env::args().len();
    if arg_len <= 1 {
        eprintln!("Usage: {} <file> ...", env::args().next().unwrap());
        process::exit(1);
    }

    for file_path in env::args().skip(1) {
        if arg_len > 2 {
            println!();
            println!("{}:", file_path);
        }

        let file = match fs::File::open(&file_path) {
            Ok(file) => file,
            Err(err) => {
                println!("Failed to open file '{}': {}", file_path, err);
                continue;
            }
        };
        let file = match unsafe { memmap2::Mmap::map(&file) } {
            Ok(mmap) => mmap,
            Err(err) => {
                println!("Failed to map file '{}': {}", file_path, err);
                continue;
            }
        };

        let stdout = io::stdout();
        let stderr = io::stderr();
        readobj::print(&mut stdout.lock(), &mut stderr.lock(), &file);
    }
}
