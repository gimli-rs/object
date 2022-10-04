use object::read::macho::DyldCache;
use object::Endianness;
use std::{env, fs, process};

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
                println!("Failed to open file '{}': {}", file_path, err,);
                continue;
            }
        };
        let subcache_files = open_subcaches_if_exist(&file_path);
        let file = match unsafe { memmap2::Mmap::map(&file) } {
            Ok(mmap) => mmap,
            Err(err) => {
                println!("Failed to map file '{}': {}", file_path, err,);
                continue;
            }
        };
        let subcache_files: Option<Vec<_>> = subcache_files
            .into_iter()
            .map(
                |subcache_file| match unsafe { memmap2::Mmap::map(&subcache_file) } {
                    Ok(mmap) => Some(mmap),
                    Err(err) => {
                        eprintln!("Failed to map file '{}': {}", file_path, err);
                        None
                    }
                },
            )
            .collect();
        let subcache_files: Vec<&[u8]> = match &subcache_files {
            Some(subcache_files) => subcache_files
                .iter()
                .map(|subcache_file| &**subcache_file)
                .collect(),
            None => continue,
        };
        let cache = match DyldCache::<Endianness>::parse(&*file, &subcache_files) {
            Ok(cache) => cache,
            Err(err) => {
                println!(
                    "Failed to parse Dyld shared cache file '{}': {}",
                    file_path, err,
                );
                continue;
            }
        };

        // Print the list of image paths in this file.
        for image in cache.images() {
            if let Ok(path) = image.path() {
                println!("{}", path);
            }
        }
    }
}

// If the file is a dyld shared cache, and we're on macOS 12 or later,
// then there will be one or more "subcache" files next to this file,
// with the names filename.1, filename.2, ..., filename.symbols
// or filename.01, filename.02 on macOS 13
fn open_subcaches_if_exist(path: &str) -> Vec<fs::File> {
    let mut files = Vec::new();
    for i in 1.. {
        let subcache_path = format!("{}.{}", path, i);
        match fs::File::open(&subcache_path) {
            Ok(subcache_file) => files.push(subcache_file),
            Err(_) => break,
        };
    }
    if files.is_empty() {
        for i in 1.. {
            let subcache_path = format!("{}.{:02}", path, i);
            match fs::File::open(&subcache_path) {
                Ok(subcache_file) => files.push(subcache_file),
                Err(_) => break,
            };
        }
    }
    let symbols_subcache_path = format!("{}.symbols", path);
    if let Ok(subcache_file) = fs::File::open(&symbols_subcache_path) {
        files.push(subcache_file);
    };
    println!("Found {} subcache files", files.len());
    files
}
