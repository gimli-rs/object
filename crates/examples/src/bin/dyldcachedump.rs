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
        let mmap = match unsafe { memmap2::Mmap::map(&file) } {
            Ok(mmap) => mmap,
            Err(err) => {
                println!("Failed to map file '{}': {}", file_path, err,);
                continue;
            }
        };
        let data = &*mmap;

        let subcache_suffixes = match DyldCache::<Endianness>::subcache_suffixes(data) {
            Ok(subcaches_suffixes) => subcaches_suffixes,
            Err(err) => {
                println!(
                    "Failed to parse Dyld shared cache file '{}': {}",
                    file_path, err,
                );
                continue;
            }
        };
        let Ok(subcache_files) = subcache_suffixes
            .into_iter()
            .map(|suffix| {
                let subcache_path = format!("{}{}", file_path, suffix);
                let file = match fs::File::open(&subcache_path) {
                    Ok(file) => file,
                    Err(err) => {
                        println!("Failed to open file '{}': {}", subcache_path, err);
                        return Err(());
                    }
                };
                let mmap = match unsafe { memmap2::Mmap::map(&file) } {
                    Ok(mmap) => mmap,
                    Err(err) => {
                        println!("Failed to map file '{}': {}", subcache_path, err);
                        return Err(());
                    }
                };
                Ok(mmap)
            })
            .collect::<Result<Vec<_>, _>>()
        else {
            continue;
        };
        let subcache_data: Vec<&[u8]> = subcache_files.iter().map(|f| &**f).collect();

        let cache = match DyldCache::<Endianness>::parse(data, &subcache_data) {
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
