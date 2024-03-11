use object::macho::DyldCacheHeader;
use object::read::macho::{DyldCache, DyldSubCacheSlice};
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
        let file = match unsafe { memmap2::Mmap::map(&file) } {
            Ok(mmap) => mmap,
            Err(err) => {
                println!("Failed to map file '{}': {}", file_path, err,);
                continue;
            }
        };

        let subcaches_info = match get_subcache_info(&file) {
            Ok(subcaches_info) => subcaches_info,
            Err(err) => {
                println!(
                    "Failed to parse Dyld shared cache file '{}': {}",
                    file_path, err,
                );
                continue;
            }
        };
        let subcache_files = subcaches_info
            .map(|info| open_subcaches(&file_path, info))
            .unwrap_or_default();
        let subcache_files: Option<Vec<_>> = subcache_files
            .into_iter()
            .map(
                |subcache_file| match unsafe { memmap2::Mmap::map(&subcache_file) } {
                    Ok(mmap) => Some(mmap),
                    Err(err) => {
                        println!("Failed to map file '{}': {}", file_path, err);
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

/// Gets the slice of subcache info structs from the header of the main cache.
fn get_subcache_info(
    main_cache_data: &[u8],
) -> object::read::Result<Option<DyldSubCacheSlice<'_, Endianness>>> {
    let header = DyldCacheHeader::<Endianness>::parse(main_cache_data)?;
    let (_arch, endian) = header.parse_magic()?;
    let subcaches_info = header.subcaches(endian, main_cache_data)?;
    Ok(subcaches_info)
}

// If the file is a dyld shared cache, and we're on macOS 12 or later,
// then there will be one or more "subcache" files next to this file,
// with the names filename.1, filename.2, ..., filename.symbols
// or filename.01, filename.02, ..., filename.symbols on macOS 13
fn open_subcaches(path: &str, subcaches_info: DyldSubCacheSlice<Endianness>) -> Vec<fs::File> {
    let subcache_suffixes: Vec<String> = match subcaches_info {
        DyldSubCacheSlice::V1(subcaches) => {
            // macOS 12: Subcaches have the file suffixes .1, .2, .3 etc.
            (1..subcaches.len() + 1).map(|i| format!(".{i}")).collect()
        }
        DyldSubCacheSlice::V2(subcaches) => {
            // macOS 13+: The subcache file suffix is written down in the header of the main cache.
            subcaches
                .iter()
                .map(|s| {
                    // The suffix is a nul-terminated string in a fixed-size byte array.
                    let suffix = s.file_suffix;
                    let len = suffix.iter().position(|&c| c == 0).unwrap_or(suffix.len());
                    String::from_utf8_lossy(&suffix[..len]).to_string()
                })
                .collect()
        }
        _ => panic!(
            "If this case is hit, it means that someone added a variant to the (non-exhaustive) \
            DyldSubCacheSlice enum and forgot to update this example"
        ),
    };
    let mut files = Vec::new();
    for suffix in subcache_suffixes {
        let subcache_path = format!("{path}{suffix}");
        match fs::File::open(subcache_path) {
            Ok(subcache_file) => files.push(subcache_file),
            Err(_) => break,
        };
    }
    let symbols_subcache_path = format!("{}.symbols", path);
    if let Ok(subcache_file) = fs::File::open(symbols_subcache_path) {
        files.push(subcache_file);
    };
    println!("Found {} subcache files", files.len());
    files
}
