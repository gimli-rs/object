use object::{macho::DyldCacheHeader, read::macho::DyldSubCacheSlice, Endianness};
use object_examples::objdump;
use std::{env, fs, io, process};

fn main() {
    let mut args = env::args();
    let cmd = args.next().unwrap();
    if args.len() == 0 {
        eprintln!("Usage: {} <file> [<member>...]", cmd);
        process::exit(1);
    }
    let file_path = args.next().unwrap();
    let member_names: Vec<_> = args.collect();

    let file = match fs::File::open(&file_path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Failed to open file '{}': {}", file_path, err,);
            process::exit(1);
        }
    };
    let file = match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => mmap,
        Err(err) => {
            eprintln!("Failed to map file '{}': {}", file_path, err,);
            process::exit(1);
        }
    };
    let subcaches_info = get_subcache_info_if_dyld_cache(&file).ok().flatten();
    let extra_files = subcaches_info
        .map(|info| open_subcaches(&file_path, info))
        .unwrap_or_default();
    let extra_files: Vec<_> = extra_files
        .into_iter()
        .map(
            |subcache_file| match unsafe { memmap2::Mmap::map(&subcache_file) } {
                Ok(mmap) => mmap,
                Err(err) => {
                    eprintln!("Failed to map file '{}': {}", file_path, err,);
                    process::exit(1);
                }
            },
        )
        .collect();
    let extra_file_data: Vec<&[u8]> = extra_files.iter().map(|f| &**f).collect();

    let stdout = io::stdout();
    let stderr = io::stderr();
    objdump::print(
        &mut stdout.lock(),
        &mut stderr.lock(),
        &file,
        &extra_file_data,
        member_names,
    )
    .unwrap();
}

/// Gets the slice of subcache info structs from the header of the main cache,
/// if `main_cache_data` is the data of a Dyld shared cache.
fn get_subcache_info_if_dyld_cache(
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
