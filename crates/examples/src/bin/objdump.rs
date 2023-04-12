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
    let extra_files = open_subcaches_if_exist(&file_path);
    let file = match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => mmap,
        Err(err) => {
            eprintln!("Failed to map file '{}': {}", file_path, err,);
            process::exit(1);
        }
    };
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

// If the file is a dyld shared cache, and we're on macOS 12 or later,
// then there will be one or more "subcache" files next to this file,
// with the names filename.1, filename.2 etc.
// Read those files now, if they exist, even if we don't know that
// we're dealing with a dyld shared cache. By the time we know what
// we're dealing with, it's too late to read more files.
fn open_subcaches_if_exist(path: &str) -> Vec<fs::File> {
    let mut files = Vec::new();
    for i in 1.. {
        let subcache_path = format!("{}.{}", path, i);
        match fs::File::open(&subcache_path) {
            Ok(subcache_file) => files.push(subcache_file),
            Err(_) => break,
        };
    }
    let symbols_subcache_path = format!("{}.symbols", path);
    if let Ok(subcache_file) = fs::File::open(symbols_subcache_path) {
        files.push(subcache_file);
    };
    files
}
