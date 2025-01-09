use object::read::macho::DyldCache;
use object::Endianness;
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
    let mmap = match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => mmap,
        Err(err) => {
            eprintln!("Failed to map file '{}': {}", file_path, err,);
            process::exit(1);
        }
    };
    let data = &*mmap;

    let subcache_suffixes = DyldCache::<Endianness>::subcache_suffixes(data).unwrap_or_default();
    let subcache_files = subcache_suffixes
        .into_iter()
        .map(|suffix| {
            let subcache_path = format!("{}{}", file_path, suffix);
            let file = match fs::File::open(&subcache_path) {
                Ok(file) => file,
                Err(err) => {
                    eprintln!("Failed to open file '{}': {}", subcache_path, err);
                    process::exit(1);
                }
            };
            match unsafe { memmap2::Mmap::map(&file) } {
                Ok(mmap) => mmap,
                Err(err) => {
                    eprintln!("Failed to map file '{}': {}", subcache_path, err);
                    process::exit(1);
                }
            }
        })
        .collect::<Vec<_>>();
    let extra_file_data: Vec<&[u8]> = subcache_files.iter().map(|f| &**f).collect();

    let stdout = io::stdout();
    let stderr = io::stderr();
    objdump::print(
        &mut stdout.lock(),
        &mut stderr.lock(),
        data,
        &extra_file_data,
        member_names,
    )
    .unwrap();
}
