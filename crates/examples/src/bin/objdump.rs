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

    let stdout = io::stdout();
    let stderr = io::stderr();
    objdump::print(&mut stdout.lock(), &mut stderr.lock(), &*file, member_names).unwrap();
}
