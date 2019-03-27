use object::{Object, SectionKind, Symbol, SymbolKind};
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
        let file = match unsafe { memmap::Mmap::map(&file) } {
            Ok(mmap) => mmap,
            Err(err) => {
                println!("Failed to map file '{}': {}", file_path, err,);
                continue;
            }
        };
        let file = match object::File::parse(&*file) {
            Ok(file) => file,
            Err(err) => {
                println!("Failed to parse file '{}': {}", file_path, err);
                continue;
            }
        };

        println!("Debugging symbols:");
        for symbol in file.symbols() {
            print_symbol(&symbol);
        }
        println!();

        println!("Dynamic symbols:");
        for symbol in file.dynamic_symbols() {
            print_symbol(&symbol);
        }
    }
}

fn print_symbol(symbol: &Symbol<'_>) {
    if let SymbolKind::Section | SymbolKind::File = symbol.kind() {
        return;
    }

    let mut kind = match symbol.section_kind() {
        Some(SectionKind::Unknown) => '?',
        Some(SectionKind::Text) => 't',
        Some(SectionKind::Data) => 'd',
        Some(SectionKind::ReadOnlyData) => 'r',
        Some(SectionKind::UninitializedData) => 'b',
        Some(SectionKind::Other) => 's',
        None => 'U',
    };

    if symbol.is_global() {
        kind = kind.to_ascii_uppercase();
    }

    if symbol.is_undefined() {
        print!("{:16} ", "");
    } else {
        print!("{:016x} ", symbol.address());
    }
    println!(
        "{:016x} {} {}",
        symbol.size(),
        kind,
        symbol.name().unwrap_or("<unknown>"),
    );
}
