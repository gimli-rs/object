use object::read::macho::{DyldCache, DyldCacheImage};
use object::{Endianness, File, Object, ObjectComdat, ObjectSection, ObjectSymbol, ReadRef};
use std::{env, fs, process};

fn main() {
    let arg_len = env::args().len();
    if arg_len < 3 {
        // E.g. dyldcacheobjdump /System/Library/dyld/dyld_shared_cache_x86_64 /System/Library/Frameworks/AppKit.framework/Versions/C/AppKit
        eprintln!(
            "Usage: {} <cache_path> <dylib_path> ...",
            env::args().next().unwrap()
        );
        process::exit(1);
    }

    let mut path_iter = env::args().skip(1);
    let cache_path = path_iter.next().unwrap();

    let file = match fs::File::open(&cache_path) {
        Ok(file) => file,
        Err(err) => {
            println!("Failed to open file '{}': {}", cache_path, err,);
            process::exit(1);
        }
    };
    let file = match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => mmap,
        Err(err) => {
            println!("Failed to map file '{}': {}", cache_path, err,);
            process::exit(1);
        }
    };
    let cache = match DyldCache::<Endianness>::parse(&*file) {
        Ok(cache) => cache,
        Err(err) => {
            println!(
                "Failed to parse Dyld shared cache file '{}': {}",
                cache_path, err,
            );
            process::exit(1);
        }
    };

    for dylib_path in path_iter {
        if arg_len > 3 {
            println!();
            println!("{}:", dylib_path);
        }

        let image = match find_image(&cache, &dylib_path) {
            Some(image) => image,
            None => {
                println!(
                    "Could not find dylib path in shared cache file '{}': {}",
                    cache_path, dylib_path,
                );
                continue;
            }
        };

        let file = match image.parse_object() {
            Ok(file) => file,
            Err(err) => {
                println!("Failed to parse Mach-O image '{}': {}", dylib_path, err);
                process::exit(1);
            }
        };
        dump_object(&file);
    }
}

fn find_image<'data>(cache: &DyldCache<'data>, path: &str) -> Option<DyldCacheImage<'data>> {
    let mut images = cache.iter_images();
    while let Ok(Some(image)) = images.next() {
        if image.path() == Ok(path) {
            return Some(image);
        }
    }
    None
}

fn dump_object<'data, R>(file: &File<'data, R>)
where
    R: ReadRef<'data>,
{
    println!(
        "Format: Mach-O {:?}-endian {}-bit",
        file.endianness(),
        if file.is_64() { "64" } else { "32" }
    );
    println!("Architecture: {:?}", file.architecture());
    println!("Flags: {:x?}", file.flags());

    match file.mach_uuid() {
        Ok(Some(uuid)) => println!("Mach UUID: {:x?}", uuid),
        Ok(None) => {}
        Err(e) => println!("Failed to parse Mach UUID: {}", e),
    }
    for segment in file.segments() {
        println!("{:x?}", segment);
    }

    for section in file.sections() {
        println!("{}: {:x?}", section.index().0, section);
    }

    for comdat in file.comdats() {
        print!("{:?} Sections:", comdat);
        for section in comdat.sections() {
            print!(" {}", section.0);
        }
        println!();
    }

    println!();
    println!("Symbols");
    for symbol in file.symbols() {
        println!("{}: {:x?}", symbol.index().0, symbol);
    }

    for section in file.sections() {
        if section.relocations().next().is_some() {
            println!(
                "\n{} relocations",
                section.name().unwrap_or("<invalid name>")
            );
            for relocation in section.relocations() {
                println!("{:x?}", relocation);
            }
        }
    }

    println!();
    println!("Dynamic symbols");
    for symbol in file.dynamic_symbols() {
        println!("{}: {:x?}", symbol.index().0, symbol);
    }

    if let Some(relocations) = file.dynamic_relocations() {
        println!();
        println!("Dynamic relocations");
        for relocation in relocations {
            println!("{:x?}", relocation);
        }
    }

    let imports = file.imports().unwrap();
    if !imports.is_empty() {
        println!();
        for import in imports {
            println!("{:?}", import);
        }
    }

    let exports = file.exports().unwrap();
    if !exports.is_empty() {
        println!();
        for export in exports {
            println!("{:x?}", export);
        }
    }
}
