use object::{
    Object, ObjectSegment, SEGMENT_RWE_FLAG_EXECUTE, SEGMENT_RWE_FLAG_READ, SEGMENT_RWE_FLAG_WRITE,
};
use std::{env, fs, process};

fn main() {
    let mut args = env::args().skip(1);
    if args.len() < 1 {
        eprintln!("Usage: {} <object file path>", env::args().next().unwrap());
        process::exit(1);
    }

    let file_path = args.next().unwrap();

    let file = match fs::File::open(&file_path) {
        Ok(file) => file,
        Err(err) => {
            println!("Failed to open file '{}': {}", file_path, err,);
            return;
        }
    };
    let file = match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => mmap,
        Err(err) => {
            println!("Failed to map file '{}': {}", file_path, err,);
            return;
        }
    };

    match object::File::parse(&*file) {
        Ok(object) => print_segments(&object),
        Err(err) => {
            println!("Failed to parse file segments '{}': {}", file_path, err,);
            return;
        }
    };
}

fn print_segments(object: &object::File) {
    for segment in object.segments() {
        println!("-------------------------");
        println!(
            "name = {}",
            segment.name().unwrap_or_default().unwrap_or_default()
        );
        println!("address = 0x{:016x}", segment.address());
        println!("size = {}", segment.size());
        println!("file range = {:?}", segment.file_range());
        let rwe_flag = segment.rwe_flags();
        println!("rwe flags = {}", rwe_flag);
        if rwe_flag & SEGMENT_RWE_FLAG_READ > 0 {
            println!("    - Read");
        }
        if rwe_flag & SEGMENT_RWE_FLAG_WRITE > 0 {
            println!("    - Write");
        }
        if rwe_flag & SEGMENT_RWE_FLAG_EXECUTE > 0 {
            println!("    - Execute");
        }
    }
}
