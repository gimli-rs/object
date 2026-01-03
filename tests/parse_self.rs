#![cfg(feature = "read")]
use object::{File, Object, ObjectSegment};
use std::{env, fs};

#[test]
fn parse_self() {
    let exe = env::current_exe().unwrap();
    let data = fs::read(exe).unwrap();
    let object = File::parse(&*data).unwrap();
    assert!(object.entry() != 0);
    assert!(object.sections().count() != 0);
}

#[test]
fn parse_self_segment_permissions() {
    let exe = env::current_exe().unwrap();
    let data = fs::read(exe).unwrap();
    let object = File::parse(&*data).unwrap();

    // Find an executable segment (typically __TEXT on Mach-O or .text on ELF)
    let has_executable_segment = object.segments().any(|seg| seg.executable());
    assert!(
        has_executable_segment,
        "Expected at least one executable segment"
    );

    // All segments should have consistent flags vs method results
    for seg in object.segments() {
        let flags = seg.flags();
        assert_eq!(seg.readable(), flags.readable());
        assert_eq!(seg.writable(), flags.writable());
        assert_eq!(seg.executable(), flags.executable());
    }
}

#[cfg(feature = "std")]
#[test]
fn parse_self_cache() {
    use object::read::{ReadCache, ReadRef};
    let exe = env::current_exe().unwrap();
    let file = fs::File::open(exe).unwrap();
    let cache = ReadCache::new(file);
    let data = cache.range(0, cache.len().unwrap());
    let object = File::parse(data).unwrap();
    assert!(object.entry() != 0);
    assert!(object.sections().count() != 0);
}
