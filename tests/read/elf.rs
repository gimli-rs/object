use object::read;
use object::Object;
use std::fs;
use std::path::PathBuf;

#[cfg(feature = "elf")]
#[test]
fn elf_mapping_symbols() {
    let path_to_obj: PathBuf = ["testfiles", "elf", "base-aarch64.o"].iter().collect();
    let contents = fs::read(&path_to_obj).expect("Could not read base-aarch64.o");
    let file: read::elf::ElfFile64 =
        read::elf::ElfFile::<_>::parse(&contents[..]).expect("Could not parse base-aarch64.o");
    let symbols = file.symbol_map();
    assert_eq!(symbols.symbols().len(), 1);
    assert_eq!(symbols.symbols()[0].name(), "main");
}
