use object::{pe, read, Object, ObjectSection};
use std::fs;
use std::path::PathBuf;

#[cfg(feature = "coff")]
#[test]
fn coff_extended_relocations() {
    let path_to_obj: PathBuf = ["testfiles", "coff", "relocs_overflow.o"].iter().collect();
    let contents = fs::read(path_to_obj).expect("Could not read relocs_overflow.o");
    let file =
        read::coff::CoffFile::<_>::parse(&contents[..]).expect("Could not parse relocs_overflow.o");
    let code_section = file
        .section_by_name(".text")
        .expect("Could not find .text section in relocs_overflow.o");
    match code_section.flags() {
        object::SectionFlags::Coff { characteristics } => {
            assert!(characteristics & pe::IMAGE_SCN_LNK_NRELOC_OVFL != 0)
        }
        _ => panic!("Invalid section flags flavour."),
    };
    let relocations = code_section.relocations().collect::<Vec<_>>();
    assert_eq!(relocations.len(), 65536);
}

#[cfg(feature = "coff")]
#[test]
fn coff_weak_external() {
    use object::{coff::ImageSymbol, ObjectSymbol};

    let path_to_obj: PathBuf = ["testfiles", "pe", "weak-extern.o"].iter().collect();
    let contents = fs::read(path_to_obj).expect("Could not read weak-extern.o");
    let file =
        read::coff::CoffFile::<_>::parse(&contents[..]).expect("Could not parse weak-extern.o");
    let weak_symbol = file
        .symbol_by_name("weak_symbol")
        .expect("Could not find 'weak_symbol' symbol in weak-extern.o");

    assert!(
        weak_symbol.coff_symbol().has_aux_weak_external(),
        "'weak_symbol' should have an auxiliary weak external symbol."
    );

    let weak_external = file
        .coff_symbol_table()
        .aux_weak_external(weak_symbol.index())
        .expect("Could not parse auxiliary weak external symbol.");

    let default_symbol_index = weak_external
        .weak_default_sym_index
        .get(object::LittleEndian);

    let _ = file
        .symbol_by_index(read::SymbolIndex(default_symbol_index as usize))
        .expect("Could not find default symbol for weak external symbol.");
}
