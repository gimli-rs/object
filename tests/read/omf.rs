#![cfg(feature = "std")]

use object::{
    Object, ObjectComdat, ObjectSection, ObjectSymbol, RelocationKind, SectionKind, SymbolKind,
};

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|_| panic!("Failed to read {}", path))
}

#[test]
fn test_comprehensive() {
    let data = read("testfiles/omf/comprehensive_test.obj");
    let file = object::File::parse(&data[..]).unwrap();
    assert_eq!(file.format(), object::BinaryFormat::Omf);

    // Check sections
    let sections: Vec<_> = file.sections().collect();
    assert!(
        sections.len() >= 3,
        "Should have at least CODE, DATA, and BSS sections"
    );

    // Check for both PC-relative and segment-relative relocations (M-bit test)
    let mut has_relative = false;
    let mut has_absolute = false;
    for section in file.sections() {
        for (_offset, reloc) in section.relocations() {
            match reloc.kind() {
                RelocationKind::Relative => has_relative = true,
                RelocationKind::Absolute => has_absolute = true,
                _ => {}
            }
        }
    }
    assert!(has_relative, "Should have Relative relocations (M=0)");
    assert!(has_absolute, "Should have Absolute relocations (M=1)");

    // Check COMDEF symbols (communal variables)
    let shared_var = file
        .symbols()
        .find(|sym| sym.name() == Ok("shared_var"))
        .expect("Should have COMDEF symbol");
    assert!(shared_var.is_common());
    assert_eq!(shared_var.size(), 2);
    let shared_array = file
        .symbols()
        .find(|sym| sym.name() == Ok("shared_array"))
        .expect("Should have FAR COMDEF symbol");
    assert!(shared_array.is_common());
    assert_eq!(shared_array.size(), 0x100);

    // Check absolute symbols
    let video = file
        .symbols()
        .find(|sym| sym.name() == Ok("VIDEO_MEMORY"))
        .expect("Should have ABS symbol");
    assert_eq!(video.address(), 0xb800);
    assert_eq!(video.section(), object::SymbolSection::Absolute);
}

#[test]
fn test_lidata() {
    let data = read("testfiles/omf/test_lidata.obj");
    let file = object::File::parse(&data[..]).unwrap();
    assert_eq!(file.format(), object::BinaryFormat::Omf);

    // Check that LIDATA records are expanded correctly.
    let section = file.section_by_name("_DATA").unwrap();
    let data = section.uncompressed_data().unwrap();
    assert_eq!(data.len(), 0x16d);
    // char zeros[100] = {0};
    assert_eq!(&data[0..0x64], &[0u8; 100][..]);
    // int pattern[75] = {0x5555};
    assert_eq!(&data[0x64..0x68], &[0x55, 0x55, 0x00, 0x00]);
    assert_eq!(&data[0x68..0xfa], &[0u8; 0x92][..]);
    // unsigned short ffs[50] = {0xFFFF};
    assert_eq!(&data[0xfa..0xfc], &[0xff, 0xff]);
    // char mixed[] = {1, 2, 3, 4, 5};
    assert_eq!(&data[0x168..0x16d], &[1, 2, 3, 4, 5]);
}

#[test]
fn test_comdat_watcom() {
    let data = read("testfiles/omf/comdat-watcom.obj");
    let file = object::File::parse(&data[..]).unwrap();
    assert_eq!(file.format(), object::BinaryFormat::Omf);

    // Each COMDAT record synthesizes a section and a symbol.
    let comdats: Vec<_> = file.comdats().collect();
    assert_eq!(comdats.len(), 2);
    for (comdat, name) in comdats.iter().zip(["W?foo1$n(i)i", "W?foo2$n(i)i"]) {
        assert_eq!(comdat.name(), Ok(name));
        assert_eq!(comdat.kind(), object::ComdatKind::Any);

        let sections: Vec<_> = comdat.sections().collect();
        assert_eq!(sections.len(), 1);
        let section = file.section_by_index(sections[0]).unwrap();
        assert_eq!(section.name(), Ok(name));
        assert_eq!(section.kind(), SectionKind::Text);
        assert_ne!(section.size(), 0);
        // The COMDAT data must be available.
        let data = section.uncompressed_data().unwrap();
        assert_eq!(data.len() as u64, section.size());
        // FIXUPP records following COMDAT records apply to the COMDAT.
        assert_ne!(section.relocations().count(), 0);

        let symbol = file.symbol_by_index(comdat.symbol()).unwrap();
        assert_eq!(symbol.name(), Ok(name));
        assert_eq!(symbol.kind(), SymbolKind::Text);
        assert_eq!(symbol.section_index(), Some(sections[0]));
        assert!(symbol.is_definition());
    }
}

#[test]
fn test_comdat_borland() {
    let data = read("testfiles/omf/comdat-borland.obj");
    let file = object::File::parse(&data[..]).unwrap();
    assert_eq!(file.format(), object::BinaryFormat::Omf);

    // Borland uses COMDEF records with a segment index data type to define
    // communal functions in virtual segments, which behave like COMDATs.
    let comdats: Vec<_> = file.comdats().collect();
    assert_eq!(comdats.len(), 2);
    for (comdat, (name, size)) in comdats.iter().zip([("@foo1$qi", 0xf), ("@foo2$qi", 0xa)]) {
        assert_eq!(comdat.name(), Ok(name));

        let sections: Vec<_> = comdat.sections().collect();
        assert_eq!(sections.len(), 1);
        let section = file.section_by_index(sections[0]).unwrap();
        assert_eq!(section.name(), Ok(name));
        assert_eq!(section.kind(), SectionKind::Text);
        assert_eq!(section.size(), size);
        // LEDATA records reference virtual segments using segment indices
        // with bit 14 set.
        let data = section.uncompressed_data().unwrap();
        assert_eq!(data.len() as u64, section.size());
        assert_ne!(data[0], 0);

        let symbol = file.symbol_by_index(comdat.symbol()).unwrap();
        assert_eq!(symbol.name(), Ok(name));
        assert_eq!(symbol.kind(), SymbolKind::Text);
        assert!(symbol.is_definition());
        assert!(!symbol.is_common());
    }
}

#[test]
fn test_comdat_continuation() {
    let data = read("testfiles/omf/test_comdat.obj");
    let file = object::File::parse(&data[..]).unwrap();
    assert_eq!(file.format(), object::BinaryFormat::Omf);

    let comdats: Vec<_> = file.comdats().collect();
    assert_eq!(comdats.len(), 10);
    for comdat in &comdats {
        let sections: Vec<_> = comdat.sections().collect();
        assert_eq!(sections.len(), 1);
        let section = file.section_by_index(sections[0]).unwrap();
        let data = section.uncompressed_data().unwrap();
        assert_eq!(data.len() as u64, section.size());
    }
}
