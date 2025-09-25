#[cfg(feature = "std")]
use object::{Object, ObjectSection, ObjectSymbol, RelocationKind};

#[cfg(feature = "std")]
#[test]
fn test_comprehensive() {
    let path = "testfiles/omf/comprehensive_test.obj";
    let data = std::fs::read(path).unwrap_or_else(|_| panic!("Failed to read {}", path));

    let file = object::File::parse(&data[..]).unwrap();
    assert_eq!(file.format(), object::BinaryFormat::Omf);

    // Check sections
    let sections: Vec<_> = file.sections().collect();
    assert!(
        sections.len() >= 3,
        "Should have at least CODE, DATA, and BSS sections"
    );

    // Check for relocations (tests thread subrecord and F/T bit handling)
    let mut total_relocations = 0;
    for section in file.sections() {
        let relocs: Vec<_> = section.relocations().collect();
        total_relocations += relocs.len();

        // Check for both PC-relative and segment-relative relocations (M-bit test)
        for (_offset, reloc) in &relocs {
            let _kind = reloc.kind(); // Should have both Relative and Absolute
        }
    }
    assert!(
        total_relocations > 0,
        "Should have relocations (tests thread/fixup parsing)"
    );

    // Check symbols (tests PUBDEF/EXTDEF parsing)
    let symbols: Vec<_> = file.symbols().collect();
    assert!(!symbols.is_empty(), "Should have symbols");

    // Check for COMDEF symbols if supported
    let has_comdef = symbols
        .iter()
        .any(|sym| sym.name().unwrap_or("").contains("shared"));
    assert!(has_comdef, "Should have COMDEF symbols (shared variables)");
}

#[cfg(feature = "std")]
#[test]
fn test_lidata() {
    let path = "testfiles/omf/test_lidata.obj";
    let data = std::fs::read(path).unwrap_or_else(|_| panic!("Failed to read {}", path));

    let file = object::File::parse(&data[..]).unwrap();
    assert_eq!(file.format(), object::BinaryFormat::Omf);

    // Check that sections have data (LIDATA should be expanded)
    let mut total_data_size = 0;
    for section in file.sections() {
        // Use uncompressed_data to get expanded LIDATA
        if let Ok(data) = section.uncompressed_data() {
            total_data_size += data.len();
        }
    }
    assert_eq!(total_data_size, 401);
}

#[cfg(feature = "std")]
#[test]
fn test_relocations() {
    let path = "testfiles/omf/comprehensive_test.obj";
    let data = std::fs::read(path).unwrap_or_else(|_| panic!("Failed to read {}", path));
    let file = object::File::parse(&data[..]).unwrap();

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
}

#[cfg(feature = "std")]
#[test]
fn test_comdat() {
    let path = "testfiles/omf/test_comdat.obj";
    let data = std::fs::read(path).unwrap_or_else(|_| panic!("Failed to read {}", path));

    let file = object::File::parse(&data[..]).unwrap();
    assert_eq!(file.format(), object::BinaryFormat::Omf);

    // COMDAT support would show up as sections or symbols
    let sections: Vec<_> = file.sections().collect();
    let symbols: Vec<_> = file.symbols().collect();

    assert!(
        !sections.is_empty() || !symbols.is_empty(),
        "Should have parsed some content from COMDAT file"
    );
}
