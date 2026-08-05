#![cfg(all(feature = "read", feature = "write"))]

use object::read::{ObjectSection, ObjectSymbol};
use object::{
    Architecture, BinaryFormat, Endianness, Object, RelocationEncoding, RelocationFlags,
    RelocationKind, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};
use object::{read, write};

// EBCDIC-encoded string constants
const CEESTART_EBCDIC: &[u8] = &[0xC3, 0xC5, 0xC5, 0xE2, 0xE3, 0xC1, 0xD9, 0xE3]; // "CEESTART"
const PRINTF_EBCDIC: &[u8] = &[0x97, 0x99, 0x89, 0x95, 0xA3, 0x86]; // "printf"
const DOTDEBUG_INFO_EBCDIC: &[u8] = &[
    0x4B, 0x84, 0x85, 0x82, 0xA4, 0x87, 0x6D, 0x89, 0x95, 0x86, 0x96,
]; // ".debug_info"
const DOTDEBUG_LINE_EBCDIC: &[u8] = &[
    0x4B, 0x84, 0x85, 0x82, 0xA4, 0x87, 0x6D, 0x93, 0x89, 0x95, 0x85,
]; // ".debug_line"
const DOTDEBUG_STR_EBCDIC: &[u8] = &[0x4B, 0x84, 0x85, 0x82, 0xA4, 0x87, 0x6D, 0xA2, 0xA3, 0x99]; // ".debug_str"
const C_CODE_EBCDIC: &[u8] = &[0xC3, 0x6D, 0xC3, 0xD6, 0xC4, 0xC5]; // "C_CODE"
const EXTERNAL_FUNC_EBCDIC: &[u8] = &[
    0x85, 0xA7, 0xA3, 0x85, 0x99, 0x95, 0x81, 0x93, 0x6D, 0x86, 0xA4, 0x95, 0x83,
]; // "external_func"
const FUNC1_EBCDIC: &[u8] = &[0x86, 0xA4, 0x95, 0x83, 0xF1]; // "func1"
const FUNC2_EBCDIC: &[u8] = &[0x86, 0xA4, 0x95, 0x83, 0xF2]; // "func2"
const EXTERNAL_EBCDIC: &[u8] = &[0x85, 0xA7, 0xA3, 0x85, 0x99, 0x95, 0x81, 0x93]; // "external"

/// Test basic GOFF file structure with external references
/// Similar to base.o which has SD (compile unit), ER (external refs), and ED (sections)
#[test]
fn goff_basic_structure() {
    let mut object = write::Object::new(BinaryFormat::Goff, Architecture::S390x, Endianness::Big);

    // Add external text reference (like CEESTART in base.o)
    let _text_er = object.add_symbol(write::Symbol {
        name: CEESTART_EBCDIC.to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: write::SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });

    // Add external data reference (like printf in base.o)
    let _data_er = object.add_symbol(write::Symbol {
        name: PRINTF_EBCDIC.to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: write::SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });

    // Add a debug section (ED record in GOFF)
    let debug_section = object.add_section(
        Vec::new(),
        DOTDEBUG_INFO_EBCDIC.to_vec(),
        SectionKind::Debug,
    );
    object.append_section_data(debug_section, &[0x01, 0x02, 0x03, 0x04], 1);

    let bytes = object.write().unwrap();

    // Verify we can parse it back
    let object = read::File::parse(&*bytes).unwrap();
    assert_eq!(object.format(), BinaryFormat::Goff);
    assert_eq!(object.architecture(), Architecture::S390x);
    assert_eq!(object.endianness(), Endianness::Big);

    let goff = read::goff::GoffFile::parse(&*bytes).unwrap();

    // Verify external symbols are present
    let symbols: Vec<_> = object.symbols().collect();
    assert!(
        symbols.len() >= 2,
        "Should have at least 2 external symbols"
    );

    // Find our external symbols by comparing EBCDIC bytes directly
    let mut found_ceestart = false;
    let mut found_printf = false;

    for symbol in &symbols {
        if let Ok(name_bytes) = symbol.name_bytes() {
            if name_bytes == CEESTART_EBCDIC {
                found_ceestart = true;
                assert!(symbol.is_undefined());
            } else if name_bytes == PRINTF_EBCDIC {
                found_printf = true;
                assert!(symbol.is_undefined());
            }
        }
    }

    assert!(found_ceestart, "Should find CEESTART symbol");
    assert!(found_printf, "Should find printf symbol");

    // Verify section data
    let sections: Vec<_> = object.sections().collect();
    assert!(!sections.is_empty(), "Should have at least one section");

    let goff_sections: Vec<read::goff::GoffSection64<'_, '_>> = goff.sections().collect();
    assert!(
        !goff_sections.is_empty(),
        "Concrete GOFF parser should expose at least one section"
    );

    // Find the debug section by comparing EBCDIC bytes directly
    let debug_section = goff_sections
        .iter()
        .find(|s| {
            if let Ok(name_bytes) = s.name_bytes_parts() {
                // Compare the actual bytes, handling potential padding
                name_bytes.starts_with(DOTDEBUG_INFO_EBCDIC)
            } else {
                false
            }
        })
        .expect("Should find .debug_info section");

    // Check section data using the concrete GOFF section type.
    let data = ObjectSection::uncompressed_data(debug_section).unwrap();
    assert_eq!(&data[..], &[0x01, 0x02, 0x03, 0x04]);
}

/// Test GOFF file with only compile unit (minimal valid GOFF)
#[test]
fn goff_minimal() {
    let object = write::Object::new(BinaryFormat::Goff, Architecture::S390x, Endianness::Big);

    let bytes = object.write().unwrap();

    let object = read::File::parse(&*bytes).unwrap();
    assert_eq!(object.format(), BinaryFormat::Goff);
    assert_eq!(object.architecture(), Architecture::S390x);
    assert_eq!(object.endianness(), Endianness::Big);

    // Minimal GOFF has HDR, compile unit SD, and END records
    // Should be parseable even with no user-defined symbols or sections
}

/// Test GOFF with multiple debug sections
#[test]
fn goff_multiple_debug_sections() {
    let mut object = write::Object::new(BinaryFormat::Goff, Architecture::S390x, Endianness::Big);

    // Add multiple debug sections (like B_IDRL in base.o)
    let debug1 = object.add_section(
        Vec::new(),
        DOTDEBUG_LINE_EBCDIC.to_vec(),
        SectionKind::Debug,
    );
    object.append_section_data(debug1, &[0xDE, 0xAD], 1);

    let debug2 = object.add_section(Vec::new(), DOTDEBUG_STR_EBCDIC.to_vec(), SectionKind::Debug);
    object.append_section_data(debug2, &[0xBE, 0xEF], 1);

    let bytes = object.write().unwrap();

    let object = read::File::parse(&*bytes).unwrap();
    assert_eq!(object.format(), BinaryFormat::Goff);

    let sections: Vec<_> = object.sections().collect();
    assert_eq!(sections.len(), 2, "Should have 2 debug sections");

    let goff = read::goff::GoffFile::parse(&*bytes).unwrap();
    let goff_sections: Vec<read::goff::GoffSection64<'_, '_>> = goff.sections().collect();
    assert_eq!(
        goff_sections.len(),
        2,
        "Concrete GOFF parser should have 2 debug sections"
    );

    // Verify section data using the concrete GOFF section type.
    let data0 = ObjectSection::uncompressed_data(&goff_sections[0]).unwrap();
    assert_eq!(&data0[..], &[0xDE, 0xAD]);
    let data1 = ObjectSection::uncompressed_data(&goff_sections[1]).unwrap();
    assert_eq!(&data1[..], &[0xBE, 0xEF]);
}

#[test]
fn goff_relocation_absolute() {
    let mut object = write::Object::new(BinaryFormat::Goff, Architecture::S390x, Endianness::Big);

    // Add code section with placeholder for absolute address
    let code_data = vec![
        0xC0, 0xE5, 0x00, 0x00, 0x00, 0x00, // BRASL %r14, 0 (placeholder)
        0x07, 0xFE, // BR %r14
    ];
    let code_section = object.add_section(vec![], C_CODE_EBCDIC.to_vec(), SectionKind::Text);
    object.section_mut(code_section).set_data(code_data, 8);

    // Add external symbol
    let ext_symbol = object.add_symbol(write::Symbol {
        name: EXTERNAL_FUNC_EBCDIC.to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: write::SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });

    // Add absolute relocation at offset 2 (the address field in BRASL)
    object
        .add_relocation(
            code_section,
            write::Relocation {
                offset: 2,
                symbol: ext_symbol,
                addend: 0,
                flags: RelocationFlags::Generic {
                    kind: RelocationKind::Absolute,
                    encoding: RelocationEncoding::Generic,
                    size: 32,
                },
            },
        )
        .unwrap();

    // Write to buffer
    let mut buffer = Vec::new();
    object.write_stream(&mut buffer).unwrap();

    // Verify RLD record exists
    assert!(
        buffer.windows(3).any(|w| w == &[0x03, 0x20, 0x00]),
        "RLD record not found in output"
    );

    // Parse back and verify
    let parsed = object::File::parse(&*buffer).unwrap();

    // Verify section exists - GOFF creates one section per ED
    let sections: Vec<_> = parsed.sections().collect();
    assert_eq!(sections.len(), 1, "Expected 1 section");

    let section = &sections[0];

    // Verify relocations
    let relocations: Vec<_> = section.relocations().collect();
    assert_eq!(relocations.len(), 1, "Expected 1 relocation");

    let (offset, reloc) = &relocations[0];
    assert_eq!(*offset, 2, "Relocation offset mismatch");
    assert_eq!(
        reloc.kind(),
        RelocationKind::Absolute,
        "Relocation kind mismatch"
    );
    assert_eq!(
        reloc.size(),
        32,
        "Relocation size mismatch (expected 32 bits)"
    );
}

#[test]
fn goff_relocation_multiple() {
    let mut object = write::Object::new(BinaryFormat::Goff, Architecture::S390x, Endianness::Big);

    // Add code section
    let code_data = vec![0x00; 32];
    let code_section = object.add_section(vec![], C_CODE_EBCDIC.to_vec(), SectionKind::Text);
    object.section_mut(code_section).set_data(code_data, 8);

    // Add multiple external symbols
    let sym1 = object.add_symbol(write::Symbol {
        name: FUNC1_EBCDIC.to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: write::SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });

    let sym2 = object.add_symbol(write::Symbol {
        name: FUNC2_EBCDIC.to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: write::SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });

    // Add multiple relocations
    object
        .add_relocation(
            code_section,
            write::Relocation {
                offset: 4,
                symbol: sym1,
                addend: 0,
                flags: RelocationFlags::Generic {
                    kind: RelocationKind::Absolute,
                    encoding: RelocationEncoding::Generic,
                    size: 32,
                },
            },
        )
        .unwrap();

    object
        .add_relocation(
            code_section,
            write::Relocation {
                offset: 12,
                symbol: sym2,
                addend: 0,
                flags: RelocationFlags::Generic {
                    kind: RelocationKind::Absolute,
                    encoding: RelocationEncoding::Generic,
                    size: 32,
                },
            },
        )
        .unwrap();

    // Write to buffer
    let mut buffer = Vec::new();
    object.write_stream(&mut buffer).unwrap();

    // Parse back and verify
    let parsed = object::File::parse(&*buffer).unwrap();

    let section = parsed.sections().next().unwrap();
    let relocations: Vec<_> = section.relocations().collect();

    assert_eq!(relocations.len(), 2, "Expected 2 relocations");
    assert_eq!(relocations[0].0, 4, "First relocation offset mismatch");
    assert_eq!(relocations[1].0, 12, "Second relocation offset mismatch");
}

#[test]
fn goff_relocation_compression() {
    let mut object = write::Object::new(BinaryFormat::Goff, Architecture::S390x, Endianness::Big);

    // Add code section
    let code_data = vec![0x00; 64];
    let code_section = object.add_section(vec![], C_CODE_EBCDIC.to_vec(), SectionKind::Text);
    object.section_mut(code_section).set_data(code_data, 8);

    // Add external symbol
    let ext_symbol = object.add_symbol(write::Symbol {
        name: EXTERNAL_EBCDIC.to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: write::SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });

    // Add multiple relocations to same symbol (should compress R-pointer)
    for i in 0..4 {
        object
            .add_relocation(
                code_section,
                write::Relocation {
                    offset: i * 8,
                    symbol: ext_symbol,
                    addend: 0,
                    flags: RelocationFlags::Generic {
                        kind: RelocationKind::Absolute,
                        encoding: RelocationEncoding::Generic,
                        size: 32,
                    },
                },
            )
            .unwrap();
    }

    // Write to buffer
    let mut buffer = Vec::new();
    object.write_stream(&mut buffer).unwrap();

    // Parse back and verify all relocations present
    let parsed = object::File::parse(&*buffer).unwrap();

    let section = parsed.sections().next().unwrap();
    let relocations: Vec<_> = section.relocations().collect();

    assert_eq!(relocations.len(), 4, "Expected 4 relocations");

    // Verify offsets are correct
    for (i, (offset, _)) in relocations.iter().enumerate() {
        assert_eq!(*offset, (i * 8) as u64, "Relocation {} offset mismatch", i);
    }
}
