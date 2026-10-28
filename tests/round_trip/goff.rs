#![cfg(all(feature = "read", feature = "write"))]

use object::read::{ObjectSection, ObjectSymbol};
use object::{
    Architecture, BinaryFormat, Endianness, Object, RelocationEncoding, RelocationFlags,
    RelocationKind, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};
use object::{goff, pod, read, write};

// string constants
//
const CEESTART: &[u8] = b"CEESTART";
const PRINTF: &[u8] = b"printf";
const DOTDEBUG_INFO: &[u8] = b"D_INFO";
const DOTDEBUG_LINE: &[u8] = b"D_LINE";
const DOTDEBUG_STR: &[u8] = b"D_STR";
const C_CODE: &[u8] = b"C_CODE";
const EXTERNAL_FUNC: &[u8] = b"external_func";
const FUNC1: &[u8] = b"func1";
const FUNC2: &[u8] = b"func2_ext"; // 9 bytes, requires continuation record
const EXTERNAL: &[u8] = b"external";

/// Test basic GOFF file structure with external references
/// Similar to base.o which has SD (compile unit), ER (external refs), and ED (sections)
#[test]
fn goff_basic_structure() {
    let mut object = write::Object::new(BinaryFormat::Goff, Architecture::S390x, Endianness::Big);

    // Add external text reference (like CEESTART in base.o)
    let _text_er = object.add_symbol(write::Symbol {
        name: CEESTART.to_vec(),
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
        name: PRINTF.to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: write::SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });

    // Add a debug section (ED record in GOFF)
    let debug_section = object.add_section(Vec::new(), DOTDEBUG_INFO.to_vec(), SectionKind::Debug);
    // 58 bytes of data forces a TXT continuation record (inline field holds 56 bytes max)
    object.append_section_data(
        debug_section,
        &[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
            0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x3A,
        ],
        1,
    );

    let bytes = object.write().unwrap();

    // Verify we can parse it back
    let object = read::File::parse(&*bytes).unwrap();
    assert_eq!(object.format(), BinaryFormat::Goff);
    assert_eq!(object.architecture(), Architecture::S390x);
    assert_eq!(object.endianness(), Endianness::Big);

    let goff = read::goff::GoffFile::parse(&*bytes).unwrap();

    // Verify external symbols are present
    let symbols: Vec<_> = goff.symbols().collect();
    assert!(
        symbols.len() >= 2,
        "Should have at least 2 external symbols"
    );

    let mut found_ceestart = false;
    let mut found_printf = false;

    for symbol in &symbols {
        let name_bytes = symbol.decoded_name_bytes().unwrap();
        if name_bytes == CEESTART {
            found_ceestart = true;
            assert!(symbol.is_undefined());
        } else if name_bytes == PRINTF {
            found_printf = true;
            assert!(symbol.is_undefined());
        }
    }

    assert!(found_ceestart, "Should find CEESTART symbol");
    assert!(found_printf, "Should find printf symbol");

    let printf = object
        .symbol_by_name_bytes(PRINTF)
        .expect("Should find printf");
    assert_eq!(printf.decoded_name().as_deref(), Ok("printf"));

    // Verify section data
    let sections: Vec<_> = object.sections().collect();
    assert!(!sections.is_empty(), "Should have at least one section");

    let goff_sections: Vec<read::goff::GoffSection<'_, '_>> = goff.sections().collect();
    assert!(
        !goff_sections.is_empty(),
        "Concrete GOFF parser should expose at least one section"
    );

    // Find the debug section
    let debug_section = object
        .section_by_name_bytes(DOTDEBUG_INFO)
        .expect("Should find .debug_info section");

    // Check section data
    let data = debug_section.collected_data().unwrap();
    assert_eq!(
        &data[..],
        &[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
            0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x3A,
        ]
    );
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
    let debug1 = object.add_section(Vec::new(), DOTDEBUG_LINE.to_vec(), SectionKind::Debug);
    object.append_section_data(debug1, &[0xDE, 0xAD], 1);

    let debug2 = object.add_section(Vec::new(), DOTDEBUG_STR.to_vec(), SectionKind::Debug);
    object.append_section_data(debug2, &[0xBE, 0xEF], 1);

    let bytes = object.write().unwrap();

    let object = read::File::parse(&*bytes).unwrap();
    assert_eq!(object.format(), BinaryFormat::Goff);

    let sections: Vec<_> = object.sections().collect();
    assert_eq!(sections.len(), 2, "Should have 2 debug sections");

    let goff = read::goff::GoffFile::parse(&*bytes).unwrap();
    let goff_sections: Vec<read::goff::GoffSection<'_, '_>> = goff.sections().collect();
    assert_eq!(
        goff_sections.len(),
        2,
        "Concrete GOFF parser should have 2 debug sections"
    );

    // Verify section data using the concrete GOFF section type.
    let data0 = goff_sections[0].collected_data().unwrap();
    assert_eq!(&data0[..], &[0xDE, 0xAD]);
    let data1 = goff_sections[1].collected_data().unwrap();
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
    let code_section = object.add_section(vec![], C_CODE.to_vec(), SectionKind::Text);
    object.section_mut(code_section).set_data(code_data, 8);

    // Add external symbol
    let ext_symbol = object.add_symbol(write::Symbol {
        name: EXTERNAL_FUNC.to_vec(),
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
        buffer.windows(3).any(|w| w == [0x03, 0x20, 0x00]),
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
    let code_section = object.add_section(vec![], C_CODE.to_vec(), SectionKind::Text);
    object.section_mut(code_section).set_data(code_data, 8);

    // Add multiple external symbols
    let sym1 = object.add_symbol(write::Symbol {
        name: FUNC1.to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: write::SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });

    let sym2 = object.add_symbol(write::Symbol {
        name: FUNC2.to_vec(),
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
    let code_section = object.add_section(vec![], C_CODE.to_vec(), SectionKind::Text);
    object.section_mut(code_section).set_data(code_data, 8);

    // Add external symbol
    let ext_symbol = object.add_symbol(write::Symbol {
        name: EXTERNAL.to_vec(),
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

#[test]
fn goff_relocation_rld_continuation() {
    // Each relocation is at least 12 bytes; 3000 * 12 > 32767 (max logical record size).
    const NUM_RELOCATIONS: usize = 3000;

    let mut object = write::Object::new(BinaryFormat::Goff, Architecture::S390x, Endianness::Big);

    let code_section = object.add_section(vec![], C_CODE.to_vec(), SectionKind::Text);
    object
        .section_mut(code_section)
        .set_data(vec![0x00; NUM_RELOCATIONS * 4], 8);

    let symbol = object.add_symbol(write::Symbol {
        name: EXTERNAL.to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: write::SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });

    for i in 0..NUM_RELOCATIONS {
        // Each relocation differs in offset.
        object
            .add_relocation(
                code_section,
                write::Relocation {
                    offset: (i as u64) * 4,
                    symbol,
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

    let mut buffer = Vec::new();
    object.write_stream(&mut buffer).unwrap();

    let prefix = goff::RecordPrefix::new(goff::RT_RLD).with_continued(true);
    assert_eq!(buffer.len() % 80, 0);
    assert_eq!(
        buffer
            .chunks_exact(80)
            .filter(|w| w.starts_with(pod::bytes_of(&prefix)))
            .count(),
        2
    );

    let parsed = object::File::parse(&*buffer).unwrap();
    let section = parsed.sections().next().unwrap();
    let mut relocations: Vec<_> = section.relocations().map(|(offset, _)| offset).collect();
    relocations.sort();

    assert_eq!(relocations.len(), NUM_RELOCATIONS);
    for (i, offset) in relocations.iter().enumerate() {
        assert_eq!(*offset, (i * 4) as u64);
    }
}
