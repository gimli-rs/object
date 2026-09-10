#![cfg(feature = "goff")]

use object::read;
use std::fs;
use std::path::PathBuf;

/// Convert IBM-1047 EBCDIC bytes to an ASCII `String`.
///
/// The table is the inverse of the ISO-8859-1 → IBM-1047 table: for every
/// `(ascii, ebcdic)` pair in the forward table, this table stores `ascii` at
/// index `ebcdic`.  Bytes that have no printable ASCII counterpart map to 0x00.
fn ebcdic_to_ascii(bytes: &[u8]) -> String {
    let ibm1047_to_iso88591_table: [u8; 256] = [
        0x00, 0x01, 0x02, 0x03, 0x9c, 0x09, 0x86, 0x7f, 0x97, 0x8d, 0x8e, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x9d, 0x0a, 0x08, 0x87, 0x18, 0x19, 0x92, 0x8f, 0x1c, 0x1d,
        0x1e, 0x1f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x17, 0x1b, 0x88, 0x89, 0x8a, 0x8b, 0x8c,
        0x05, 0x06, 0x07, 0x90, 0x91, 0x16, 0x93, 0x94, 0x95, 0x96, 0x04, 0x98, 0x99, 0x9a, 0x9b,
        0x14, 0x15, 0x9e, 0x1a, 0x20, 0xa0, 0xe2, 0xe4, 0xe0, 0xe1, 0xe3, 0xe5, 0xe7, 0xf1, 0xa2,
        0x2e, 0x3c, 0x28, 0x2b, 0x7c, 0x26, 0xe9, 0xea, 0xeb, 0xe8, 0xed, 0xee, 0xef, 0xec, 0xdf,
        0x21, 0x24, 0x2a, 0x29, 0x3b, 0x5e, 0x2d, 0x2f, 0xc2, 0xc4, 0xc0, 0xc1, 0xc3, 0xc5, 0xc7,
        0xd1, 0xa6, 0x2c, 0x25, 0x5f, 0x3e, 0x3f, 0xf8, 0xc9, 0xca, 0xcb, 0xc8, 0xcd, 0xce, 0xcf,
        0xcc, 0x60, 0x3a, 0x23, 0x40, 0x27, 0x3d, 0x22, 0xd8, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x67, 0x68, 0x69, 0xab, 0xbb, 0xf0, 0xfd, 0xfe, 0xb1, 0xb0, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
        0x6f, 0x70, 0x71, 0x72, 0xaa, 0xba, 0xe6, 0xb8, 0xc6, 0xa4, 0xb5, 0x7e, 0x73, 0x74, 0x75,
        0x76, 0x77, 0x78, 0x79, 0x7a, 0xa1, 0xbf, 0xd0, 0x5b, 0xde, 0xae, 0xac, 0xa3, 0xa5, 0xb7,
        0xa9, 0xa7, 0xb6, 0xbc, 0xbd, 0xbe, 0xdd, 0xa8, 0xaf, 0x5d, 0xb4, 0xd7, 0x7b, 0x41, 0x42,
        0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0xad, 0xf4, 0xf6, 0xf2, 0xf3, 0xf5, 0x7d, 0x4a,
        0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0xb9, 0xfb, 0xfc, 0xf9, 0xfa, 0xff, 0x5c,
        0xf7, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0xb2, 0xd4, 0xd6, 0xd2, 0xd3, 0xd5,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xb3, 0xdb, 0xdc, 0xd9, 0xda,
        0x9f,
    ];

    let ascii: Vec<u8> = bytes
        .iter()
        .map(|&b| ibm1047_to_iso88591_table[b as usize])
        .collect();
    String::from_utf8_lossy(&ascii)
        .trim_end_matches('\0')
        .to_string()
}

#[test]
fn goff_base_symbols() {
    let path_to_obj: PathBuf = ["testfiles", "goff", "base.o"].iter().collect();
    let contents = fs::read(&path_to_obj).expect("Could not read base.o");
    let file = read::goff::GoffFile::parse(&contents[..]).expect("Could not parse base.o");

    // Expected ESD records from base.goffdump
    // Format: (ESDID, Type, Parent, Offset, Length, Name)
    let expected_symbols = vec![
        (
            0x00000001, 0x00, 0x00000000, 0x00000000, 0x00000000, "base#C",
        ),
        (
            0x00000002, 0x01, 0x00000001, 0x00000000, 0x000000FC, "C_CODE",
        ),
        (
            0x00000003, 0x02, 0x00000002, 0x00000000, 0x00000000, "base#C",
        ),
        (
            0x00000004, 0x01, 0x00000001, 0x00000000, 0x00000000, "C_@@PPA2",
        ),
        (
            0x00000005, 0x03, 0x00000004, 0x00000000, 0x00000008, ".&ppa2",
        ),
        (
            0x00000006, 0x01, 0x00000001, 0x00000000, 0x00000022, "B_IDRL",
        ),
        (
            0x00000007, 0x00, 0x00000000, 0x00000000, 0x00000000, "CEEMAIN",
        ),
        (
            0x00000008, 0x01, 0x00000007, 0x00000000, 0x0000000C, "C_DATA",
        ),
        (
            0x00000009, 0x02, 0x00000008, 0x00000000, 0x00000000, "CEEMAIN",
        ),
        (
            0x0000000A, 0x04, 0x00000001, 0x00000000, 0x00000000, "CEESTART",
        ),
        (0x0000000B, 0x02, 0x00000002, 0x00000000, 0x00000000, "main"),
        (
            0x0000000C, 0x04, 0x00000001, 0x00000000, 0x00000000, "printf",
        ),
        (
            0x0000000D, 0x04, 0x00000001, 0x00000000, 0x00000000, "EDCINPL",
        ),
        (
            0x0000000E, 0x00, 0x00000000, 0x00000000, 0x00000000, "CEESTART",
        ),
        (
            0x0000000F, 0x01, 0x0000000E, 0x00000000, 0x0000007C, "C_CODE",
        ),
        (
            0x00000010, 0x02, 0x0000000F, 0x00000000, 0x00000000, "CEESTART",
        ),
        (
            0x00000011, 0x04, 0x0000000E, 0x00000000, 0x00000000, "CEEMAIN",
        ),
        (
            0x00000012, 0x04, 0x0000000E, 0x00000000, 0x00000000, "CEEFMAIN",
        ),
        (
            0x00000013, 0x04, 0x0000000E, 0x00000000, 0x00000000, "CEEBETBL",
        ),
        (
            0x00000014, 0x04, 0x0000000E, 0x00000000, 0x00000000, "CEEROOTA",
        ),
        (
            0x00000015, 0x04, 0x00000001, 0x00000000, 0x00000000, "CEESG003",
        ),
    ];

    // Use symbol_records() to access ALL symbols including ED/SD (internal API)
    let symbol_records = file.symbol_records();

    assert_eq!(
        symbol_records.len(),
        expected_symbols.len(),
        "Expected {} symbols, found {}",
        expected_symbols.len(),
        symbol_records.len()
    );

    // Verify each symbol's properties using internal symbol_records access
    for (
        expected_esdid,
        expected_type,
        expected_parent,
        expected_offset,
        expected_length,
        expected_name,
    ) in expected_symbols.iter()
    {
        let symbol = symbol_records
            .get(*expected_esdid as usize - 1)
            .unwrap_or_else(|| panic!("Failed to find symbol with ESDID 0x{:08X}", expected_esdid));

        // Check ESDID using public getter
        assert_eq!(
            symbol.esdid(),
            *expected_esdid,
            "ESDID mismatch for symbol '{}'",
            expected_name
        );

        // Check symbol type using public getter
        assert_eq!(
            symbol.symbol_type(),
            object::goff::SymbolType(*expected_type),
            "Symbol type mismatch for ESDID 0x{:08X} ({})",
            expected_esdid,
            expected_name
        );

        // Check parent ESDID using public getter
        assert_eq!(
            symbol.parent_esdid().0,
            *expected_parent as usize,
            "Parent ESDID mismatch for ESDID 0x{:08X} ({})",
            expected_esdid,
            expected_name
        );

        // Check offset using public getter
        assert_eq!(
            symbol.offset(),
            *expected_offset,
            "Offset mismatch for ESDID 0x{:08X} ({})",
            expected_esdid,
            expected_name
        );

        // Check length using public getter
        assert_eq!(
            symbol.length(),
            *expected_length,
            "Length mismatch for ESDID 0x{:08X} ({})",
            expected_esdid,
            expected_name
        );

        // Check name by converting EBCDIC to ASCII
        assert_eq!(
            ebcdic_to_ascii(symbol.name_bytes_owned()),
            *expected_name,
            "Name mismatch for ESDID 0x{:08X}",
            expected_esdid
        );
    }
}

#[test]
fn goff_foo_symbols() {
    let path_to_obj: PathBuf = ["testfiles", "goff", "foo.o"].iter().collect();
    let contents = fs::read(&path_to_obj).expect("Could not read foo.o");
    let file = read::goff::GoffFile::parse(&contents[..]).expect("Could not parse foo.o");

    // Expected ESD records from foo.goffdump
    // Format: (ESDID, Type, Parent, Offset, Length, Name)
    let expected_symbols = vec![
        (
            0x00000001, 0x00, 0x00000000, 0x00000000, 0x00000000, "foo#C",
        ),
        (
            0x00000002, 0x01, 0x00000001, 0x00000000, 0x00000000, "C_WSA64",
        ),
        (
            0x00000003, 0x03, 0x00000002, 0x00000000, 0x00000002, "foo#S",
        ),
        (
            0x00000004, 0x01, 0x00000001, 0x00000000, 0x000000A4, "C_CODE64",
        ),
        (
            0x00000005, 0x02, 0x00000004, 0x00000000, 0x00000000, "foo#C",
        ),
        (
            0x00000006,
            0x01,
            0x00000001,
            0x00000000,
            0x00000000,
            "C_@@QPPA2",
        ),
        (
            0x00000007, 0x03, 0x00000006, 0x00000000, 0x00000008, ".&ppa2",
        ),
        (
            0x00000008, 0x01, 0x00000001, 0x00000000, 0x00000022, "B_IDRL",
        ),
        (
            0x00000009, 0x04, 0x00000001, 0x00000000, 0x00000000, "CELQSTRT",
        ),
        (0x0000000A, 0x02, 0x00000004, 0x00000040, 0x00000000, "c"),
        (0x0000000B, 0x02, 0x00000004, 0x00000060, 0x00000000, "bar"),
    ];

    // Use symbol_records() to access ALL symbols including ED/SD (internal API)
    let symbol_records = file.symbol_records();

    assert_eq!(
        symbol_records.len(),
        expected_symbols.len(),
        "Expected {} symbols, found {}",
        expected_symbols.len(),
        symbol_records.len()
    );

    // Verify each symbol's properties using internal symbol_records access
    for (
        expected_esdid,
        expected_type,
        expected_parent,
        expected_offset,
        expected_length,
        expected_name,
    ) in expected_symbols.iter()
    {
        let symbol = symbol_records
            .get(*expected_esdid as usize - 1)
            .unwrap_or_else(|| panic!("Failed to find symbol with ESDID 0x{:08X}", expected_esdid));

        // Check ESDID using public getter
        assert_eq!(
            symbol.esdid(),
            *expected_esdid,
            "ESDID mismatch for symbol '{}'",
            expected_name
        );

        // Check symbol type using public getter
        assert_eq!(
            symbol.symbol_type(),
            object::goff::SymbolType(*expected_type),
            "Symbol type mismatch for ESDID 0x{:08X} ({})",
            expected_esdid,
            expected_name
        );

        // Check parent ESDID using public getter
        assert_eq!(
            symbol.parent_esdid().0,
            *expected_parent as usize,
            "Parent ESDID mismatch for ESDID 0x{:08X} ({})",
            expected_esdid,
            expected_name
        );

        // Check offset using public getter
        assert_eq!(
            symbol.offset(),
            *expected_offset,
            "Offset mismatch for ESDID 0x{:08X} ({})",
            expected_esdid,
            expected_name
        );

        // Check length using public getter
        assert_eq!(
            symbol.length(),
            *expected_length,
            "Length mismatch for ESDID 0x{:08X} ({})",
            expected_esdid,
            expected_name
        );

        // Check name by converting EBCDIC to ASCII
        assert_eq!(
            ebcdic_to_ascii(symbol.name_bytes_owned()),
            *expected_name,
            "Name mismatch for ESDID 0x{:08X}",
            expected_esdid
        );
    }
}

#[test]
fn goff_foo_behavioral_attributes() {
    use object::goff::*;

    let path_to_obj: PathBuf = ["testfiles", "goff", "foo.o"].iter().collect();
    let contents = fs::read(&path_to_obj).expect("Could not read foo.o");
    let file = read::goff::GoffFile::parse(&contents[..]).expect("Could not parse foo.o");

    // Use symbol_records() to access SD/ED symbols (types 0x00 and 0x01)
    let symbol_records = file.symbol_records();

    // Test behavioral attributes for ESDID 00000001 (foo#C, Sd)
    // Expected BA bytes: 00 00 00 60 00 01 00 00 00 00
    // BA30=3 (RENT) is in byte[3]=0x60, bits 5-7 (IBM bit numbering 0-2)
    // BA54=1 (Section) is in byte[5]=0x01, bits 0-3 (IBM bit numbering 4-7)
    let symbol1 = symbol_records
        .get(0x00000001_usize - 1)
        .expect("Failed to find symbol with ESDID 0x00000001");
    let flags1 = symbol1.behavioral_flags();
    assert_eq!(
        flags1.amode(),
        GOFF_AMODE_UNSPEC,
        "ESDID 1: AMODE should be Unspec"
    );
    assert_eq!(
        flags1.rmode(),
        GOFF_RMODE_UNSPEC,
        "ESDID 1: RMODE should be Unspec"
    );
    // BA30: byte[3] bits 5-7 = 3 (RENT)
    assert_eq!(
        (flags1.tasking_and_exec >> 5) & 0x07,
        3,
        "ESDID 1: Tasking bits should be 3 (RENT)"
    );
    // BA54: byte[5] bits 0-3 = 1 (Section scope)
    assert_eq!(
        flags1.loading_and_scope & 0x0F,
        1,
        "ESDID 1: Binding scope bits should be 1 (Section)"
    );

    // Test behavioral attributes for ESDID 00000002 (C_WSA64, Ed)
    // Expected BA bytes: 00 04 01 00 00 40 04 00 00 00
    // BA10=04, BA24=1, BA50=1, BA62=0 (OS linkage), BA63=04
    let symbol2 = symbol_records
        .get(0x00000002_usize - 1)
        .expect("Failed to find symbol with ESDID 0x00000002");
    let flags2 = symbol2.behavioral_flags();
    assert_eq!(
        flags2.amode(),
        GOFF_AMODE_UNSPEC,
        "ESDID 2: AMODE should be Unspec"
    );
    assert_eq!(flags2.rmode(), GOFF_RMODE_64, "ESDID 2: RMODE should be 64");
    assert_eq!(
        flags2.text_and_binding & 0x0F,
        1,
        "ESDID 2: BA24 (Binding) should be 1 (Merge)"
    );
    assert_eq!(
        (flags2.loading_and_scope >> 6) & 0x03,
        1,
        "ESDID 2: BA50 (Loading) should be 1 (Deferred)"
    );
    assert!(
        !flags2.is_xplink(),
        "ESDID 2: BA62 should indicate OS linkage (not XPLINK)"
    );
    assert_eq!(
        flags2.linkage_and_align & 0x1F,
        4,
        "ESDID 2: BA63 (Alignment) should be 4 (Quadword)"
    );

    // Test behavioral attributes for ESDID 00000003 (foo#S, Pr)
    // Expected BA bytes: 00 00 00 00 00 00 24 00 00 00
    // BA62=1 (XPLINK), BA63=04 (Quadword alignment)
    let symbol3 = symbol_records
        .get(0x00000003_usize - 1)
        .expect("Failed to find symbol with ESDID 0x00000003");
    let flags3 = symbol3.behavioral_flags();
    assert!(
        flags3.is_xplink(),
        "ESDID 3: BA62 should indicate XPLINK linkage"
    );
    assert_eq!(
        flags3.linkage_and_align & 0x1F,
        4,
        "ESDID 3: BA63 (Alignment) should be 4 (Quadword)"
    );

    // Test behavioral attributes for ESDID 00000004 (C_CODE64, Ed)
    // Expected BA bytes: 00 04 00 00 00 00 04 00 00 00
    // BA10=04 (RMODE 64), BA62=0 (OS linkage)
    let symbol4 = symbol_records
        .get(0x00000004_usize - 1)
        .expect("Failed to find symbol with ESDID 0x00000004");
    let flags4 = symbol4.behavioral_flags();
    assert_eq!(flags4.rmode(), GOFF_RMODE_64, "ESDID 4: RMODE should be 64");
    assert!(
        !flags4.is_xplink(),
        "ESDID 4: BA62 should indicate OS linkage (not XPLINK)"
    );

    // Test behavioral attributes for ESDID 00000005 (foo#C, Ld)
    // Expected BA bytes: 04 00 00 40 00 01 00 00 00 00
    // BA00=04, BA35=2, BA54=1, BA62=1 (XPLINK linkage)
    let symbol5 = symbol_records
        .get(0x00000005_usize - 1)
        .expect("Failed to find symbol with ESDID 0x00000005");
    let flags5 = symbol5.behavioral_flags();
    assert_eq!(flags5.amode(), GOFF_AMODE_64, "ESDID 5: AMODE should be 64");
    assert_eq!(
        flags5.rmode(),
        GOFF_RMODE_UNSPEC,
        "ESDID 5: RMODE should be Unspec"
    );
    assert_eq!(
        flags5.tasking_and_exec & 0x07,
        2,
        "ESDID 5: BA35 (Executable) should be 2 (Code)"
    );
    assert_eq!(
        flags5.loading_and_scope & 0x0F,
        1,
        "ESDID 5: BA54 (Scope) should be 1 (Section)"
    );
    assert!(
        flags5.is_xplink(),
        "ESDID 5: BA62 should indicate XPLINK linkage"
    );
    assert_eq!(
        flags5.linkage_and_align & 0x1F,
        0,
        "ESDID 5: BA63 (Alignment) should be 0 (Byte)"
    );

    // Test behavioral attributes for ESDID 00000009 (CELQSTRT, ErWx)
    // Expected BA bytes: 04 04 00 40 00 04 00 00 00 00
    // BA00=04, BA10=04, BA35=2, BA54=4
    let symbol9 = symbol_records
        .get(0x00000009_usize - 1)
        .expect("Failed to find symbol with ESDID 0x00000009");
    let flags9 = symbol9.behavioral_flags();
    assert_eq!(flags9.amode(), GOFF_AMODE_64, "ESDID 9: AMODE should be 64");
    assert_eq!(flags9.rmode(), GOFF_RMODE_64, "ESDID 9: RMODE should be 64");
    assert_eq!(
        flags9.tasking_and_exec & 0x07,
        2,
        "ESDID 9: BA35 (Executable) should be 2 (Code)"
    );
    assert_eq!(
        flags9.loading_and_scope & 0x0F,
        4,
        "ESDID 9: BA54 (Scope) should be 4 (Import-Export)"
    );
}

#[test]
fn goff_foo_section_flags() {
    let path_to_obj: PathBuf = ["testfiles", "goff", "foo.o"].iter().collect();
    let contents = fs::read(&path_to_obj).expect("Could not read foo.o");
    let file = read::goff::GoffFile::parse(&contents[..]).expect("Could not parse foo.o");

    // Use symbol_records() to access all symbols including sections (ED/SD types)
    let symbol_records = file.symbol_records();

    println!("\n=== Section Flags for foo.o ===\n");

    // Iterate through all symbols and print flags for section-type symbols
    for symbol in symbol_records.iter() {
        let symbol_type = symbol.symbol_type();

        // Only print for SD (0x00) and ED (0x01) types which represent sections
        if symbol_type.0 == 0x00 || symbol_type.0 == 0x01 {
            let flags = symbol.behavioral_flags();
            let name = ebcdic_to_ascii(symbol.name_bytes_owned());

            println!(
                "ESDID: 0x{:08X} | Type: 0x{:02X} | Name: {}",
                symbol.esdid(),
                symbol_type.0,
                name
            );
            println!(
                "  AMODE: 0x{:02X} ({})",
                flags.amode.0,
                match flags.amode() {
                    object::goff::GOFF_AMODE_24 => "24-bit",
                    object::goff::GOFF_AMODE_31 => "31-bit",
                    object::goff::GOFF_AMODE_64 => "64-bit",
                    object::goff::GOFF_AMODE_ANY => "Any",
                    _ => "Unspecified",
                }
            );
            println!(
                "  RMODE: 0x{:02X} ({})",
                flags.rmode.0,
                match flags.rmode() {
                    object::goff::GOFF_RMODE_24 => "24-bit",
                    object::goff::GOFF_RMODE_31 => "31-bit",
                    object::goff::GOFF_RMODE_64 => "64-bit",
                    _ => "Unspecified",
                }
            );
            println!("  Text/Binding: 0x{:02X}", flags.text_and_binding);
            println!("  Tasking/Exec: 0x{:02X}", flags.tasking_and_exec);
            println!("  Dup/Strength: 0x{:02X}", flags.dup_and_strength);
            println!("  Loading/Scope: 0x{:02X}", flags.loading_and_scope);
            println!("  Linkage/Align: 0x{:02X}", flags.linkage_and_align);
            println!("  XPLINK: {}", flags.is_xplink());
            println!(
                "  Binding Scope: 0x{:02X} ({})",
                flags.binding_scope(),
                match flags.binding_scope() {
                    object::goff::GOFF_SCOPE_UNSPEC => "Unspecified",
                    object::goff::GOFF_SCOPE_SECTION => "Section",
                    object::goff::GOFF_SCOPE_MODULE => "Module",
                    object::goff::GOFF_SCOPE_LIBRARY => "Library",
                    object::goff::GOFF_SCOPE_IMPORT_EXPORT => "Import/Export",
                    _ => "Unknown",
                }
            );
            println!();
        }
    }
}

#[test]
fn goff_foo_binding_scope() {
    let path_to_obj: PathBuf = ["testfiles", "goff", "foo.o"].iter().collect();
    let contents = fs::read(&path_to_obj).expect("Could not read foo.o");
    let file = read::goff::GoffFile::parse(&contents[..]).expect("Could not parse foo.o");

    let symbol_records = file.symbol_records();

    println!("\n=== Binding Scope Test for foo.o ===\n");
    println!("Expected from foo.goffdump BA54 column:\n");
    println!("ESDID 1: BA54=1 (Section)");
    println!("ESDID 2: BA54=0 (Unspec)");
    println!("ESDID 3: BA54=1 (Section)");
    println!("ESDID 4: BA54=0 (Unspec)");
    println!("ESDID 5: BA54=1 (Section)");
    println!("ESDID 9: BA54=4 (Import-Export)\n");

    // Check specific symbols
    for esdid in [1, 2, 3, 4, 5, 9] {
        if let Some(symbol) = symbol_records.get(esdid - 1) {
            let flags = symbol.behavioral_flags();
            let name = ebcdic_to_ascii(symbol.name_bytes_owned());
            let scope_raw = flags.loading_and_scope & 0xF0;
            let scope_value = flags.binding_scope();

            println!("ESDID: 0x{:08X} | Name: {}", esdid, name);
            println!(
                "  Byte 5 (loading_and_scope): 0x{:02X}",
                flags.loading_and_scope
            );
            println!("  Binding Scope (bits 4-7, mask 0xF0): 0x{:02X}", scope_raw);
            println!("  binding_scope() returns: 0x{:02X}", scope_value.0);
            println!(
                "  Matches constant: {}",
                match scope_value {
                    object::goff::GOFF_SCOPE_UNSPEC => "UNSPEC (0x00)",
                    object::goff::GOFF_SCOPE_SECTION => "SECTION (0x10)",
                    object::goff::GOFF_SCOPE_MODULE => "MODULE (0x20)",
                    object::goff::GOFF_SCOPE_LIBRARY => "LIBRARY (0x30)",
                    object::goff::GOFF_SCOPE_IMPORT_EXPORT => "IMPORT_EXPORT (0x40)",
                    _ => "UNKNOWN",
                }
            );
            println!();
        }
    }
}
