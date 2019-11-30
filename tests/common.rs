#![cfg(all(feature = "read", feature = "write"))]

use object::read::{Object, ObjectSection};
use object::{read, write};
use object::{SectionKind, SymbolKind, SymbolScope};
use target_lexicon::{Architecture, BinaryFormat};

#[test]
fn elf_x86_64_common() {
    let mut object = write::Object::new(BinaryFormat::Elf, Architecture::X86_64);

    let symbol = write::Symbol {
        name: b"v1".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: write::SymbolSection::Undefined,
    };
    object.add_common_symbol(symbol, 4, 4);

    let symbol = write::Symbol {
        name: b"v2".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: write::SymbolSection::Undefined,
    };
    object.add_common_symbol(symbol, 8, 8);

    let bytes = object.write().unwrap();

    //std::fs::write(&"common.o", &bytes).unwrap();

    let object = read::File::parse(&bytes).unwrap();
    assert_eq!(object.format(), BinaryFormat::Elf);
    assert_eq!(object.architecture(), Architecture::X86_64);

    let mut symbols = object.symbols();

    let (_, symbol) = symbols.next().unwrap();
    println!("{:?}", symbol);
    assert_eq!(symbol.name(), Some(""));

    let (_, symbol) = symbols.next().unwrap();
    println!("{:?}", symbol);
    assert_eq!(symbol.name(), Some("v1"));
    assert_eq!(symbol.kind(), SymbolKind::Data);
    assert_eq!(symbol.section(), read::SymbolSection::Common);
    assert_eq!(symbol.scope(), SymbolScope::Linkage);
    assert_eq!(symbol.is_weak(), false);
    assert_eq!(symbol.is_undefined(), false);
    assert_eq!(symbol.address(), 0);
    assert_eq!(symbol.size(), 4);

    let (_, symbol) = symbols.next().unwrap();
    println!("{:?}", symbol);
    assert_eq!(symbol.name(), Some("v2"));
    assert_eq!(symbol.kind(), SymbolKind::Data);
    assert_eq!(symbol.section(), read::SymbolSection::Common);
    assert_eq!(symbol.scope(), SymbolScope::Linkage);
    assert_eq!(symbol.is_weak(), false);
    assert_eq!(symbol.is_undefined(), false);
    assert_eq!(symbol.address(), 0);
    assert_eq!(symbol.size(), 8);

    let symbol = symbols.next();
    assert!(symbol.is_none(), format!("unexpected symbol {:?}", symbol));
}

#[test]
fn macho_x86_64_common() {
    let mut object = write::Object::new(BinaryFormat::Macho, Architecture::X86_64);

    let symbol = write::Symbol {
        name: b"v1".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: write::SymbolSection::Undefined,
    };
    object.add_common_symbol(symbol, 4, 4);

    let symbol = write::Symbol {
        name: b"v2".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: write::SymbolSection::Undefined,
    };
    object.add_common_symbol(symbol, 8, 8);

    let bytes = object.write().unwrap();

    //std::fs::write(&"common.o", &bytes).unwrap();

    let object = read::File::parse(&bytes).unwrap();
    assert_eq!(object.format(), BinaryFormat::Macho);
    assert_eq!(object.architecture(), Architecture::X86_64);

    let mut sections = object.sections();

    let common = sections.next().unwrap();
    println!("{:?}", common);
    let common_index = common.index();
    assert_eq!(common.name(), Some("__common"));
    assert_eq!(common.segment_name(), Some("__DATA"));
    assert_eq!(common.kind(), SectionKind::Common);
    assert_eq!(common.size(), 16);
    // This is a bug in goblin: https://github.com/m4b/goblin/pull/195
    //assert_eq!(&*common.data(), &[]);

    let section = sections.next();
    assert!(
        section.is_none(),
        format!("unexpected section {:?}", section)
    );

    let mut symbols = object.symbols();

    let (_, symbol) = symbols.next().unwrap();
    println!("{:?}", symbol);
    assert_eq!(symbol.name(), Some("_v1"));
    assert_eq!(symbol.kind(), SymbolKind::Data);
    assert_eq!(symbol.section_index(), Some(common_index));
    assert_eq!(symbol.scope(), SymbolScope::Linkage);
    assert_eq!(symbol.is_weak(), false);
    assert_eq!(symbol.is_undefined(), false);
    assert_eq!(symbol.address(), 0);

    let (_, symbol) = symbols.next().unwrap();
    println!("{:?}", symbol);
    assert_eq!(symbol.name(), Some("_v2"));
    assert_eq!(symbol.kind(), SymbolKind::Data);
    assert_eq!(symbol.section_index(), Some(common_index));
    assert_eq!(symbol.scope(), SymbolScope::Linkage);
    assert_eq!(symbol.is_weak(), false);
    assert_eq!(symbol.is_undefined(), false);
    assert_eq!(symbol.address(), 8);

    let symbol = symbols.next();
    assert!(symbol.is_none(), format!("unexpected symbol {:?}", symbol));
}
