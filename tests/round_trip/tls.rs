#![cfg(all(feature = "read", feature = "write"))]

use object::read::{Object, ObjectSection};
use object::{read, write};
use object::{
    RelocationEncoding, RelocationKind, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};
use target_lexicon::{Architecture, BinaryFormat};

#[test]
fn coff_x86_64_tls() {
    let mut object = write::Object::new(BinaryFormat::Coff, Architecture::X86_64);

    let section = object.section_id(write::StandardSection::Tls);
    let symbol = object.add_symbol(write::Symbol {
        name: b"tls1".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Tls,
        scope: SymbolScope::Linkage,
        weak: false,
        section: write::SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });
    object.add_symbol_data(symbol, section, &[1; 30], 4);

    let bytes = object.write().unwrap();

    //std::fs::write(&"tls.o", &bytes).unwrap();

    let object = read::File::parse(&bytes).unwrap();
    assert_eq!(object.format(), BinaryFormat::Coff);
    assert_eq!(object.architecture(), Architecture::X86_64);

    let mut sections = object.sections();

    let section = sections.next().unwrap();
    println!("{:?}", section);
    let tls_index = section.index();
    assert_eq!(section.name(), Some(".tls$"));
    assert_eq!(section.kind(), SectionKind::Data);
    assert_eq!(section.size(), 30);
    assert_eq!(&section.data()[..], &[1; 30]);

    let mut symbols = object.symbols();

    let (_, symbol) = symbols.next().unwrap();
    println!("{:?}", symbol);
    assert_eq!(symbol.name(), Some("tls1"));
    assert_eq!(symbol.kind(), SymbolKind::Data);
    assert_eq!(symbol.section_index(), Some(tls_index));
    assert_eq!(symbol.scope(), SymbolScope::Linkage);
    assert_eq!(symbol.is_weak(), false);
    assert_eq!(symbol.is_undefined(), false);
}

#[test]
fn elf_x86_64_tls() {
    let mut object = write::Object::new(BinaryFormat::Elf, Architecture::X86_64);

    let section = object.section_id(write::StandardSection::Tls);
    let symbol = object.add_symbol(write::Symbol {
        name: b"tls1".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Tls,
        scope: SymbolScope::Linkage,
        weak: false,
        section: write::SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });
    object.add_symbol_data(symbol, section, &[1; 30], 4);

    let section = object.section_id(write::StandardSection::UninitializedTls);
    let symbol = object.add_symbol(write::Symbol {
        name: b"tls2".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Tls,
        scope: SymbolScope::Linkage,
        weak: false,
        section: write::SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });
    object.add_symbol_bss(symbol, section, 31, 4);

    let bytes = object.write().unwrap();

    //std::fs::write(&"tls.o", &bytes).unwrap();

    let object = read::File::parse(&bytes).unwrap();
    assert_eq!(object.format(), BinaryFormat::Elf);
    assert_eq!(object.architecture(), Architecture::X86_64);

    let mut sections = object.sections();

    let section = sections.next().unwrap();
    println!("{:?}", section);
    assert_eq!(section.name(), Some(""));

    let section = sections.next().unwrap();
    println!("{:?}", section);
    let tdata_index = section.index();
    assert_eq!(section.name(), Some(".tdata"));
    assert_eq!(section.kind(), SectionKind::Tls);
    assert_eq!(section.size(), 30);
    assert_eq!(&section.data()[..], &[1; 30]);

    let section = sections.next().unwrap();
    println!("{:?}", section);
    let tbss_index = section.index();
    assert_eq!(section.name(), Some(".tbss"));
    assert_eq!(section.kind(), SectionKind::UninitializedTls);
    assert_eq!(section.size(), 31);
    assert_eq!(&section.data()[..], &[]);

    let mut symbols = object.symbols();

    let (_, symbol) = symbols.next().unwrap();
    println!("{:?}", symbol);
    assert_eq!(symbol.name(), Some(""));

    let (_, symbol) = symbols.next().unwrap();
    println!("{:?}", symbol);
    assert_eq!(symbol.name(), Some("tls1"));
    assert_eq!(symbol.kind(), SymbolKind::Tls);
    assert_eq!(symbol.section_index(), Some(tdata_index));
    assert_eq!(symbol.scope(), SymbolScope::Linkage);
    assert_eq!(symbol.is_weak(), false);
    assert_eq!(symbol.is_undefined(), false);
    assert_eq!(symbol.size(), 30);

    let (_, symbol) = symbols.next().unwrap();
    println!("{:?}", symbol);
    assert_eq!(symbol.name(), Some("tls2"));
    assert_eq!(symbol.kind(), SymbolKind::Tls);
    assert_eq!(symbol.section_index(), Some(tbss_index));
    assert_eq!(symbol.scope(), SymbolScope::Linkage);
    assert_eq!(symbol.is_weak(), false);
    assert_eq!(symbol.is_undefined(), false);
    assert_eq!(symbol.size(), 31);
}

#[test]
fn macho_x86_64_tls() {
    let mut object = write::Object::new(BinaryFormat::Macho, Architecture::X86_64);

    let section = object.section_id(write::StandardSection::Tls);
    let symbol = object.add_symbol(write::Symbol {
        name: b"tls1".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Tls,
        scope: SymbolScope::Linkage,
        weak: false,
        section: write::SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });
    object.add_symbol_data(symbol, section, &[1; 30], 4);

    let section = object.section_id(write::StandardSection::UninitializedTls);
    let symbol = object.add_symbol(write::Symbol {
        name: b"tls2".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Tls,
        scope: SymbolScope::Linkage,
        weak: false,
        section: write::SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });
    object.add_symbol_bss(symbol, section, 31, 4);

    let bytes = object.write().unwrap();

    //std::fs::write(&"tls.o", &bytes).unwrap();

    let object = read::File::parse(&bytes).unwrap();
    assert_eq!(object.format(), BinaryFormat::Macho);
    assert_eq!(object.architecture(), Architecture::X86_64);

    let mut sections = object.sections();

    let thread_data = sections.next().unwrap();
    println!("{:?}", thread_data);
    let thread_data_index = thread_data.index();
    assert_eq!(thread_data.name(), Some("__thread_data"));
    assert_eq!(thread_data.segment_name(), Some("__DATA"));
    assert_eq!(thread_data.kind(), SectionKind::Tls);
    assert_eq!(thread_data.size(), 30);
    assert_eq!(&thread_data.data()[..], &[1; 30]);

    let thread_vars = sections.next().unwrap();
    println!("{:?}", thread_vars);
    let thread_vars_index = thread_vars.index();
    assert_eq!(thread_vars.name(), Some("__thread_vars"));
    assert_eq!(thread_vars.segment_name(), Some("__DATA"));
    assert_eq!(thread_vars.kind(), SectionKind::TlsVariables);
    assert_eq!(thread_vars.size(), 2 * 3 * 8);
    assert_eq!(&thread_vars.data()[..], &[0; 48][..]);

    let thread_bss = sections.next().unwrap();
    println!("{:?}", thread_bss);
    let thread_bss_index = thread_bss.index();
    assert_eq!(thread_bss.name(), Some("__thread_bss"));
    assert_eq!(thread_bss.segment_name(), Some("__DATA"));
    assert_eq!(thread_bss.kind(), SectionKind::UninitializedTls);
    assert_eq!(thread_bss.size(), 31);
    assert_eq!(&thread_bss.data()[..], &[]);

    let mut symbols = object.symbols();

    let (_, symbol) = symbols.next().unwrap();
    println!("{:?}", symbol);
    assert_eq!(symbol.name(), Some("_tls1"));
    assert_eq!(symbol.kind(), SymbolKind::Tls);
    assert_eq!(symbol.section_index(), Some(thread_vars_index));
    assert_eq!(symbol.scope(), SymbolScope::Linkage);
    assert_eq!(symbol.is_weak(), false);
    assert_eq!(symbol.is_undefined(), false);

    let (tls1_init_symbol, symbol) = symbols.next().unwrap();
    println!("{:?}", symbol);
    assert_eq!(symbol.name(), Some("_tls1$tlv$init"));
    assert_eq!(symbol.kind(), SymbolKind::Tls);
    assert_eq!(symbol.section_index(), Some(thread_data_index));
    assert_eq!(symbol.scope(), SymbolScope::Compilation);
    assert_eq!(symbol.is_weak(), false);
    assert_eq!(symbol.is_undefined(), false);

    let (tlv_bootstrap_symbol, symbol) = symbols.next().unwrap();
    println!("{:?}", symbol);
    assert_eq!(symbol.name(), Some("__tlv_bootstrap"));
    assert_eq!(symbol.kind(), SymbolKind::Unknown);
    assert_eq!(symbol.section_index(), None);
    assert_eq!(symbol.scope(), SymbolScope::Unknown);
    assert_eq!(symbol.is_weak(), false);
    assert_eq!(symbol.is_undefined(), true);

    let (_, symbol) = symbols.next().unwrap();
    println!("{:?}", symbol);
    assert_eq!(symbol.name(), Some("_tls2"));
    assert_eq!(symbol.kind(), SymbolKind::Tls);
    assert_eq!(symbol.section_index(), Some(thread_vars_index));
    assert_eq!(symbol.scope(), SymbolScope::Linkage);
    assert_eq!(symbol.is_weak(), false);
    assert_eq!(symbol.is_undefined(), false);

    let (tls2_init_symbol, symbol) = symbols.next().unwrap();
    println!("{:?}", symbol);
    assert_eq!(symbol.name(), Some("_tls2$tlv$init"));
    assert_eq!(symbol.kind(), SymbolKind::Tls);
    assert_eq!(symbol.section_index(), Some(thread_bss_index));
    assert_eq!(symbol.scope(), SymbolScope::Compilation);
    assert_eq!(symbol.is_weak(), false);
    assert_eq!(symbol.is_undefined(), false);

    let mut relocations = thread_vars.relocations();

    let (offset, relocation) = relocations.next().unwrap();
    println!("{:?}", relocation);
    assert_eq!(offset, 0);
    assert_eq!(relocation.kind(), RelocationKind::Absolute);
    assert_eq!(relocation.encoding(), RelocationEncoding::Generic);
    assert_eq!(relocation.size(), 64);
    assert_eq!(
        relocation.target(),
        read::RelocationTarget::Symbol(tlv_bootstrap_symbol)
    );
    assert_eq!(relocation.addend(), 0);

    let (offset, relocation) = relocations.next().unwrap();
    println!("{:?}", relocation);
    assert_eq!(offset, 16);
    assert_eq!(relocation.kind(), RelocationKind::Absolute);
    assert_eq!(relocation.encoding(), RelocationEncoding::Generic);
    assert_eq!(relocation.size(), 64);
    assert_eq!(
        relocation.target(),
        read::RelocationTarget::Symbol(tls1_init_symbol)
    );
    assert_eq!(relocation.addend(), 0);

    let (offset, relocation) = relocations.next().unwrap();
    println!("{:?}", relocation);
    assert_eq!(offset, 24);
    assert_eq!(relocation.kind(), RelocationKind::Absolute);
    assert_eq!(relocation.encoding(), RelocationEncoding::Generic);
    assert_eq!(relocation.size(), 64);
    assert_eq!(
        relocation.target(),
        read::RelocationTarget::Symbol(tlv_bootstrap_symbol)
    );
    assert_eq!(relocation.addend(), 0);

    let (offset, relocation) = relocations.next().unwrap();
    println!("{:?}", relocation);
    assert_eq!(offset, 40);
    assert_eq!(relocation.kind(), RelocationKind::Absolute);
    assert_eq!(relocation.encoding(), RelocationEncoding::Generic);
    assert_eq!(relocation.size(), 64);
    assert_eq!(
        relocation.target(),
        read::RelocationTarget::Symbol(tls2_init_symbol)
    );
    assert_eq!(relocation.addend(), 0);
}
