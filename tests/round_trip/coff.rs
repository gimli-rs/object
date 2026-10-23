use object::read::coff::Symbol;
use object::read::{Object, ObjectSection, ObjectSymbol};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationEncoding, RelocationFlags, RelocationKind,
    SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};
use object::{read, write};

#[test]
fn limits_section_count() {
    let mut object =
        write::Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let max = usize::from(object::pe::IMAGE_SYM_SECTION_MAX);
    let mut last = object.add_section(vec![], b".data".to_vec(), SectionKind::Data);
    for _ in 1..max {
        last = object.add_section(vec![], b".data".to_vec(), SectionKind::Data);
    }
    object.section_symbol(last);
    let bytes = object.write().unwrap();
    let file = read::File::parse(&*bytes).unwrap();
    assert_eq!(file.sections().count(), max);
    assert_eq!(
        file.symbols().next().unwrap().section_index(),
        Some(object::SectionIndex(max))
    );

    object.add_section(vec![], b".data".to_vec(), SectionKind::Data);
    assert!(object.write().is_err());
}

#[test]
fn limits_bss_size() {
    let mut object =
        write::Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let section = object.section_id(write::StandardSection::UninitializedData);
    object.section_symbol(section);
    object.append_section_bss(section, u64::from(u32::MAX), 1);
    let bytes = object.write().unwrap();
    let file = read::File::parse(&*bytes).unwrap();
    let bss = file.sections().next().unwrap();
    assert_eq!(bss.size(), u64::from(u32::MAX));
    assert_eq!(bss.data(), Ok(&[][..]));

    object.append_section_bss(section, 1, 1);
    assert!(object.write().is_err());
}

#[test]
fn limits_symbol_value() {
    let mut object =
        write::Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let symbol = object.add_symbol(write::Symbol {
        name: b"value".to_vec(),
        value: u64::from(u32::MAX),
        // This field is not encoded for an ordinary COFF symbol.
        size: u64::MAX,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: write::SymbolSection::Absolute,
        flags: SymbolFlags::None,
    });
    let bytes = object.write().unwrap();
    let file = read::coff::CoffFile::<_>::parse(&*bytes).unwrap();
    assert_eq!(
        file.symbols().next().unwrap().coff_symbol().value(),
        u32::MAX
    );

    object.symbol_mut(symbol).value += 1;
    assert!(object.write().is_err());
}

#[test]
fn limits_common_size() {
    let mut object =
        write::Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let symbol = object.add_symbol(write::Symbol {
        name: b"common".to_vec(),
        // A common symbol encodes its size instead of this field.
        value: u64::MAX,
        size: u64::from(u32::MAX),
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: write::SymbolSection::Common,
        flags: SymbolFlags::None,
    });
    let bytes = object.write().unwrap();
    let file = read::File::parse(&*bytes).unwrap();
    let common = file.symbols().next().unwrap();
    assert!(common.is_common());
    assert_eq!(common.size(), u64::from(u32::MAX));

    object.symbol_mut(symbol).size += 1;
    assert!(object.write().is_err());
}

#[test]
fn limits_weak_symbol_value() {
    let mut object =
        write::Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let symbol = object.add_symbol(write::Symbol {
        name: b"value".to_vec(),
        value: u64::from(u32::MAX),
        size: u64::MAX,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: true,
        section: write::SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });
    let bytes = object.write().unwrap();
    let file = read::coff::CoffFile::<_>::parse(&*bytes).unwrap();
    let mut symbols = file.symbols();
    let default = symbols.next().unwrap();
    assert_eq!(default.name(), Ok(".weak.value"));
    assert_eq!(default.coff_symbol().value(), u32::MAX);
    let weak = symbols.next().unwrap();
    assert!(weak.is_weak());
    assert_eq!(weak.coff_symbol().value(), 0);

    object.symbol_mut(symbol).value += 1;
    assert!(object.write().is_err());
}

#[test]
fn limits_file_name() {
    let max = usize::from(u8::MAX) * object::pe::IMAGE_SIZEOF_SYMBOL;
    for len in [
        1,
        object::pe::IMAGE_SIZEOF_SYMBOL,
        object::pe::IMAGE_SIZEOF_SYMBOL + 1,
        max,
    ] {
        let mut object =
            write::Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
        let name = vec![b'a'; len];
        object.add_file_symbol(name.clone());
        let bytes = object.write().unwrap();
        let file = read::File::parse(&*bytes).unwrap();
        assert_eq!(file.symbols().next().unwrap().name_bytes(), Ok(&*name));
    }

    for len in [max + 1, max + object::pe::IMAGE_SIZEOF_SYMBOL] {
        let mut object =
            write::Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
        object.add_file_symbol(vec![b'a'; len]);
        assert!(object.write().is_err());
    }
}

#[test]
fn reloc_overflow() {
    let mut object =
        write::Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let text = object.section_id(write::StandardSection::Text);
    object.append_section_data(text, &[0; 4], 4);
    let symbol = object.add_symbol(write::Symbol {
        name: b"f".to_vec(),
        value: 0,
        size: 4,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: write::SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    for i in 0..0x10000 {
        object
            .add_relocation(
                text,
                write::Relocation {
                    offset: i,
                    symbol,
                    addend: 0,
                    flags: RelocationFlags::Generic {
                        kind: RelocationKind::Absolute,
                        encoding: RelocationEncoding::Generic,
                        size: 64,
                    },
                },
            )
            .unwrap();
    }
    let bytes = object.write().unwrap();

    //std::fs::write(&"reloc_overflow.o", &bytes).unwrap();

    let object = read::File::parse(&*bytes).unwrap();
    assert_eq!(object.format(), BinaryFormat::Coff);
    assert_eq!(object.architecture(), Architecture::X86_64);

    let section = object.sections().next().unwrap();
    assert_eq!(section.name(), Ok(".text"));

    let mut i = 0;
    for (offset, _relocation) in section.relocations() {
        assert_eq!(offset, i);
        i += 1;
    }
    assert_eq!(i, 0x10000);
}
