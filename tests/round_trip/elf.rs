use object::read::Object;
use object::{read, write};
use object::{
    Architecture, BinaryFormat, Endianness, SectionIndex, SymbolFlags, SymbolKind, SymbolScope,
    SymbolSection,
};

#[test]
fn symtab_shndx() {
    let mut object =
        write::Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);

    for i in 0..0x10000 {
        let name = format!("func{}", i).into_bytes();
        let (section, offset) =
            object.add_subsection(write::StandardSection::Text, &name, &[0xcc], 1);
        object.add_symbol(write::Symbol {
            name,
            value: offset,
            size: 1,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: write::SymbolSection::Section(section),
            flags: SymbolFlags::None,
        });
    }
    let bytes = object.write().unwrap();

    //std::fs::write(&"symtab_shndx.o", &bytes).unwrap();

    let object = read::File::parse(&bytes).unwrap();
    assert_eq!(object.format(), BinaryFormat::Elf);
    assert_eq!(object.architecture(), Architecture::X86_64);

    for (index, symbol) in object.symbols().skip(1) {
        assert_eq!(
            symbol.section(),
            SymbolSection::Section(SectionIndex(index.0))
        );
    }
}

#[cfg(feature = "compression")]
#[test]
fn compression_zlib() {
    use object::read::ObjectSection;
    use object::LittleEndian as LE;
    use std::io::Write;

    let data = b"test data data data";
    let len = data.len() as u64;

    let mut ch = object::elf::CompressionHeader64::<LE>::default();
    ch.ch_type.set(LE, object::elf::ELFCOMPRESS_ZLIB);
    ch.ch_size.set(LE, len);
    ch.ch_addralign.set(LE, 1);

    let mut buf = Vec::new();
    buf.write(object::bytes_of(&ch)).unwrap();
    let mut encoder = flate2::write::ZlibEncoder::new(buf, flate2::Compression::default());
    encoder.write_all(data).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut object =
        write::Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let section = object.add_section(
        Vec::new(),
        b".debug_info".to_vec(),
        object::SectionKind::Other,
    );
    object.section_mut(section).set_data(compressed, 1);
    object.section_mut(section).flags = object::SectionFlags::Elf {
        sh_flags: object::elf::SHF_COMPRESSED.into(),
    };
    let bytes = object.write().unwrap();

    //std::fs::write(&"compression.o", &bytes).unwrap();

    let object = read::File::parse(&bytes).unwrap();
    assert_eq!(object.format(), BinaryFormat::Elf);
    assert_eq!(object.architecture(), Architecture::X86_64);

    let section = object.section_by_name(".debug_info").unwrap();
    let uncompressed = section.uncompressed_data().unwrap();
    assert_eq!(data, &*uncompressed);
}

#[cfg(feature = "compression")]
#[test]
fn compression_gnu() {
    use object::read::ObjectSection;
    use std::io::Write;

    let data = b"test data data data";
    let len = data.len() as u32;

    let mut buf = Vec::new();
    buf.write_all(b"ZLIB\0\0\0\0").unwrap();
    buf.write_all(&len.to_be_bytes()).unwrap();
    let mut encoder = flate2::write::ZlibEncoder::new(buf, flate2::Compression::default());
    encoder.write_all(data).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut object =
        write::Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let section = object.add_section(
        Vec::new(),
        b".zdebug_info".to_vec(),
        object::SectionKind::Other,
    );
    object.section_mut(section).set_data(compressed, 1);
    let bytes = object.write().unwrap();

    //std::fs::write(&"compression.o", &bytes).unwrap();

    let object = read::File::parse(&bytes).unwrap();
    assert_eq!(object.format(), BinaryFormat::Elf);
    assert_eq!(object.architecture(), Architecture::X86_64);

    let section = object.section_by_name(".zdebug_info").unwrap();
    let uncompressed = section.uncompressed_data().unwrap();
    assert_eq!(data, &*uncompressed);
}
