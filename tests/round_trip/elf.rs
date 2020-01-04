use object::read::Object;
use object::{read, write};
use object::{SectionIndex, SymbolFlags, SymbolKind, SymbolScope, SymbolSection};
use target_lexicon::{Architecture, BinaryFormat};

#[test]
fn symtab_shndx() {
    let mut object = write::Object::new(BinaryFormat::Elf, Architecture::X86_64);

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
