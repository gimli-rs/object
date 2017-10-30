use goblin::elf;

use {SectionKind, Symbol, SymbolKind};

pub(crate) fn get_section<'a>(
    elf: &elf::Elf<'a>,
    section_name: &str,
    data: &'a [u8],
) -> Option<&'a [u8]> {
    for header in &elf.section_headers {
        if let Some(Ok(name)) = elf.shdr_strtab.get(header.sh_name) {
            if name == section_name {
                return Some(&data[header.sh_offset as usize..][..header.sh_size as usize]);
            }
        }
    }
    None
}

pub(crate) fn get_symbols<'a>(elf: &elf::Elf<'a>) -> Vec<Symbol<'a>> {
    // Determine section kinds.
    // The section kinds are inherited by symbols in those sections.
    let mut section_kinds = Vec::new();
    for sh in &elf.section_headers {
        let kind = match sh.sh_type {
            elf::section_header::SHT_PROGBITS => {
                if sh.sh_flags & elf::section_header::SHF_EXECINSTR as u64 != 0 {
                    SectionKind::Text
                } else if sh.sh_flags & elf::section_header::SHF_WRITE as u64 != 0 {
                    SectionKind::Data
                } else {
                    SectionKind::ReadOnlyData
                }
            }
            elf::section_header::SHT_NOBITS => SectionKind::UninitializedData,
            _ => SectionKind::Unknown,
        };
        section_kinds.push(kind);
    }

    let mut symbols = Vec::new();
    // Skip undefined symbol index.
    for sym in elf.syms.iter().skip(1) {
        let kind = match elf::sym::st_type(sym.st_info) {
            elf::sym::STT_OBJECT => SymbolKind::Data,
            elf::sym::STT_FUNC => SymbolKind::Text,
            elf::sym::STT_SECTION => SymbolKind::Section,
            elf::sym::STT_FILE => SymbolKind::File,
            elf::sym::STT_COMMON => SymbolKind::Common,
            elf::sym::STT_TLS => SymbolKind::Tls,
            _ => SymbolKind::Unknown,
        };
        let global = elf::sym::st_bind(sym.st_info) != elf::sym::STB_LOCAL;
        let section_kind = if sym.st_shndx == elf::section_header::SHN_UNDEF as usize
            || sym.st_shndx >= section_kinds.len()
        {
            None
        } else {
            Some(section_kinds[sym.st_shndx])
        };
        let name = match elf.strtab.get(sym.st_name) {
            Some(Ok(name)) => name.as_bytes(),
            _ => continue,
        };
        symbols.push(Symbol {
            kind,
            section: sym.st_shndx,
            section_kind,
            global,
            name,
            address: sym.st_value,
            size: sym.st_size,
        });
    }
    symbols
}
