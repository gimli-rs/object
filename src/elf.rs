use std::slice;

use goblin::elf;

use {SectionKind, Symbol, SymbolKind};

/// An ELF object file.
#[derive(Debug)]
pub struct ElfFile<'a> {
    elf: elf::Elf<'a>,
    data: &'a [u8],
}

/// An iterator of the sections of an `ElfFile`.
#[derive(Debug)]
pub struct ElfSectionIterator<'a> {
    file: &'a ElfFile<'a>,
    iter: slice::Iter<'a, elf::SectionHeader>,
}

/// A section of an `ElfFile`.
#[derive(Debug)]
pub struct ElfSection<'a> {
    file: &'a ElfFile<'a>,
    section: <slice::Iter<'a, elf::SectionHeader> as Iterator>::Item,
}

impl<'a> ElfFile<'a> {
    /// Parse the raw ELF file data.
    pub fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        let elf = elf::Elf::parse(data).map_err(|_| "Could not parse ELF header")?;
        Ok(ElfFile { elf, data })
    }

    /// Get the contents of the section named `section_name`, if such
    /// a section exists.
    pub fn get_section(&self, section_name: &str) -> Option<&'a [u8]> {
        for header in &self.elf.section_headers {
            if let Some(Ok(name)) = self.elf.shdr_strtab.get(header.sh_name) {
                if name == section_name {
                    return Some(&self.data[header.sh_offset as usize..][..header.sh_size as usize]);
                }
            }
        }
        None
    }

    /// Get an Iterator over the sections in the file.
    pub fn get_sections(&self) -> ElfSectionIterator {
        ElfSectionIterator {
            file: self,
            iter: self.elf.section_headers.iter(),
        }
    }

    /// Get a `Vec` of the symbols defined in the file.
    pub fn get_symbols(&self) -> Vec<Symbol<'a>> {
        // Determine section kinds.
        // The section kinds are inherited by symbols in those sections.
        let mut section_kinds = Vec::new();
        for sh in &self.elf.section_headers {
            let kind = match sh.sh_type {
                elf::section_header::SHT_PROGBITS => {
                    if sh.sh_flags & u64::from(elf::section_header::SHF_EXECINSTR) != 0 {
                        SectionKind::Text
                    } else if sh.sh_flags & u64::from(elf::section_header::SHF_WRITE) != 0 {
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
        for sym in self.elf.syms.iter().skip(1) {
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
            let name = match self.elf.strtab.get(sym.st_name) {
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

    /// Return true if the file is little endian, false if it is big endian.
    #[inline]
    pub fn is_little_endian(&self) -> bool {
        self.elf.little_endian
    }
}

impl<'a> Iterator for ElfSectionIterator<'a> {
    type Item = ElfSection<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|section| {
            ElfSection {
                file: self.file,
                section,
            }
        })
    }
}

impl<'a> ElfSection<'a> {
    /// Returns the address of the section.
    #[inline]
    pub fn address(&self) -> u64 {
        self.section.sh_addr
    }

    /// Returns a reference to contents of the section.
    pub fn data(&self) -> &'a [u8] {
        &self.file.data[self.section.sh_offset as usize..][..self.section.sh_size as usize]
    }

    /// Returns the name of the section.
    pub fn name(&self) -> Option<&str> {
        self.file
            .elf
            .shdr_strtab
            .get(self.section.sh_name)
            .and_then(|x| x.ok())
    }
}
