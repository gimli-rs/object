use std::slice;

use goblin::elf;

use {Machine, Object, ObjectSection, ObjectSegment, SectionKind, Symbol, SymbolKind};

/// An ELF object file.
#[derive(Debug)]
pub struct ElfFile<'a> {
    elf: elf::Elf<'a>,
    data: &'a [u8],
}

/// An iterator over the segments of an `ElfFile`.
#[derive(Debug)]
pub struct ElfSegmentIterator<'a> {
    file: &'a ElfFile<'a>,
    iter: slice::Iter<'a, elf::ProgramHeader>,
}

/// A segment of an `ElfFile`.
#[derive(Debug)]
pub struct ElfSegment<'a> {
    file: &'a ElfFile<'a>,
    segment: &'a elf::ProgramHeader,
}

/// An iterator over the sections of an `ElfFile`.
#[derive(Debug)]
pub struct ElfSectionIterator<'a> {
    file: &'a ElfFile<'a>,
    iter: slice::Iter<'a, elf::SectionHeader>,
}

/// A section of an `ElfFile`.
#[derive(Debug)]
pub struct ElfSection<'a> {
    file: &'a ElfFile<'a>,
    section: &'a elf::SectionHeader,
}

impl<'a> ElfFile<'a> {
    /// Get the ELF headers of the file.
    // TODO: this is temporary to allow access to features this crate doesn't provide yet
    #[inline]
    pub fn elf(&self) -> &elf::Elf<'a> {
        &self.elf
    }
}

impl<'a> Object<'a> for ElfFile<'a> {
    type Segment = ElfSegment<'a>;
    type SegmentIterator = ElfSegmentIterator<'a>;
    type Section = ElfSection<'a>;
    type SectionIterator = ElfSectionIterator<'a>;

    fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        let elf = elf::Elf::parse(data).map_err(|_| "Could not parse ELF header")?;
        Ok(ElfFile { elf, data })
    }

    fn machine(&self) -> Machine {
        match self.elf.header.e_machine {
            elf::header::EM_ARM => Machine::Arm,
            elf::header::EM_AARCH64 => Machine::Arm64,
            elf::header::EM_386 => Machine::X86,
            elf::header::EM_X86_64 => Machine::X86_64,
            _ => Machine::Other,
        }
    }

    fn segments(&'a self) -> ElfSegmentIterator<'a> {
        ElfSegmentIterator {
            file: self,
            iter: self.elf.program_headers.iter(),
        }
    }

    fn section_data_by_name(&self, section_name: &str) -> Option<&'a [u8]> {
        for header in &self.elf.section_headers {
            if let Some(Ok(name)) = self.elf.shdr_strtab.get(header.sh_name) {
                if name == section_name {
                    return Some(&self.data[header.sh_offset as usize..][..header.sh_size as usize]);
                }
            }
        }
        None
    }

    fn sections(&'a self) -> ElfSectionIterator<'a> {
        ElfSectionIterator {
            file: self,
            iter: self.elf.section_headers.iter(),
        }
    }

    fn symbols(&self) -> Vec<Symbol<'a>> {
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
            let name = self.elf.strtab.get(sym.st_name).and_then(Result::ok);
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

    #[inline]
    fn is_little_endian(&self) -> bool {
        self.elf.little_endian
    }
}

impl<'a> Iterator for ElfSegmentIterator<'a> {
    type Item = ElfSegment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(segment) = self.iter.next() {
            if segment.p_type == elf::program_header::PT_LOAD {
                return Some(ElfSegment {
                    file: self.file,
                    segment,
                });
            }
        }
        None
    }
}

impl<'a> ObjectSegment<'a> for ElfSegment<'a> {
    #[inline]
    fn address(&self) -> u64 {
        self.segment.p_vaddr
    }

    #[inline]
    fn size(&self) -> u64 {
        self.segment.p_memsz
    }

    fn data(&self) -> &'a [u8] {
        &self.file.data[self.segment.p_offset as usize..][..self.segment.p_filesz as usize]
    }

    #[inline]
    fn name(&self) -> Option<&str> {
        None
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

impl<'a> ObjectSection<'a> for ElfSection<'a> {
    #[inline]
    fn address(&self) -> u64 {
        self.section.sh_addr
    }

    #[inline]
    fn size(&self) -> u64 {
        self.section.sh_size
    }

    fn data(&self) -> &'a [u8] {
        if self.section.sh_type == elf::section_header::SHT_NOBITS {
            &[]
        } else {
            &self.file.data[self.section.sh_offset as usize..][..self.section.sh_size as usize]
        }
    }

    fn name(&self) -> Option<&str> {
        self.file
            .elf
            .shdr_strtab
            .get(self.section.sh_name)
            .and_then(Result::ok)
    }

    #[inline]
    fn segment_name(&self) -> Option<&str> {
        None
    }
}
