use crate::alloc::borrow::Cow;
use crate::alloc::fmt;
use crate::alloc::vec::Vec;
use std::iter;
use std::slice;

#[cfg(feature = "compression")]
use flate2::{Decompress, FlushDecompress};

#[cfg(feature = "compression")]
use goblin::container;
use goblin::{elf, strtab};
#[cfg(feature = "compression")]
use scroll::ctx::TryFromCtx;
use scroll::{self, Pread};

use crate::{
    Machine, Object, ObjectSection, ObjectSegment, Relocation, RelocationKind, SectionKind, Symbol,
    SymbolKind, SymbolMap,
};

/// An ELF object file.
#[derive(Debug)]
pub struct ElfFile<'data> {
    elf: elf::Elf<'data>,
    data: &'data [u8],
}

/// An iterator over the segments of an `ElfFile`.
#[derive(Debug)]
pub struct ElfSegmentIterator<'data, 'file>
where
    'data: 'file,
{
    file: &'file ElfFile<'data>,
    iter: slice::Iter<'file, elf::ProgramHeader>,
}

/// A segment of an `ElfFile`.
#[derive(Debug)]
pub struct ElfSegment<'data, 'file>
where
    'data: 'file,
{
    file: &'file ElfFile<'data>,
    segment: &'file elf::ProgramHeader,
}

/// An iterator over the sections of an `ElfFile`.
#[derive(Debug)]
pub struct ElfSectionIterator<'data, 'file>
where
    'data: 'file,
{
    file: &'file ElfFile<'data>,
    iter: iter::Enumerate<slice::Iter<'file, elf::SectionHeader>>,
}

/// A section of an `ElfFile`.
#[derive(Debug)]
pub struct ElfSection<'data, 'file>
where
    'data: 'file,
{
    file: &'file ElfFile<'data>,
    index: usize,
    section: &'file elf::SectionHeader,
}

/// An iterator over the symbols of an `ElfFile`.
pub struct ElfSymbolIterator<'data, 'file>
where
    'data: 'file,
{
    strtab: &'file strtab::Strtab<'data>,
    symbols: elf::sym::SymIterator<'data>,
    section_kinds: Vec<SectionKind>,
}

/// An iterator over the relocations in an `ElfSection`.
pub struct ElfRelocationIterator<'data, 'file>
where
    'data: 'file,
{
    /// The index of the section that the relocations apply to.
    section_index: u32,
    file: &'file ElfFile<'data>,
    sections: slice::Iter<'file, (elf::ShdrIdx, elf::RelocSection<'data>)>,
    relocations: Option<elf::reloc::RelocIterator<'data>>,
}

impl<'data> ElfFile<'data> {
    /// Get the ELF headers of the file.
    // TODO: this is temporary to allow access to features this crate doesn't provide yet
    #[inline]
    pub fn elf(&self) -> &elf::Elf<'data> {
        &self.elf
    }

    /// Parse the raw ELF file data.
    pub fn parse(data: &'data [u8]) -> Result<Self, &'static str> {
        let elf = elf::Elf::parse(data).map_err(|_| "Could not parse ELF header")?;
        Ok(ElfFile { elf, data })
    }

    fn raw_section_by_name<'file>(
        &'file self,
        section_name: &str,
    ) -> Option<ElfSection<'data, 'file>> {
        for (index, section) in self.elf.section_headers.iter().enumerate() {
            if let Some(Ok(name)) = self.elf.shdr_strtab.get(section.sh_name) {
                if name == section_name {
                    return Some(ElfSection {
                        file: self,
                        index,
                        section,
                    });
                }
            }
        }
        None
    }

    #[cfg(feature = "compression")]
    fn zdebug_section_by_name<'file>(
        &'file self,
        section_name: &str,
    ) -> Option<ElfSection<'data, 'file>> {
        if !section_name.starts_with(".debug_") {
            return None;
        }
        self.raw_section_by_name(&format!(".zdebug_{}", &section_name[7..]))
    }

    #[cfg(not(feature = "compression"))]
    fn zdebug_section_by_name<'file>(
        &'file self,
        _section_name: &str,
    ) -> Option<ElfSection<'data, 'file>> {
        None
    }
}

impl<'data, 'file> Object<'data, 'file> for ElfFile<'data>
where
    'data: 'file,
{
    type Segment = ElfSegment<'data, 'file>;
    type SegmentIterator = ElfSegmentIterator<'data, 'file>;
    type Section = ElfSection<'data, 'file>;
    type SectionIterator = ElfSectionIterator<'data, 'file>;
    type SymbolIterator = ElfSymbolIterator<'data, 'file>;

    fn machine(&self) -> Machine {
        match self.elf.header.e_machine {
            elf::header::EM_ARM => Machine::Arm,
            elf::header::EM_AARCH64 => Machine::Arm64,
            elf::header::EM_386 => Machine::X86,
            elf::header::EM_X86_64 => Machine::X86_64,
            _ => Machine::Other,
        }
    }

    fn segments(&'file self) -> ElfSegmentIterator<'data, 'file> {
        ElfSegmentIterator {
            file: self,
            iter: self.elf.program_headers.iter(),
        }
    }

    fn section_by_name(&'file self, section_name: &str) -> Option<ElfSection<'data, 'file>> {
        self.raw_section_by_name(section_name)
            .or_else(|| self.zdebug_section_by_name(section_name))
    }

    fn sections(&'file self) -> ElfSectionIterator<'data, 'file> {
        ElfSectionIterator {
            file: self,
            iter: self.elf.section_headers.iter().enumerate(),
        }
    }

    fn symbol_by_index(&self, index: u64) -> Option<Symbol<'data>> {
        // TODO: determine section_kind too
        self.elf
            .syms
            .get(index as usize)
            .map(|symbol| parse_symbol(&symbol, &self.elf.strtab, &[]))
    }

    fn symbols(&'file self) -> ElfSymbolIterator<'data, 'file> {
        ElfSymbolIterator {
            strtab: &self.elf.strtab,
            symbols: self.elf.syms.iter(),
            section_kinds: self.sections().map(|x| x.kind()).collect(),
        }
    }

    fn dynamic_symbols(&'file self) -> ElfSymbolIterator<'data, 'file> {
        ElfSymbolIterator {
            strtab: &self.elf.dynstrtab,
            symbols: self.elf.dynsyms.iter(),
            section_kinds: self.sections().map(|x| x.kind()).collect(),
        }
    }

    fn symbol_map(&self) -> SymbolMap<'data> {
        let mut symbols: Vec<_> = self.symbols().filter(SymbolMap::filter).collect();
        symbols.sort_by_key(|x| x.address);
        SymbolMap { symbols }
    }

    #[inline]
    fn is_little_endian(&self) -> bool {
        self.elf.little_endian
    }

    fn has_debug_symbols(&self) -> bool {
        for header in &self.elf.section_headers {
            if let Some(Ok(name)) = self.elf.shdr_strtab.get(header.sh_name) {
                if name == ".debug_info" || name == ".zdebug_info" {
                    return true;
                }
            }
        }
        false
    }

    fn build_id(&self) -> Option<&'data [u8]> {
        if let Some(mut notes) = self.elf.iter_note_headers(self.data) {
            while let Some(Ok(note)) = notes.next() {
                if note.n_type == elf::note::NT_GNU_BUILD_ID {
                    return Some(note.desc);
                }
            }
        }
        if let Some(mut notes) = self
            .elf
            .iter_note_sections(self.data, Some(".note.gnu.build-id"))
        {
            while let Some(Ok(note)) = notes.next() {
                if note.n_type == elf::note::NT_GNU_BUILD_ID {
                    return Some(note.desc);
                }
            }
        }
        None
    }

    fn gnu_debuglink(&self) -> Option<(&'data [u8], u32)> {
        if let Some(Cow::Borrowed(data)) = self.section_data_by_name(".gnu_debuglink") {
            if let Some(filename_len) = data.iter().position(|x| *x == 0) {
                let filename = &data[..filename_len];
                // Round to 4 byte alignment after null terminator.
                let offset = (filename_len + 1 + 3) & !3;
                if offset + 4 <= data.len() {
                    let endian = if self.is_little_endian() {
                        scroll::LE
                    } else {
                        scroll::BE
                    };
                    let crc: u32 = data.pread_with(offset, endian).unwrap();
                    return Some((filename, crc));
                }
            }
        }
        None
    }

    fn entry(&self) -> u64 {
        self.elf.entry
    }
}

impl<'data, 'file> Iterator for ElfSegmentIterator<'data, 'file> {
    type Item = ElfSegment<'data, 'file>;

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

impl<'data, 'file> ObjectSegment<'data> for ElfSegment<'data, 'file> {
    #[inline]
    fn address(&self) -> u64 {
        self.segment.p_vaddr
    }

    #[inline]
    fn size(&self) -> u64 {
        self.segment.p_memsz
    }

    fn data(&self) -> &'data [u8] {
        &self.file.data[self.segment.p_offset as usize..][..self.segment.p_filesz as usize]
    }

    #[inline]
    fn name(&self) -> Option<&str> {
        None
    }
}

impl<'data, 'file> Iterator for ElfSectionIterator<'data, 'file> {
    type Item = ElfSection<'data, 'file>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|(index, section)| ElfSection {
            index,
            file: self.file,
            section,
        })
    }
}

impl<'data, 'file> ElfSection<'data, 'file> {
    fn raw_data(&self) -> &'data [u8] {
        if self.section.sh_type == elf::section_header::SHT_NOBITS {
            &[]
        } else {
            &self.file.data[self.section.sh_offset as usize..][..self.section.sh_size as usize]
        }
    }

    #[cfg(feature = "compression")]
    fn maybe_decompress_data(&self) -> Option<Cow<'data, [u8]>> {
        if (self.section.sh_flags & u64::from(elf::section_header::SHF_COMPRESSED)) == 0 {
            return None;
        }

        let container = match self.file.elf.header.container() {
            Ok(c) => c,
            Err(_) => return None,
        };
        let endianness = match self.file.elf.header.endianness() {
            Ok(e) => e,
            Err(_) => return None,
        };
        let ctx = container::Ctx::new(container, endianness);
        let data = self.raw_data();
        let (compression_type, uncompressed_size, compressed_data) =
            match elf::compression_header::CompressionHeader::try_from_ctx(&data, ctx) {
                Ok((chdr, size)) => (chdr.ch_type, chdr.ch_size, &data[size..]),
                Err(_) => return None,
            };
        if compression_type != elf::compression_header::ELFCOMPRESS_ZLIB {
            return None;
        }

        let mut decompressed = Vec::with_capacity(uncompressed_size as usize);
        let mut decompress = Decompress::new(true);
        if decompress
            .decompress_vec(compressed_data, &mut decompressed, FlushDecompress::Finish)
            .is_err()
        {
            return None;
        }
        Some(Cow::Owned(decompressed))
    }

    /// Try GNU-style "ZLIB" header decompression.
    #[cfg(feature = "compression")]
    fn maybe_decompress_data_gnu(&self) -> Option<Cow<'data, [u8]>> {
        let name = match self.name() {
            Some(name) => name,
            None => return None,
        };
        if !name.starts_with(".zdebug_") {
            return None;
        }
        let data = self.raw_data();
        // Assume ZLIB-style uncompressed data is no more than 4GB to avoid accidentally
        // huge allocations. This also reduces the chance of accidentally matching on a
        // .debug_str that happens to start with "ZLIB".
        if data.len() < 12 || &data[..8] != b"ZLIB\0\0\0\0" {
            return None;
        }
        let uncompressed_size: u32 = data.pread_with(8, scroll::BE).unwrap();
        let mut decompressed = Vec::with_capacity(uncompressed_size as usize);
        let mut decompress = Decompress::new(true);
        if decompress
            .decompress_vec(&data[12..], &mut decompressed, FlushDecompress::Finish)
            .is_err()
        {
            return None;
        }
        Some(Cow::Owned(decompressed))
    }
}

impl<'data, 'file> ObjectSection<'data> for ElfSection<'data, 'file> {
    type RelocationIterator = ElfRelocationIterator<'data, 'file>;

    #[inline]
    fn address(&self) -> u64 {
        self.section.sh_addr
    }

    #[inline]
    fn size(&self) -> u64 {
        self.section.sh_size
    }

    #[inline]
    fn data(&self) -> Cow<'data, [u8]> {
        Cow::from(self.raw_data())
    }

    #[cfg(feature = "compression")]
    fn uncompressed_data(&self) -> Cow<'data, [u8]> {
        self.maybe_decompress_data()
            .or_else(|| self.maybe_decompress_data_gnu())
            .unwrap_or_else(|| self.data())
    }

    #[cfg(not(feature = "compression"))]
    #[inline]
    fn uncompressed_data(&self) -> Cow<'data, [u8]> {
        self.data()
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

    fn kind(&self) -> SectionKind {
        match self.section.sh_type {
            elf::section_header::SHT_PROGBITS => {
                if self.section.sh_flags & u64::from(elf::section_header::SHF_ALLOC) == 0 {
                    SectionKind::Unknown
                } else if self.section.sh_flags & u64::from(elf::section_header::SHF_EXECINSTR) != 0
                {
                    SectionKind::Text
                } else if self.section.sh_flags & u64::from(elf::section_header::SHF_WRITE) != 0 {
                    SectionKind::Data
                } else {
                    SectionKind::ReadOnlyData
                }
            }
            elf::section_header::SHT_NOBITS => SectionKind::UninitializedData,
            _ => SectionKind::Unknown,
        }
    }

    fn relocations(&self) -> ElfRelocationIterator<'data, 'file> {
        ElfRelocationIterator {
            section_index: self.index as u32,
            file: self.file,
            sections: self.file.elf.shdr_relocs.iter(),
            relocations: None,
        }
    }
}

impl<'data, 'file> fmt::Debug for ElfSymbolIterator<'data, 'file> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ElfSymbolIterator").finish()
    }
}

impl<'data, 'file> Iterator for ElfSymbolIterator<'data, 'file> {
    type Item = Symbol<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        self.symbols
            .next()
            .map(|symbol| parse_symbol(&symbol, self.strtab, &self.section_kinds))
    }
}

fn parse_symbol<'data>(
    symbol: &elf::sym::Sym,
    strtab: &strtab::Strtab<'data>,
    section_kinds: &[SectionKind],
) -> Symbol<'data> {
    let name = strtab.get(symbol.st_name).and_then(Result::ok);
    let kind = match elf::sym::st_type(symbol.st_info) {
        elf::sym::STT_OBJECT => SymbolKind::Data,
        elf::sym::STT_FUNC => SymbolKind::Text,
        elf::sym::STT_SECTION => SymbolKind::Section,
        elf::sym::STT_FILE => SymbolKind::File,
        elf::sym::STT_COMMON => SymbolKind::Common,
        elf::sym::STT_TLS => SymbolKind::Tls,
        _ => SymbolKind::Unknown,
    };
    let section_kind = if symbol.st_shndx == elf::section_header::SHN_UNDEF as usize {
        None
    } else {
        Some(
            section_kinds
                .get(symbol.st_shndx)
                .cloned()
                .unwrap_or(SectionKind::Unknown),
        )
    };
    Symbol {
        name,
        address: symbol.st_value,
        size: symbol.st_size,
        kind,
        section_kind,
        global: elf::sym::st_bind(symbol.st_info) != elf::sym::STB_LOCAL,
    }
}

impl<'data, 'file> Iterator for ElfRelocationIterator<'data, 'file> {
    type Item = (u64, Relocation);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ref mut relocations) = self.relocations {
                if let Some(reloc) = relocations.next() {
                    let kind = match self.file.elf.header.e_machine {
                        elf::header::EM_ARM => match reloc.r_type {
                            elf::reloc::R_ARM_ABS32 => RelocationKind::Direct32,
                            _ => RelocationKind::Other(reloc.r_type),
                        },
                        elf::header::EM_AARCH64 => match reloc.r_type {
                            elf::reloc::R_AARCH64_ABS64 => RelocationKind::Direct64,
                            elf::reloc::R_AARCH64_ABS32 => RelocationKind::Direct32,
                            _ => RelocationKind::Other(reloc.r_type),
                        },
                        elf::header::EM_386 => match reloc.r_type {
                            elf::reloc::R_386_32 => RelocationKind::Direct32,
                            _ => RelocationKind::Other(reloc.r_type),
                        },
                        elf::header::EM_X86_64 => match reloc.r_type {
                            elf::reloc::R_X86_64_64 => RelocationKind::Direct64,
                            elf::reloc::R_X86_64_32 => RelocationKind::Direct32,
                            elf::reloc::R_X86_64_32S => RelocationKind::DirectSigned32,
                            _ => RelocationKind::Other(reloc.r_type),
                        },
                        _ => RelocationKind::Other(reloc.r_type),
                    };
                    return Some((
                        reloc.r_offset,
                        Relocation {
                            kind,
                            symbol: reloc.r_sym as u64,
                            addend: reloc.r_addend.unwrap_or(0),
                            implicit_addend: reloc.r_addend.is_none(),
                        },
                    ));
                }
            }
            match self.sections.next() {
                None => return None,
                Some((index, relocs)) => {
                    let section = &self.file.elf.section_headers[*index];
                    if section.sh_info == self.section_index {
                        self.relocations = Some(relocs.into_iter());
                    }
                    // TODO: do we need to return section.sh_link?
                }
            }
        }
    }
}

impl<'data, 'file> fmt::Debug for ElfRelocationIterator<'data, 'file> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ElfRelocationIterator").finish()
    }
}
