//! Support for reading ELF files.
//!
//! Defines traits to abstract over the difference between ELF32/ELF64,
//! and implements read functionality in terms of these traits.
//!
//! Also provides `ElfFile` and related types which implement the `Object` trait.

#[cfg(feature = "compression")]
use alloc::borrow::Cow;
use alloc::fmt;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::{iter, mem, slice, str};
#[cfg(feature = "compression")]
use flate2::{Decompress, FlushDecompress};
use target_lexicon::{Aarch64Architecture, Architecture, ArmArchitecture};

use crate::elf;
use crate::endian::{self, Endian, RunTimeEndian, U32};
use crate::pod::{Bytes, Pod};
use crate::read::util::{self, StringTable};
use crate::read::{
    self, Error, FileFlags, Object, ObjectSection, ObjectSegment, ReadError, Relocation,
    RelocationEncoding, RelocationKind, RelocationTarget, SectionFlags, SectionIndex, SectionKind,
    Symbol, SymbolFlags, SymbolIndex, SymbolKind, SymbolMap, SymbolScope, SymbolSection,
};

/// A 32-bit ELF object file.
pub type ElfFile32<'data, Endian = RunTimeEndian> = ElfFile<'data, elf::FileHeader32<Endian>>;
/// A 64-bit ELF object file.
pub type ElfFile64<'data, Endian = RunTimeEndian> = ElfFile<'data, elf::FileHeader64<Endian>>;

/// A partially parsed ELF file.
///
/// Most of the functionality of this type is provided by the `Object` trait implementation.
#[derive(Debug)]
pub struct ElfFile<'data, Elf: FileHeader> {
    endian: Elf::Endian,
    header: &'data Elf,
    segments: &'data [Elf::ProgramHeader],
    sections: &'data [Elf::SectionHeader],
    section_strings: StringTable<'data>,
    relocations: Vec<usize>,
    symbols: SymbolTable<'data, Elf>,
    dynamic_symbols: SymbolTable<'data, Elf>,
    data: Bytes<'data>,
}

impl<'data, Elf: FileHeader> ElfFile<'data, Elf> {
    /// Parse the raw ELF file data.
    pub fn parse(data: &'data [u8]) -> read::Result<Self> {
        let data = Bytes(data);
        let header = data
            .read_at::<Elf>(0)
            .read_error("Invalid ELF header size or alignment")?;
        if !header.is_supported() {
            return Err(Error("Unsupported ELF header"));
        }

        // TODO: Check self.e_ehsize?

        let endian = header.endian()?;
        let segments = header.program_headers(endian, data)?;
        let sections = header.section_headers(endian, data)?;

        let section_string_data = if !sections.is_empty() {
            let index = header.shstrndx(endian, data)?;
            let shstrtab_section = sections
                .get(index as usize)
                .read_error("Invalid ELF section header strtab index")?;
            shstrtab_section
                .data(endian, data)
                .read_error("Invalid ELF section header strtab data")?
        } else {
            Bytes(&[])
        };
        let section_strings = StringTable {
            data: section_string_data,
        };

        let mut symbol_section = None;
        let mut symbols = &[][..];
        let mut symbol_string_data = Bytes(&[]);
        let mut symbol_shndx = &[][..];
        let mut dynamic_symbols = &[][..];
        let mut dynamic_symbol_string_data = Bytes(&[]);
        // TODO: only do this if the user requires it.
        for (index, section) in sections.iter().enumerate() {
            match section.sh_type(endian) {
                elf::SHT_DYNSYM => {
                    if dynamic_symbols.is_empty() {
                        dynamic_symbols = section
                            .data_as_array(endian, data)
                            .read_error("Invalid ELF dynsym data")?;
                        let strtab_section = sections
                            .get(section.sh_link(endian) as usize)
                            .read_error("Invalid ELF dynstr section index")?;
                        dynamic_symbol_string_data = strtab_section
                            .data(endian, data)
                            .read_error("Invalid ELF dynstr data")?;
                    }
                }
                elf::SHT_SYMTAB => {
                    if symbols.is_empty() {
                        symbol_section = Some(index);
                        symbols = section
                            .data_as_array(endian, data)
                            .read_error("Invalid ELF symtab data")?;
                        let strtab_section = sections
                            .get(section.sh_link(endian) as usize)
                            .read_error("Invalid ELF strtab section index")?;
                        symbol_string_data = strtab_section
                            .data(endian, data)
                            .read_error("Invalid ELF strtab data")?;
                    }
                }
                elf::SHT_SYMTAB_SHNDX => {
                    if symbol_shndx.is_empty() {
                        symbol_shndx = section
                            .data_as_array(endian, data)
                            .read_error("Invalid ELF symtab_shndx data")?;
                    }
                }
                _ => {}
            }
        }
        let symbol_strings = StringTable {
            data: symbol_string_data,
        };
        let symbols = SymbolTable {
            symbols,
            strings: symbol_strings,
            shndx: symbol_shndx,
        };
        let dynamic_symbol_strings = StringTable {
            data: dynamic_symbol_string_data,
        };
        let dynamic_symbols = SymbolTable {
            symbols: dynamic_symbols,
            strings: dynamic_symbol_strings,
            shndx: &[],
        };

        // The API we provide requires a mapping from section to relocations, so build it now.
        // TODO: only do this if the user requires it (and then we can return an error
        // for invalid sh_link values).
        let mut relocations = vec![0; sections.len()];
        for (index, section) in sections.iter().enumerate().rev() {
            let sh_type = section.sh_type(endian);
            if sh_type == elf::SHT_REL || sh_type == elf::SHT_RELA {
                let sh_info = section.sh_info(endian) as usize;
                let sh_link = section.sh_link(endian) as usize;
                // Skip dynamic relocations (sh_info = 0), invalid sh_info, and section
                // relocations with the wrong symbol table (sh_link).
                if sh_info != 0 && sh_info < relocations.len() && Some(sh_link) == symbol_section {
                    // Handle multiple relocation sections by chaining them.
                    let next = relocations[sh_info];
                    relocations[sh_info] = index;
                    relocations[index] = next;
                }
            }
        }

        Ok(ElfFile {
            endian,
            header,
            segments,
            sections,
            section_strings,
            relocations,
            symbols,
            dynamic_symbols,
            data,
        })
    }

    fn raw_section_by_name<'file>(
        &'file self,
        section_name: &str,
    ) -> Option<ElfSection<'data, 'file, Elf>> {
        for (index, section) in self.sections.iter().enumerate() {
            if let Ok(name) = self.section_strings.get(section.sh_name(self.endian)) {
                if name == section_name.as_bytes() {
                    return Some(ElfSection {
                        file: self,
                        index: SectionIndex(index),
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
    ) -> Option<ElfSection<'data, 'file, Elf>> {
        if !section_name.starts_with(".debug_") {
            return None;
        }
        self.raw_section_by_name(&format!(".zdebug_{}", &section_name[7..]))
    }

    #[cfg(not(feature = "compression"))]
    fn zdebug_section_by_name<'file>(
        &'file self,
        _section_name: &str,
    ) -> Option<ElfSection<'data, 'file, Elf>> {
        None
    }
}

impl<'data, Elf: FileHeader> read::private::Sealed for ElfFile<'data, Elf> {}

impl<'data, 'file, Elf> Object<'data, 'file> for ElfFile<'data, Elf>
where
    'data: 'file,
    Elf: FileHeader,
{
    type Segment = ElfSegment<'data, 'file, Elf>;
    type SegmentIterator = ElfSegmentIterator<'data, 'file, Elf>;
    type Section = ElfSection<'data, 'file, Elf>;
    type SectionIterator = ElfSectionIterator<'data, 'file, Elf>;
    type SymbolIterator = ElfSymbolIterator<'data, 'file, Elf>;

    fn architecture(&self) -> Architecture {
        match self.header.e_machine(self.endian) {
            elf::EM_ARM => Architecture::Arm(ArmArchitecture::Arm),
            elf::EM_AARCH64 => Architecture::Aarch64(Aarch64Architecture::Aarch64),
            elf::EM_386 => Architecture::I386,
            elf::EM_X86_64 => Architecture::X86_64,
            elf::EM_MIPS => Architecture::Mips,
            _ => Architecture::Unknown,
        }
    }

    #[inline]
    fn is_little_endian(&self) -> bool {
        self.header.is_little_endian()
    }

    #[inline]
    fn is_64(&self) -> bool {
        self.header.is_class_64()
    }

    fn segments(&'file self) -> ElfSegmentIterator<'data, 'file, Elf> {
        ElfSegmentIterator {
            file: self,
            iter: self.segments.iter(),
        }
    }

    fn section_by_name(&'file self, section_name: &str) -> Option<ElfSection<'data, 'file, Elf>> {
        self.raw_section_by_name(section_name)
            .or_else(|| self.zdebug_section_by_name(section_name))
    }

    fn section_by_index(&'file self, index: SectionIndex) -> Option<ElfSection<'data, 'file, Elf>> {
        self.sections.get(index.0).map(|section| ElfSection {
            file: self,
            index,
            section,
        })
    }

    fn sections(&'file self) -> ElfSectionIterator<'data, 'file, Elf> {
        ElfSectionIterator {
            file: self,
            iter: self.sections.iter().enumerate(),
        }
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> Option<Symbol<'data>> {
        let shndx = self.symbols.shndx.get(index.0).cloned();
        self.symbols.symbols.get(index.0).map(|symbol| {
            parse_symbol::<Elf>(self.endian, index.0, symbol, self.symbols.strings, shndx)
        })
    }

    fn symbols(&'file self) -> ElfSymbolIterator<'data, 'file, Elf> {
        ElfSymbolIterator {
            file: self,
            symbols: self.symbols,
            index: 0,
        }
    }

    fn dynamic_symbols(&'file self) -> ElfSymbolIterator<'data, 'file, Elf> {
        ElfSymbolIterator {
            file: self,
            symbols: self.dynamic_symbols,
            index: 0,
        }
    }

    fn symbol_map(&self) -> SymbolMap<'data> {
        let mut symbols: Vec<_> = self
            .symbols()
            .map(|(_, s)| s)
            .filter(SymbolMap::filter)
            .collect();
        symbols.sort_by_key(|x| x.address);
        SymbolMap { symbols }
    }

    fn has_debug_symbols(&self) -> bool {
        for section in self.sections {
            if let Ok(name) = self.section_strings.get(section.sh_name(self.endian)) {
                if name == b".debug_info" || name == b".zdebug_info" {
                    return true;
                }
            }
        }
        false
    }

    fn build_id(&self) -> Option<&'data [u8]> {
        let endian = self.endian;
        // Use section headers if present, otherwise use program headers.
        if !self.sections.is_empty() {
            for section in self.sections {
                if let Ok(mut notes) = section.notes(endian, self.data) {
                    while let Ok(Some(note)) = notes.next() {
                        if note.name() == elf::ELF_NOTE_GNU
                            && note.n_type(endian) == elf::NT_GNU_BUILD_ID
                        {
                            return Some(note.desc);
                        }
                    }
                }
            }
        } else {
            for segment in self.segments {
                if let Ok(mut notes) = segment.notes(endian, self.data) {
                    while let Ok(Some(note)) = notes.next() {
                        if note.name() == elf::ELF_NOTE_GNU
                            && note.n_type(endian) == elf::NT_GNU_BUILD_ID
                        {
                            return Some(note.desc);
                        }
                    }
                }
            }
        }
        None
    }

    fn gnu_debuglink(&self) -> Option<(&'data [u8], u32)> {
        let section = self.raw_section_by_name(".gnu_debuglink")?;
        let data = section.section.data(self.endian, self.data).ok()?;
        let filename = data.read_string_at(0).ok()?;
        let crc_offset = util::align(filename.len() + 1, 4);
        let crc = data.read_at::<U32<_>>(crc_offset).ok()?.get(self.endian);
        Some((filename, crc))
    }

    fn entry(&self) -> u64 {
        self.header.e_entry(self.endian).into()
    }

    fn flags(&self) -> FileFlags {
        FileFlags::Elf {
            e_flags: self.header.e_flags(self.endian),
        }
    }
}

/// An iterator over the segments of an `ElfFile32`.
pub type ElfSegmentIterator32<'data, 'file, Endian = RunTimeEndian> =
    ElfSegmentIterator<'data, 'file, elf::FileHeader32<Endian>>;
/// An iterator over the segments of an `ElfFile64`.
pub type ElfSegmentIterator64<'data, 'file, Endian = RunTimeEndian> =
    ElfSegmentIterator<'data, 'file, elf::FileHeader64<Endian>>;

/// An iterator over the segments of an `ElfFile`.
#[derive(Debug)]
pub struct ElfSegmentIterator<'data, 'file, Elf>
where
    'data: 'file,
    Elf: FileHeader,
{
    file: &'file ElfFile<'data, Elf>,
    iter: slice::Iter<'data, Elf::ProgramHeader>,
}

impl<'data, 'file, Elf: FileHeader> Iterator for ElfSegmentIterator<'data, 'file, Elf> {
    type Item = ElfSegment<'data, 'file, Elf>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(segment) = self.iter.next() {
            if segment.p_type(self.file.endian) == elf::PT_LOAD {
                return Some(ElfSegment {
                    file: self.file,
                    segment,
                });
            }
        }
        None
    }
}

/// A segment of an `ElfFile32`.
pub type ElfSegment32<'data, 'file, Endian = RunTimeEndian> =
    ElfSegment<'data, 'file, elf::FileHeader32<Endian>>;
/// A segment of an `ElfFile64`.
pub type ElfSegment64<'data, 'file, Endian = RunTimeEndian> =
    ElfSegment<'data, 'file, elf::FileHeader64<Endian>>;

/// A segment of an `ElfFile`.
#[derive(Debug)]
pub struct ElfSegment<'data, 'file, Elf>
where
    'data: 'file,
    Elf: FileHeader,
{
    file: &'file ElfFile<'data, Elf>,
    segment: &'data Elf::ProgramHeader,
}

impl<'data, 'file, Elf: FileHeader> ElfSegment<'data, 'file, Elf> {
    fn bytes(&self) -> Bytes<'data> {
        self.segment
            .data(self.file.endian, self.file.data)
            .unwrap_or(Bytes(&[]))
    }
}

impl<'data, 'file, Elf: FileHeader> read::private::Sealed for ElfSegment<'data, 'file, Elf> {}

impl<'data, 'file, Elf: FileHeader> ObjectSegment<'data> for ElfSegment<'data, 'file, Elf> {
    #[inline]
    fn address(&self) -> u64 {
        self.segment.p_vaddr(self.file.endian).into()
    }

    #[inline]
    fn size(&self) -> u64 {
        self.segment.p_memsz(self.file.endian).into()
    }

    #[inline]
    fn align(&self) -> u64 {
        self.segment.p_align(self.file.endian).into()
    }

    #[inline]
    fn file_range(&self) -> (u64, u64) {
        self.segment.file_range(self.file.endian)
    }

    #[inline]
    fn data(&self) -> &'data [u8] {
        self.bytes().0
    }

    fn data_range(&self, address: u64, size: u64) -> Option<&'data [u8]> {
        read::data_range(self.bytes(), self.address(), address, size).ok()
    }

    #[inline]
    fn name(&self) -> Option<&str> {
        None
    }
}

/// An iterator over the sections of an `ElfFile32`.
pub type ElfSectionIterator32<'data, 'file, Endian = RunTimeEndian> =
    ElfSectionIterator<'data, 'file, elf::FileHeader32<Endian>>;
/// An iterator over the sections of an `ElfFile64`.
pub type ElfSectionIterator64<'data, 'file, Endian = RunTimeEndian> =
    ElfSectionIterator<'data, 'file, elf::FileHeader64<Endian>>;

/// An iterator over the sections of an `ElfFile`.
#[derive(Debug)]
pub struct ElfSectionIterator<'data, 'file, Elf>
where
    'data: 'file,
    Elf: FileHeader,
{
    file: &'file ElfFile<'data, Elf>,
    iter: iter::Enumerate<slice::Iter<'data, Elf::SectionHeader>>,
}

impl<'data, 'file, Elf: FileHeader> Iterator for ElfSectionIterator<'data, 'file, Elf> {
    type Item = ElfSection<'data, 'file, Elf>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|(index, section)| ElfSection {
            index: SectionIndex(index),
            file: self.file,
            section,
        })
    }
}

/// A section of an `ElfFile32`.
pub type ElfSection32<'data, 'file, Endian = RunTimeEndian> =
    ElfSection<'data, 'file, elf::FileHeader32<Endian>>;
/// A section of an `ElfFile64`.
pub type ElfSection64<'data, 'file, Endian = RunTimeEndian> =
    ElfSection<'data, 'file, elf::FileHeader64<Endian>>;

/// A section of an `ElfFile`.
#[derive(Debug)]
pub struct ElfSection<'data, 'file, Elf>
where
    'data: 'file,
    Elf: FileHeader,
{
    file: &'file ElfFile<'data, Elf>,
    index: SectionIndex,
    section: &'data Elf::SectionHeader,
}

impl<'data, 'file, Elf: FileHeader> ElfSection<'data, 'file, Elf> {
    fn bytes(&self) -> Bytes<'data> {
        self.section
            .data(self.file.endian, self.file.data)
            .unwrap_or(Bytes(&[]))
    }

    #[cfg(feature = "compression")]
    fn maybe_decompress_data(&self) -> read::Result<Option<Cow<'data, [u8]>>> {
        let endian = self.file.endian;
        if (self.section.sh_flags(endian).into() & u64::from(elf::SHF_COMPRESSED)) == 0 {
            return Ok(None);
        }

        let mut data = self
            .section
            .data(endian, self.file.data)
            .read_error("Invalid ELF compressed section offset or size")?;
        let header = data
            .read::<Elf::CompressionHeader>()
            .read_error("Invalid ELF compression header size or alignment")?;
        if header.ch_type(endian) != elf::ELFCOMPRESS_ZLIB {
            return Err(Error("Unsupported ELF compression type"));
        }

        let uncompressed_size: u64 = header.ch_size(endian).into();
        let mut decompressed = Vec::with_capacity(uncompressed_size as usize);
        let mut decompress = Decompress::new(true);
        if decompress
            .decompress_vec(data.0, &mut decompressed, FlushDecompress::Finish)
            .is_err()
        {
            return Err(Error("Invalid ELF compressed data"));
        }
        Ok(Some(Cow::Owned(decompressed)))
    }

    /// Try GNU-style "ZLIB" header decompression.
    #[cfg(feature = "compression")]
    fn maybe_decompress_data_gnu(&self) -> read::Result<Option<Cow<'data, [u8]>>> {
        let name = match self.name() {
            Some(name) => name,
            None => return Ok(None),
        };
        if !name.starts_with(".zdebug_") {
            return Ok(None);
        }
        let mut data = self.bytes();
        // Assume ZLIB-style uncompressed data is no more than 4GB to avoid accidentally
        // huge allocations. This also reduces the chance of accidentally matching on a
        // .debug_str that happens to start with "ZLIB".
        if data
            .read_bytes(8)
            .read_error("ELF GNU compressed section is too short")?
            .0
            != b"ZLIB\0\0\0\0"
        {
            return Err(Error("Invalid ELF GNU compressed section header"));
        }
        let uncompressed_size = data
            .read::<U32<_>>()
            .read_error("ELF GNU compressed section is too short")?
            .get(endian::BigEndian);
        let mut decompressed = Vec::with_capacity(uncompressed_size as usize);
        let mut decompress = Decompress::new(true);
        if decompress
            .decompress_vec(data.0, &mut decompressed, FlushDecompress::Finish)
            .is_err()
        {
            return Err(Error("Invalid ELF GNU compressed data"));
        }
        Ok(Some(Cow::Owned(decompressed)))
    }
}

impl<'data, 'file, Elf: FileHeader> read::private::Sealed for ElfSection<'data, 'file, Elf> {}

impl<'data, 'file, Elf: FileHeader> ObjectSection<'data> for ElfSection<'data, 'file, Elf> {
    type RelocationIterator = ElfRelocationIterator<'data, 'file, Elf>;

    #[inline]
    fn index(&self) -> SectionIndex {
        self.index
    }

    #[inline]
    fn address(&self) -> u64 {
        self.section.sh_addr(self.file.endian).into()
    }

    #[inline]
    fn size(&self) -> u64 {
        self.section.sh_size(self.file.endian).into()
    }

    #[inline]
    fn align(&self) -> u64 {
        self.section.sh_addralign(self.file.endian).into()
    }

    #[inline]
    fn file_range(&self) -> Option<(u64, u64)> {
        self.section.file_range(self.file.endian)
    }

    #[inline]
    fn data(&self) -> &'data [u8] {
        self.bytes().0
    }

    fn data_range(&self, address: u64, size: u64) -> Option<&'data [u8]> {
        read::data_range(self.bytes(), self.address(), address, size).ok()
    }

    #[cfg(feature = "compression")]
    fn uncompressed_data(&self) -> Option<Cow<'data, [u8]>> {
        Some(if let Some(data) = self.maybe_decompress_data().ok()? {
            data
        } else if let Some(data) = self.maybe_decompress_data_gnu().ok()? {
            data
        } else {
            Cow::from(self.data())
        })
    }

    fn name(&self) -> Option<&str> {
        self.file
            .section_strings
            .get(self.section.sh_name(self.file.endian))
            .ok()
            .and_then(|s| str::from_utf8(s).ok())
    }

    #[inline]
    fn segment_name(&self) -> Option<&str> {
        None
    }

    fn kind(&self) -> SectionKind {
        let flags = self.section.sh_flags(self.file.endian).into();
        match self.section.sh_type(self.file.endian) {
            elf::SHT_PROGBITS => {
                if flags & u64::from(elf::SHF_ALLOC) != 0 {
                    if flags & u64::from(elf::SHF_EXECINSTR) != 0 {
                        SectionKind::Text
                    } else if flags & u64::from(elf::SHF_TLS) != 0 {
                        SectionKind::Tls
                    } else if flags & u64::from(elf::SHF_WRITE) != 0 {
                        SectionKind::Data
                    } else if flags & u64::from(elf::SHF_STRINGS) != 0 {
                        SectionKind::ReadOnlyString
                    } else {
                        SectionKind::ReadOnlyData
                    }
                } else if flags & u64::from(elf::SHF_STRINGS) != 0 {
                    SectionKind::OtherString
                } else {
                    SectionKind::Other
                }
            }
            elf::SHT_NOBITS => {
                if flags & u64::from(elf::SHF_TLS) != 0 {
                    SectionKind::UninitializedTls
                } else {
                    SectionKind::UninitializedData
                }
            }
            elf::SHT_NULL
            | elf::SHT_SYMTAB
            | elf::SHT_STRTAB
            | elf::SHT_RELA
            | elf::SHT_HASH
            | elf::SHT_DYNAMIC
            | elf::SHT_REL
            | elf::SHT_DYNSYM => SectionKind::Metadata,
            _ => {
                // TODO: maybe add more specialised kinds based on sh_type (e.g. Unwind)
                SectionKind::Unknown
            }
        }
    }

    fn relocations(&self) -> ElfRelocationIterator<'data, 'file, Elf> {
        ElfRelocationIterator {
            section_index: self.file.relocations[self.index.0],
            file: self.file,
            relocations: None,
        }
    }

    fn flags(&self) -> SectionFlags {
        SectionFlags::Elf {
            sh_flags: self.section.sh_flags(self.file.endian).into(),
        }
    }
}

/// An iterator over the symbols of an `ElfFile32`.
pub type ElfSymbolIterator32<'data, 'file, Endian = RunTimeEndian> =
    ElfSymbolIterator<'data, 'file, elf::FileHeader32<Endian>>;
/// An iterator over the symbols of an `ElfFile64`.
pub type ElfSymbolIterator64<'data, 'file, Endian = RunTimeEndian> =
    ElfSymbolIterator<'data, 'file, elf::FileHeader64<Endian>>;

/// An iterator over the symbols of an `ElfFile`.
pub struct ElfSymbolIterator<'data, 'file, Elf>
where
    'data: 'file,
    Elf: FileHeader,
{
    file: &'file ElfFile<'data, Elf>,
    symbols: SymbolTable<'data, Elf>,
    index: usize,
}

impl<'data, 'file, Elf: FileHeader> fmt::Debug for ElfSymbolIterator<'data, 'file, Elf> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ElfSymbolIterator").finish()
    }
}

impl<'data, 'file, Elf: FileHeader> Iterator for ElfSymbolIterator<'data, 'file, Elf> {
    type Item = (SymbolIndex, Symbol<'data>);

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.index;
        let shndx = self.symbols.shndx.get(index).cloned();
        self.symbols.symbols.get(index).map(|symbol| {
            self.index += 1;
            (
                SymbolIndex(index),
                parse_symbol::<Elf>(self.file.endian, index, symbol, self.symbols.strings, shndx),
            )
        })
    }
}

fn parse_symbol<'data, Elf: FileHeader>(
    endian: Elf::Endian,
    index: usize,
    symbol: &Elf::Sym,
    strings: StringTable<'data>,
    shndx: Option<u32>,
) -> Symbol<'data> {
    let name = strings
        .get(symbol.st_name(endian))
        .ok()
        .and_then(|s| str::from_utf8(s).ok());
    let kind = match symbol.st_type() {
        elf::STT_NOTYPE if index == 0 => SymbolKind::Null,
        elf::STT_OBJECT | elf::STT_COMMON => SymbolKind::Data,
        elf::STT_FUNC => SymbolKind::Text,
        elf::STT_SECTION => SymbolKind::Section,
        elf::STT_FILE => SymbolKind::File,
        elf::STT_TLS => SymbolKind::Tls,
        _ => SymbolKind::Unknown,
    };
    let section = match symbol.st_shndx(endian) {
        elf::SHN_UNDEF => SymbolSection::Undefined,
        elf::SHN_ABS => {
            if kind == SymbolKind::File {
                SymbolSection::None
            } else {
                SymbolSection::Absolute
            }
        }
        elf::SHN_COMMON => SymbolSection::Common,
        elf::SHN_XINDEX => match shndx {
            Some(index) => SymbolSection::Section(SectionIndex(index as usize)),
            None => SymbolSection::Unknown,
        },
        index if index < elf::SHN_LORESERVE => SymbolSection::Section(SectionIndex(index as usize)),
        _ => SymbolSection::Unknown,
    };
    let weak = symbol.st_bind() == elf::STB_WEAK;
    let scope = match symbol.st_bind() {
        _ if section == SymbolSection::Undefined => SymbolScope::Unknown,
        elf::STB_LOCAL => SymbolScope::Compilation,
        elf::STB_GLOBAL | elf::STB_WEAK => {
            if symbol.st_visibility() == elf::STV_HIDDEN {
                SymbolScope::Linkage
            } else {
                SymbolScope::Dynamic
            }
        }
        _ => SymbolScope::Unknown,
    };
    let flags = SymbolFlags::Elf {
        st_info: symbol.st_info(),
        st_other: symbol.st_other(),
    };
    Symbol {
        name,
        address: symbol.st_value(endian).into(),
        size: symbol.st_size(endian).into(),
        kind,
        section,
        weak,
        scope,
        flags,
    }
}

enum ElfRelaIterator<'data, Elf: FileHeader> {
    Rel(slice::Iter<'data, Elf::Rel>),
    Rela(slice::Iter<'data, Elf::Rela>),
}

impl<'data, Elf: FileHeader> ElfRelaIterator<'data, Elf> {
    fn is_rel(&self) -> bool {
        match self {
            ElfRelaIterator::Rel(_) => true,
            ElfRelaIterator::Rela(_) => false,
        }
    }
}

impl<'data, Elf: FileHeader> Iterator for ElfRelaIterator<'data, Elf> {
    type Item = Elf::Rela;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ElfRelaIterator::Rel(ref mut i) => i.next().cloned().map(Self::Item::from),
            ElfRelaIterator::Rela(ref mut i) => i.next().cloned(),
        }
    }
}

/// An iterator over the relocations for an `ElfSection32`.
pub type ElfRelocationIterator32<'data, 'file, Endian = RunTimeEndian> =
    ElfRelocationIterator<'data, 'file, elf::FileHeader32<Endian>>;
/// An iterator over the relocations for an `ElfSection64`.
pub type ElfRelocationIterator64<'data, 'file, Endian = RunTimeEndian> =
    ElfRelocationIterator<'data, 'file, elf::FileHeader64<Endian>>;

/// An iterator over the relocations for an `ElfSection`.
pub struct ElfRelocationIterator<'data, 'file, Elf>
where
    'data: 'file,
    Elf: FileHeader,
{
    /// The current pointer in the chain of relocation sections.
    section_index: usize,
    file: &'file ElfFile<'data, Elf>,
    relocations: Option<ElfRelaIterator<'data, Elf>>,
}

impl<'data, 'file, Elf: FileHeader> Iterator for ElfRelocationIterator<'data, 'file, Elf> {
    type Item = (u64, Relocation);

    fn next(&mut self) -> Option<Self::Item> {
        let endian = self.file.endian;
        loop {
            if let Some(ref mut relocations) = self.relocations {
                if let Some(reloc) = relocations.next() {
                    let mut encoding = RelocationEncoding::Generic;
                    let (kind, size) = match self.file.header.e_machine(endian) {
                        elf::EM_ARM => match reloc.r_type(endian) {
                            elf::R_ARM_ABS32 => (RelocationKind::Absolute, 32),
                            r_type => (RelocationKind::Elf(r_type), 0),
                        },
                        elf::EM_AARCH64 => match reloc.r_type(endian) {
                            elf::R_AARCH64_ABS64 => (RelocationKind::Absolute, 64),
                            elf::R_AARCH64_ABS32 => (RelocationKind::Absolute, 32),
                            elf::R_AARCH64_ABS16 => (RelocationKind::Absolute, 16),
                            elf::R_AARCH64_PREL64 => (RelocationKind::Relative, 64),
                            elf::R_AARCH64_PREL32 => (RelocationKind::Relative, 32),
                            elf::R_AARCH64_PREL16 => (RelocationKind::Relative, 16),
                            r_type => (RelocationKind::Elf(r_type), 0),
                        },
                        elf::EM_386 => match reloc.r_type(endian) {
                            elf::R_386_32 => (RelocationKind::Absolute, 32),
                            elf::R_386_PC32 => (RelocationKind::Relative, 32),
                            elf::R_386_GOT32 => (RelocationKind::Got, 32),
                            elf::R_386_PLT32 => (RelocationKind::PltRelative, 32),
                            elf::R_386_GOTOFF => (RelocationKind::GotBaseOffset, 32),
                            elf::R_386_GOTPC => (RelocationKind::GotBaseRelative, 32),
                            elf::R_386_16 => (RelocationKind::Absolute, 16),
                            elf::R_386_PC16 => (RelocationKind::Relative, 16),
                            elf::R_386_8 => (RelocationKind::Absolute, 8),
                            elf::R_386_PC8 => (RelocationKind::Relative, 8),
                            r_type => (RelocationKind::Elf(r_type), 0),
                        },
                        elf::EM_X86_64 => match reloc.r_type(endian) {
                            elf::R_X86_64_64 => (RelocationKind::Absolute, 64),
                            elf::R_X86_64_PC32 => (RelocationKind::Relative, 32),
                            elf::R_X86_64_GOT32 => (RelocationKind::Got, 32),
                            elf::R_X86_64_PLT32 => (RelocationKind::PltRelative, 32),
                            elf::R_X86_64_GOTPCREL => (RelocationKind::GotRelative, 32),
                            elf::R_X86_64_32 => (RelocationKind::Absolute, 32),
                            elf::R_X86_64_32S => {
                                encoding = RelocationEncoding::X86Signed;
                                (RelocationKind::Absolute, 32)
                            }
                            elf::R_X86_64_16 => (RelocationKind::Absolute, 16),
                            elf::R_X86_64_PC16 => (RelocationKind::Relative, 16),
                            elf::R_X86_64_8 => (RelocationKind::Absolute, 8),
                            elf::R_X86_64_PC8 => (RelocationKind::Relative, 8),
                            r_type => (RelocationKind::Elf(r_type), 0),
                        },
                        _ => (RelocationKind::Elf(reloc.r_type(endian)), 0),
                    };
                    let target =
                        RelocationTarget::Symbol(SymbolIndex(reloc.r_sym(endian) as usize));
                    return Some((
                        reloc.r_offset(endian).into(),
                        Relocation {
                            kind,
                            encoding,
                            size,
                            target,
                            addend: reloc.r_addend(endian).into(),
                            implicit_addend: relocations.is_rel(),
                        },
                    ));
                }
            }
            // End of the relocation section chain?
            if self.section_index == 0 {
                return None;
            }
            let section = self.file.sections.get(self.section_index)?;
            match section.sh_type(endian) {
                elf::SHT_REL => {
                    if let Ok(relocations) = section.data_as_array(endian, self.file.data) {
                        self.relocations = Some(ElfRelaIterator::Rel(relocations.iter()));
                    }
                }
                elf::SHT_RELA => {
                    if let Ok(relocations) = section.data_as_array(endian, self.file.data) {
                        self.relocations = Some(ElfRelaIterator::Rela(relocations.iter()));
                    }
                }
                _ => {}
            }
            // Get the next relocation section in the chain.
            self.section_index = self.file.relocations[self.section_index];
        }
    }
}

impl<'data, 'file, Elf: FileHeader> fmt::Debug for ElfRelocationIterator<'data, 'file, Elf> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ElfRelocationIterator").finish()
    }
}

/// An iterator over the notes in an `ElfSegment` or `ElfSection`.
#[derive(Debug)]
pub struct ElfNoteIterator<'data, Elf>
where
    Elf: FileHeader,
{
    endian: Elf::Endian,
    align: usize,
    data: Bytes<'data>,
}

impl<'data, Elf> ElfNoteIterator<'data, Elf>
where
    Elf: FileHeader,
{
    /// Returns `Err` if `align` is invalid.
    fn new(endian: Elf::Endian, align: Elf::Word, data: Bytes<'data>) -> read::Result<Self> {
        let align = match align.into() {
            0u64..=4 => 4,
            8 => 8,
            _ => return Err(Error("Invalid ELF note alignment")),
        };
        // TODO: check data alignment?
        Ok(ElfNoteIterator {
            endian,
            align,
            data,
        })
    }

    fn next(&mut self) -> read::Result<Option<ElfNote<'data, Elf>>> {
        let mut data = self.data;
        if data.is_empty() {
            return Ok(None);
        }

        let header = data
            .read::<Elf::NoteHeader>()
            .read_error("ELF note is too short")?;

        let namesz = header.n_namesz(self.endian) as usize;
        let name = data
            .read_bytes_at(0, namesz)
            .read_error("Invalid ELF note namesz")?
            .0;

        // Skip both the name and the alignment padding.
        data.skip(util::align(namesz, self.align))
            .read_error("ELF note is too short")?;

        let descsz = header.n_descsz(self.endian) as usize;
        let desc = data
            .read_bytes_at(0, descsz)
            .read_error("Invalid ELF note descsz")?
            .0;

        // Skip both the descriptor and the alignment padding (if any).
        if data.skip(util::align(descsz, self.align)).is_err() {
            data = Bytes(&[]);
        }
        self.data = data;

        Ok(Some(ElfNote { header, name, desc }))
    }
}

/// A parsed `NoteHeader32`.
pub type ElfNote32<'data, Endian = RunTimeEndian> = ElfNote<'data, elf::FileHeader32<Endian>>;
/// A parsed `NoteHeader64`.
pub type ElfNote64<'data, Endian = RunTimeEndian> = ElfNote<'data, elf::FileHeader64<Endian>>;

/// A parsed `NoteHeader`.
#[derive(Debug)]
pub struct ElfNote<'data, Elf>
where
    Elf: FileHeader,
{
    header: &'data Elf::NoteHeader,
    name: &'data [u8],
    desc: &'data [u8],
}

impl<'data, Elf: FileHeader> ElfNote<'data, Elf> {
    /// Return the `n_type` field of the `NoteHeader`.
    ///
    /// The meaning of this field is determined by `name`.
    pub fn n_type(&self, endian: Elf::Endian) -> u32 {
        self.header.n_type(endian)
    }

    /// Return the `n_namesz` field of the `NoteHeader`.
    pub fn n_namesz(&self, endian: Elf::Endian) -> u32 {
        self.header.n_namesz(endian)
    }

    /// Return the `n_descsz` field of the `NoteHeader`.
    pub fn n_descsz(&self, endian: Elf::Endian) -> u32 {
        self.header.n_descsz(endian)
    }

    /// Return the bytes for the name field following the `NoteHeader`.
    ///
    /// The length of this field is given by `n_namesz`. This field is usually a
    /// string including a null terminator (but it is not required to be).
    pub fn name(&self) -> &'data [u8] {
        self.name
    }

    /// Return the bytes for the desc field following the `NoteHeader`.
    ///
    /// The length of this field is given by `n_descsz`. The meaning
    /// of this field is determined by `name` and `n_type`.
    pub fn desc(&self) -> &'data [u8] {
        self.desc
    }
}

#[derive(Debug, Clone, Copy)]
struct SymbolTable<'data, Elf: FileHeader> {
    symbols: &'data [Elf::Sym],
    strings: StringTable<'data>,
    shndx: &'data [u32],
}

/// A trait for generic access to `FileHeader32` and `FileHeader64`.
#[allow(missing_docs)]
pub trait FileHeader: Debug + Pod {
    // Ideally this would be a `u64: From<Word>`, but can't express that.
    type Word: Into<u64>;
    type Sword: Into<i64>;
    type Endian: endian::Endian;
    type ProgramHeader: ProgramHeader<Endian = Self::Endian>;
    type SectionHeader: SectionHeader<Endian = Self::Endian>;
    type CompressionHeader: CompressionHeader<Endian = Self::Endian>;
    type NoteHeader: NoteHeader<Endian = Self::Endian>;
    type Sym: Sym<Endian = Self::Endian>;
    type Rel: Clone + Pod;
    type Rela: Rela<Endian = Self::Endian> + From<Self::Rel>;

    /// Return true if this type is a 64-bit header.
    ///
    /// This is a property of the type, not a value in the header data.
    fn is_type_64(&self) -> bool;

    fn e_ident(&self) -> &elf::Ident;
    fn e_type(&self, endian: Self::Endian) -> u16;
    fn e_machine(&self, endian: Self::Endian) -> u16;
    fn e_version(&self, endian: Self::Endian) -> u32;
    fn e_entry(&self, endian: Self::Endian) -> Self::Word;
    fn e_phoff(&self, endian: Self::Endian) -> Self::Word;
    fn e_shoff(&self, endian: Self::Endian) -> Self::Word;
    fn e_flags(&self, endian: Self::Endian) -> u32;
    fn e_ehsize(&self, endian: Self::Endian) -> u16;
    fn e_phentsize(&self, endian: Self::Endian) -> u16;
    fn e_phnum(&self, endian: Self::Endian) -> u16;
    fn e_shentsize(&self, endian: Self::Endian) -> u16;
    fn e_shnum(&self, endian: Self::Endian) -> u16;
    fn e_shstrndx(&self, endian: Self::Endian) -> u16;

    // Provided methods.

    fn is_supported(&self) -> bool {
        let ident = self.e_ident();
        // TODO: Check self.e_version too? Requires endian though.
        ident.magic == elf::ELFMAG
            && (self.is_type_64() || self.is_class_32())
            && (!self.is_type_64() || self.is_class_64())
            && (self.is_little_endian() || self.is_big_endian())
            && ident.version == elf::EV_CURRENT
    }

    fn is_class_32(&self) -> bool {
        self.e_ident().class == elf::ELFCLASS32
    }

    fn is_class_64(&self) -> bool {
        self.e_ident().class == elf::ELFCLASS64
    }

    fn is_little_endian(&self) -> bool {
        self.e_ident().data == elf::ELFDATA2LSB
    }

    fn is_big_endian(&self) -> bool {
        self.e_ident().data == elf::ELFDATA2MSB
    }

    fn endian(&self) -> read::Result<Self::Endian> {
        Self::Endian::from_big_endian(self.is_big_endian()).read_error("Unsupported ELF endian")
    }

    /// Return the first section header, if present.
    ///
    /// Section 0 is a special case because getting the section headers normally
    /// requires `shnum`, but `shnum` may be in the first section header.
    fn section_0<'data>(
        &self,
        endian: Self::Endian,
        data: Bytes<'data>,
    ) -> read::Result<Option<&'data Self::SectionHeader>> {
        let shoff: u64 = self.e_shoff(endian).into();
        if shoff == 0 {
            // No section headers is ok.
            return Ok(None);
        }
        let shentsize = self.e_shentsize(endian) as usize;
        if shentsize != mem::size_of::<Self::SectionHeader>() {
            // Section header size must match.
            return Err(Error("Invalid ELF section header entry size"));
        }
        data.read_at(shoff as usize)
            .map(Some)
            .read_error("Invalid ELF section header offset or size")
    }

    /// Return the `e_phnum` field of the header. Handles extended values.
    ///
    /// Returns `Err` for invalid values.
    fn phnum<'data>(&self, endian: Self::Endian, data: Bytes<'data>) -> read::Result<usize> {
        let e_phnum = self.e_phnum(endian);
        if e_phnum < elf::PN_XNUM {
            Ok(e_phnum as usize)
        } else if let Some(section_0) = self.section_0(endian, data)? {
            Ok(section_0.sh_info(endian) as usize)
        } else {
            // Section 0 must exist if e_phnum overflows.
            Err(Error("Missing ELF section headers for e_phnum overflow"))
        }
    }

    /// Return the `e_shnum` field of the header. Handles extended values.
    ///
    /// Returns `Err` for invalid values.
    fn shnum<'data>(&self, endian: Self::Endian, data: Bytes<'data>) -> read::Result<usize> {
        let e_shnum = self.e_shnum(endian);
        if e_shnum > 0 {
            Ok(e_shnum as usize)
        } else if let Some(section_0) = self.section_0(endian, data)? {
            let size: u64 = section_0.sh_size(endian).into();
            Ok(size as usize)
        } else {
            // No section headers is ok.
            Ok(0)
        }
    }

    /// Return the `e_shstrndx` field of the header. Handles extended values.
    ///
    /// Returns `Err` for invalid values (including if the index is 0).
    fn shstrndx<'data>(&self, endian: Self::Endian, data: Bytes<'data>) -> read::Result<u32> {
        let e_shstrndx = self.e_shstrndx(endian);
        let index = if e_shstrndx != elf::SHN_XINDEX {
            e_shstrndx.into()
        } else if let Some(section_0) = self.section_0(endian, data)? {
            section_0.sh_link(endian)
        } else {
            // Section 0 must exist if we're trying to read e_shstrndx.
            return Err(Error("Missing ELF section headers for e_shstrndx overflow"));
        };
        if index == 0 {
            return Err(Error("Missing ELF e_shstrndx"));
        }
        Ok(index)
    }

    /// Return the slice of program headers.
    ///
    /// Returns `Ok(&[])` if there are no program headers.
    /// Returns `Err` for invalid values.
    fn program_headers<'data>(
        &self,
        endian: Self::Endian,
        data: Bytes<'data>,
    ) -> read::Result<&'data [Self::ProgramHeader]> {
        let phoff: u64 = self.e_phoff(endian).into();
        if phoff == 0 {
            // No program headers is ok.
            return Ok(&[]);
        }
        let phnum = self.phnum(endian, data)?;
        if phnum == 0 {
            // No program headers is ok.
            return Ok(&[]);
        }
        let phentsize = self.e_phentsize(endian) as usize;
        if phentsize != mem::size_of::<Self::ProgramHeader>() {
            // Program header size must match.
            return Err(Error("Invalid ELF program header entry size"));
        }
        data.read_slice_at(phoff as usize, phnum)
            .read_error("Invalid ELF program header size or alignment")
    }

    /// Return the slice of section headers.
    ///
    /// Returns `Ok(&[])` if there are no section headers.
    /// Returns `Err` for invalid values.
    fn section_headers<'data>(
        &self,
        endian: Self::Endian,
        data: Bytes<'data>,
    ) -> read::Result<&'data [Self::SectionHeader]> {
        let shoff: u64 = self.e_shoff(endian).into();
        if shoff == 0 {
            // No section headers is ok.
            return Ok(&[]);
        }
        let shnum = self.shnum(endian, data)?;
        if shnum == 0 {
            // No section headers is ok.
            return Ok(&[]);
        }
        let shentsize = self.e_shentsize(endian) as usize;
        if shentsize != mem::size_of::<Self::SectionHeader>() {
            // Section header size must match.
            return Err(Error("Invalid ELF section header entry size"));
        }
        data.read_slice_at(shoff as usize, shnum)
            .read_error("Invalid ELF section header offset/size/alignment")
    }
}

/// A trait for generic access to `ProgramHeader32` and `ProgramHeader64`.
#[allow(missing_docs)]
pub trait ProgramHeader: Debug + Pod {
    type Word: Into<u64>;
    type Endian: endian::Endian;
    type Elf: FileHeader<Word = Self::Word, Endian = Self::Endian>;

    fn p_type(&self, endian: Self::Endian) -> u32;
    fn p_flags(&self, endian: Self::Endian) -> u32;
    fn p_offset(&self, endian: Self::Endian) -> Self::Word;
    fn p_vaddr(&self, endian: Self::Endian) -> Self::Word;
    fn p_paddr(&self, endian: Self::Endian) -> Self::Word;
    fn p_filesz(&self, endian: Self::Endian) -> Self::Word;
    fn p_memsz(&self, endian: Self::Endian) -> Self::Word;
    fn p_align(&self, endian: Self::Endian) -> Self::Word;

    /// Return the offset and size of the segment in the file.
    fn file_range(&self, endian: Self::Endian) -> (u64, u64) {
        (self.p_offset(endian).into(), self.p_filesz(endian).into())
    }

    /// Return the segment data.
    ///
    /// Returns `Err` for invalid values.
    fn data<'data>(&self, endian: Self::Endian, data: Bytes<'data>) -> Result<Bytes<'data>, ()> {
        let (offset, size) = self.file_range(endian);
        data.read_bytes_at(offset as usize, size as usize)
    }

    /// Return a note iterator for the segment data.
    ///
    /// Returns an empty iterator if the segment does not contain notes.
    /// Returns `Err` for invalid values.
    fn notes<'data>(
        &self,
        endian: Self::Endian,
        data: Bytes<'data>,
    ) -> read::Result<ElfNoteIterator<'data, Self::Elf>> {
        let data = if self.p_type(endian) == elf::PT_NOTE {
            self.data(endian, data)
                .read_error("Invalid ELF note segment offset or size")?
        } else {
            Bytes(&[])
        };
        ElfNoteIterator::new(endian, self.p_align(endian), data)
    }
}

/// A trait for generic access to `SectionHeader32` and `SectionHeader64`.
#[allow(missing_docs)]
pub trait SectionHeader: Debug + Pod {
    type Word: Into<u64>;
    type Endian: endian::Endian;
    type Elf: FileHeader<Word = Self::Word, Endian = Self::Endian>;

    fn sh_name(&self, endian: Self::Endian) -> u32;
    fn sh_type(&self, endian: Self::Endian) -> u32;
    fn sh_flags(&self, endian: Self::Endian) -> Self::Word;
    fn sh_addr(&self, endian: Self::Endian) -> Self::Word;
    fn sh_offset(&self, endian: Self::Endian) -> Self::Word;
    fn sh_size(&self, endian: Self::Endian) -> Self::Word;
    fn sh_link(&self, endian: Self::Endian) -> u32;
    fn sh_info(&self, endian: Self::Endian) -> u32;
    fn sh_addralign(&self, endian: Self::Endian) -> Self::Word;
    fn sh_entsize(&self, endian: Self::Endian) -> Self::Word;

    /// Return the offset and size of the section in the file.
    ///
    /// Returns `None` for sections that have no data in the file.
    fn file_range(&self, endian: Self::Endian) -> Option<(u64, u64)> {
        if self.sh_type(endian) == elf::SHT_NOBITS {
            None
        } else {
            Some((self.sh_offset(endian).into(), self.sh_size(endian).into()))
        }
    }

    /// Return the section data.
    ///
    /// Returns `Ok(&[])` if the section has no data.
    /// Returns `Err` for invalid values.
    fn data<'data>(&self, endian: Self::Endian, data: Bytes<'data>) -> Result<Bytes<'data>, ()> {
        if let Some((offset, size)) = self.file_range(endian) {
            data.read_bytes_at(offset as usize, size as usize)
        } else {
            Ok(Bytes(&[]))
        }
    }

    /// Return the section data as a slice of the given type.
    ///
    /// Allows padding at the end of the data.
    /// Returns `Ok(&[])` if the section has no data.
    /// Returns `Err` for invalid values, including bad alignment.
    fn data_as_array<'data, T: Pod>(
        &self,
        endian: Self::Endian,
        data: Bytes<'data>,
    ) -> Result<&'data [T], ()> {
        let mut data = self.data(endian, data)?;
        data.read_slice(data.len() / mem::size_of::<T>())
    }

    /// Return a note iterator for the section data.
    ///
    /// Returns an empty iterator if the section does not contain notes.
    /// Returns `Err` for invalid values.
    fn notes<'data>(
        &self,
        endian: Self::Endian,
        data: Bytes<'data>,
    ) -> read::Result<ElfNoteIterator<'data, Self::Elf>> {
        let data = if self.sh_type(endian) == elf::SHT_NOTE {
            self.data(endian, data)
                .read_error("Invalid ELF note section offset or size")?
        } else {
            Bytes(&[])
        };
        ElfNoteIterator::new(endian, self.sh_addralign(endian), data)
    }
}

/// A trait for generic access to `CompressionHeader32` and `CompressionHeader64`.
#[allow(missing_docs)]
pub trait CompressionHeader: Debug + Pod {
    type Word: Into<u64>;
    type Endian: endian::Endian;

    fn ch_type(&self, endian: Self::Endian) -> u32;
    fn ch_size(&self, endian: Self::Endian) -> Self::Word;
    fn ch_addralign(&self, endian: Self::Endian) -> Self::Word;
}

/// A trait for generic access to `NoteHeader32` and `NoteHeader64`.
#[allow(missing_docs)]
pub trait NoteHeader: Debug + Pod {
    type Endian: endian::Endian;

    fn n_namesz(&self, endian: Self::Endian) -> u32;
    fn n_descsz(&self, endian: Self::Endian) -> u32;
    fn n_type(&self, endian: Self::Endian) -> u32;
}

/// A trait for generic access to `Sym32` and `Sym64`.
#[allow(missing_docs)]
pub trait Sym: Debug + Pod {
    type Word: Into<u64>;
    type Endian: endian::Endian;

    fn st_name(&self, endian: Self::Endian) -> u32;
    fn st_info(&self) -> u8;
    fn st_bind(&self) -> u8;
    fn st_type(&self) -> u8;
    fn st_other(&self) -> u8;
    fn st_visibility(&self) -> u8;
    fn st_shndx(&self, endian: Self::Endian) -> u16;
    fn st_value(&self, endian: Self::Endian) -> Self::Word;
    fn st_size(&self, endian: Self::Endian) -> Self::Word;
}

/// A trait for generic access to `Rela32` and `Rela64`.
#[allow(missing_docs)]
pub trait Rela: Debug + Pod + Clone {
    type Word: Into<u64>;
    type Sword: Into<i64>;
    type Endian: endian::Endian;

    fn r_offset(&self, endian: Self::Endian) -> Self::Word;
    fn r_info(&self, endian: Self::Endian) -> Self::Word;
    fn r_addend(&self, endian: Self::Endian) -> Self::Sword;
    fn r_sym(&self, endian: Self::Endian) -> u32;
    fn r_type(&self, endian: Self::Endian) -> u32;
}

impl<Endian: endian::Endian> FileHeader for elf::FileHeader32<Endian> {
    type Word = u32;
    type Sword = i32;
    type Endian = Endian;
    type ProgramHeader = elf::ProgramHeader32<Endian>;
    type SectionHeader = elf::SectionHeader32<Endian>;
    type CompressionHeader = elf::CompressionHeader32<Endian>;
    type NoteHeader = elf::NoteHeader32<Endian>;
    type Sym = elf::Sym32<Endian>;
    type Rel = elf::Rel32<Endian>;
    type Rela = elf::Rela32<Endian>;

    #[inline]
    fn is_type_64(&self) -> bool {
        false
    }

    #[inline]
    fn e_ident(&self) -> &elf::Ident {
        &self.e_ident
    }

    #[inline]
    fn e_type(&self, endian: Self::Endian) -> u16 {
        self.e_type.get(endian)
    }

    #[inline]
    fn e_machine(&self, endian: Self::Endian) -> u16 {
        self.e_machine.get(endian)
    }

    #[inline]
    fn e_version(&self, endian: Self::Endian) -> u32 {
        self.e_version.get(endian)
    }

    #[inline]
    fn e_entry(&self, endian: Self::Endian) -> Self::Word {
        self.e_entry.get(endian)
    }

    #[inline]
    fn e_phoff(&self, endian: Self::Endian) -> Self::Word {
        self.e_phoff.get(endian)
    }

    #[inline]
    fn e_shoff(&self, endian: Self::Endian) -> Self::Word {
        self.e_shoff.get(endian)
    }

    #[inline]
    fn e_flags(&self, endian: Self::Endian) -> u32 {
        self.e_flags.get(endian)
    }

    #[inline]
    fn e_ehsize(&self, endian: Self::Endian) -> u16 {
        self.e_ehsize.get(endian)
    }

    #[inline]
    fn e_phentsize(&self, endian: Self::Endian) -> u16 {
        self.e_phentsize.get(endian)
    }

    #[inline]
    fn e_phnum(&self, endian: Self::Endian) -> u16 {
        self.e_phnum.get(endian)
    }

    #[inline]
    fn e_shentsize(&self, endian: Self::Endian) -> u16 {
        self.e_shentsize.get(endian)
    }

    #[inline]
    fn e_shnum(&self, endian: Self::Endian) -> u16 {
        self.e_shnum.get(endian)
    }

    #[inline]
    fn e_shstrndx(&self, endian: Self::Endian) -> u16 {
        self.e_shstrndx.get(endian)
    }
}

impl<Endian: endian::Endian> ProgramHeader for elf::ProgramHeader32<Endian> {
    type Word = u32;
    type Endian = Endian;
    type Elf = elf::FileHeader32<Endian>;

    #[inline]
    fn p_type(&self, endian: Self::Endian) -> u32 {
        self.p_type.get(endian)
    }

    #[inline]
    fn p_flags(&self, endian: Self::Endian) -> u32 {
        self.p_flags.get(endian)
    }

    #[inline]
    fn p_offset(&self, endian: Self::Endian) -> Self::Word {
        self.p_offset.get(endian)
    }

    #[inline]
    fn p_vaddr(&self, endian: Self::Endian) -> Self::Word {
        self.p_vaddr.get(endian)
    }

    #[inline]
    fn p_paddr(&self, endian: Self::Endian) -> Self::Word {
        self.p_paddr.get(endian)
    }

    #[inline]
    fn p_filesz(&self, endian: Self::Endian) -> Self::Word {
        self.p_filesz.get(endian)
    }

    #[inline]
    fn p_memsz(&self, endian: Self::Endian) -> Self::Word {
        self.p_memsz.get(endian)
    }

    #[inline]
    fn p_align(&self, endian: Self::Endian) -> Self::Word {
        self.p_align.get(endian)
    }
}

impl<Endian: endian::Endian> SectionHeader for elf::SectionHeader32<Endian> {
    type Word = u32;
    type Endian = Endian;
    type Elf = elf::FileHeader32<Endian>;

    #[inline]
    fn sh_name(&self, endian: Self::Endian) -> u32 {
        self.sh_name.get(endian)
    }

    #[inline]
    fn sh_type(&self, endian: Self::Endian) -> u32 {
        self.sh_type.get(endian)
    }

    #[inline]
    fn sh_flags(&self, endian: Self::Endian) -> Self::Word {
        self.sh_flags.get(endian)
    }

    #[inline]
    fn sh_addr(&self, endian: Self::Endian) -> Self::Word {
        self.sh_addr.get(endian)
    }

    #[inline]
    fn sh_offset(&self, endian: Self::Endian) -> Self::Word {
        self.sh_offset.get(endian)
    }

    #[inline]
    fn sh_size(&self, endian: Self::Endian) -> Self::Word {
        self.sh_size.get(endian)
    }

    #[inline]
    fn sh_link(&self, endian: Self::Endian) -> u32 {
        self.sh_link.get(endian)
    }

    #[inline]
    fn sh_info(&self, endian: Self::Endian) -> u32 {
        self.sh_info.get(endian)
    }

    #[inline]
    fn sh_addralign(&self, endian: Self::Endian) -> Self::Word {
        self.sh_addralign.get(endian)
    }

    #[inline]
    fn sh_entsize(&self, endian: Self::Endian) -> Self::Word {
        self.sh_entsize.get(endian)
    }
}

impl<Endian: endian::Endian> CompressionHeader for elf::CompressionHeader32<Endian> {
    type Word = u32;
    type Endian = Endian;

    #[inline]
    fn ch_type(&self, endian: Self::Endian) -> u32 {
        self.ch_type.get(endian)
    }

    #[inline]
    fn ch_size(&self, endian: Self::Endian) -> Self::Word {
        self.ch_size.get(endian)
    }

    #[inline]
    fn ch_addralign(&self, endian: Self::Endian) -> Self::Word {
        self.ch_addralign.get(endian)
    }
}

impl<Endian: endian::Endian> NoteHeader for elf::NoteHeader32<Endian> {
    type Endian = Endian;

    #[inline]
    fn n_namesz(&self, endian: Self::Endian) -> u32 {
        self.n_namesz.get(endian)
    }

    #[inline]
    fn n_descsz(&self, endian: Self::Endian) -> u32 {
        self.n_descsz.get(endian)
    }

    #[inline]
    fn n_type(&self, endian: Self::Endian) -> u32 {
        self.n_type.get(endian)
    }
}

impl<Endian: endian::Endian> Sym for elf::Sym32<Endian> {
    type Word = u32;
    type Endian = Endian;

    #[inline]
    fn st_name(&self, endian: Self::Endian) -> u32 {
        self.st_name.get(endian)
    }

    #[inline]
    fn st_info(&self) -> u8 {
        self.st_info
    }

    #[inline]
    fn st_bind(&self) -> u8 {
        self.st_bind()
    }

    #[inline]
    fn st_type(&self) -> u8 {
        self.st_type()
    }

    #[inline]
    fn st_other(&self) -> u8 {
        self.st_other
    }

    #[inline]
    fn st_visibility(&self) -> u8 {
        self.st_visibility()
    }

    #[inline]
    fn st_shndx(&self, endian: Self::Endian) -> u16 {
        self.st_shndx.get(endian)
    }

    #[inline]
    fn st_value(&self, endian: Self::Endian) -> Self::Word {
        self.st_value.get(endian)
    }

    #[inline]
    fn st_size(&self, endian: Self::Endian) -> Self::Word {
        self.st_size.get(endian)
    }
}

impl<Endian: endian::Endian> Rela for elf::Rela32<Endian> {
    type Word = u32;
    type Sword = i32;
    type Endian = Endian;

    #[inline]
    fn r_offset(&self, endian: Self::Endian) -> Self::Word {
        self.r_offset.get(endian)
    }

    #[inline]
    fn r_info(&self, endian: Self::Endian) -> Self::Word {
        self.r_info.get(endian)
    }

    #[inline]
    fn r_addend(&self, endian: Self::Endian) -> Self::Sword {
        self.r_addend.get(endian)
    }

    #[inline]
    fn r_sym(&self, endian: Self::Endian) -> u32 {
        self.r_sym(endian)
    }

    #[inline]
    fn r_type(&self, endian: Self::Endian) -> u32 {
        self.r_type(endian)
    }
}

impl<Endian: endian::Endian> FileHeader for elf::FileHeader64<Endian> {
    type Word = u64;
    type Sword = i64;
    type Endian = Endian;
    type ProgramHeader = elf::ProgramHeader64<Endian>;
    type SectionHeader = elf::SectionHeader64<Endian>;
    type CompressionHeader = elf::CompressionHeader64<Endian>;
    type NoteHeader = elf::NoteHeader32<Endian>;
    type Sym = elf::Sym64<Endian>;
    type Rel = elf::Rel64<Endian>;
    type Rela = elf::Rela64<Endian>;

    #[inline]
    fn is_type_64(&self) -> bool {
        true
    }

    #[inline]
    fn e_ident(&self) -> &elf::Ident {
        &self.e_ident
    }

    #[inline]
    fn e_type(&self, endian: Self::Endian) -> u16 {
        self.e_type.get(endian)
    }

    #[inline]
    fn e_machine(&self, endian: Self::Endian) -> u16 {
        self.e_machine.get(endian)
    }

    #[inline]
    fn e_version(&self, endian: Self::Endian) -> u32 {
        self.e_version.get(endian)
    }

    #[inline]
    fn e_entry(&self, endian: Self::Endian) -> Self::Word {
        self.e_entry.get(endian)
    }

    #[inline]
    fn e_phoff(&self, endian: Self::Endian) -> Self::Word {
        self.e_phoff.get(endian)
    }

    #[inline]
    fn e_shoff(&self, endian: Self::Endian) -> Self::Word {
        self.e_shoff.get(endian)
    }

    #[inline]
    fn e_flags(&self, endian: Self::Endian) -> u32 {
        self.e_flags.get(endian)
    }

    #[inline]
    fn e_ehsize(&self, endian: Self::Endian) -> u16 {
        self.e_ehsize.get(endian)
    }

    #[inline]
    fn e_phentsize(&self, endian: Self::Endian) -> u16 {
        self.e_phentsize.get(endian)
    }

    #[inline]
    fn e_phnum(&self, endian: Self::Endian) -> u16 {
        self.e_phnum.get(endian)
    }

    #[inline]
    fn e_shentsize(&self, endian: Self::Endian) -> u16 {
        self.e_shentsize.get(endian)
    }

    #[inline]
    fn e_shnum(&self, endian: Self::Endian) -> u16 {
        self.e_shnum.get(endian)
    }

    #[inline]
    fn e_shstrndx(&self, endian: Self::Endian) -> u16 {
        self.e_shstrndx.get(endian)
    }
}

impl<Endian: endian::Endian> ProgramHeader for elf::ProgramHeader64<Endian> {
    type Word = u64;
    type Endian = Endian;
    type Elf = elf::FileHeader64<Endian>;

    #[inline]
    fn p_type(&self, endian: Self::Endian) -> u32 {
        self.p_type.get(endian)
    }

    #[inline]
    fn p_flags(&self, endian: Self::Endian) -> u32 {
        self.p_flags.get(endian)
    }

    #[inline]
    fn p_offset(&self, endian: Self::Endian) -> Self::Word {
        self.p_offset.get(endian)
    }

    #[inline]
    fn p_vaddr(&self, endian: Self::Endian) -> Self::Word {
        self.p_vaddr.get(endian)
    }

    #[inline]
    fn p_paddr(&self, endian: Self::Endian) -> Self::Word {
        self.p_paddr.get(endian)
    }

    #[inline]
    fn p_filesz(&self, endian: Self::Endian) -> Self::Word {
        self.p_filesz.get(endian)
    }

    #[inline]
    fn p_memsz(&self, endian: Self::Endian) -> Self::Word {
        self.p_memsz.get(endian)
    }

    #[inline]
    fn p_align(&self, endian: Self::Endian) -> Self::Word {
        self.p_align.get(endian)
    }
}

impl<Endian: endian::Endian> SectionHeader for elf::SectionHeader64<Endian> {
    type Word = u64;
    type Endian = Endian;
    type Elf = elf::FileHeader64<Endian>;

    #[inline]
    fn sh_name(&self, endian: Self::Endian) -> u32 {
        self.sh_name.get(endian)
    }

    #[inline]
    fn sh_type(&self, endian: Self::Endian) -> u32 {
        self.sh_type.get(endian)
    }

    #[inline]
    fn sh_flags(&self, endian: Self::Endian) -> Self::Word {
        self.sh_flags.get(endian)
    }

    #[inline]
    fn sh_addr(&self, endian: Self::Endian) -> Self::Word {
        self.sh_addr.get(endian)
    }

    #[inline]
    fn sh_offset(&self, endian: Self::Endian) -> Self::Word {
        self.sh_offset.get(endian)
    }

    #[inline]
    fn sh_size(&self, endian: Self::Endian) -> Self::Word {
        self.sh_size.get(endian)
    }

    #[inline]
    fn sh_link(&self, endian: Self::Endian) -> u32 {
        self.sh_link.get(endian)
    }

    #[inline]
    fn sh_info(&self, endian: Self::Endian) -> u32 {
        self.sh_info.get(endian)
    }

    #[inline]
    fn sh_addralign(&self, endian: Self::Endian) -> Self::Word {
        self.sh_addralign.get(endian)
    }

    #[inline]
    fn sh_entsize(&self, endian: Self::Endian) -> Self::Word {
        self.sh_entsize.get(endian)
    }
}

impl<Endian: endian::Endian> CompressionHeader for elf::CompressionHeader64<Endian> {
    type Word = u64;
    type Endian = Endian;

    #[inline]
    fn ch_type(&self, endian: Self::Endian) -> u32 {
        self.ch_type.get(endian)
    }

    #[inline]
    fn ch_size(&self, endian: Self::Endian) -> Self::Word {
        self.ch_size.get(endian)
    }

    #[inline]
    fn ch_addralign(&self, endian: Self::Endian) -> Self::Word {
        self.ch_addralign.get(endian)
    }
}

impl<Endian: endian::Endian> NoteHeader for elf::NoteHeader64<Endian> {
    type Endian = Endian;

    #[inline]
    fn n_namesz(&self, endian: Self::Endian) -> u32 {
        self.n_namesz.get(endian)
    }

    #[inline]
    fn n_descsz(&self, endian: Self::Endian) -> u32 {
        self.n_descsz.get(endian)
    }

    #[inline]
    fn n_type(&self, endian: Self::Endian) -> u32 {
        self.n_type.get(endian)
    }
}

impl<Endian: endian::Endian> Sym for elf::Sym64<Endian> {
    type Word = u64;
    type Endian = Endian;

    #[inline]
    fn st_name(&self, endian: Self::Endian) -> u32 {
        self.st_name.get(endian)
    }

    #[inline]
    fn st_info(&self) -> u8 {
        self.st_info
    }

    #[inline]
    fn st_bind(&self) -> u8 {
        self.st_bind()
    }

    #[inline]
    fn st_type(&self) -> u8 {
        self.st_type()
    }

    #[inline]
    fn st_other(&self) -> u8 {
        self.st_other
    }

    #[inline]
    fn st_visibility(&self) -> u8 {
        self.st_visibility()
    }

    #[inline]
    fn st_shndx(&self, endian: Self::Endian) -> u16 {
        self.st_shndx.get(endian)
    }

    #[inline]
    fn st_value(&self, endian: Self::Endian) -> Self::Word {
        self.st_value.get(endian)
    }

    #[inline]
    fn st_size(&self, endian: Self::Endian) -> Self::Word {
        self.st_size.get(endian)
    }
}

impl<Endian: endian::Endian> Rela for elf::Rela64<Endian> {
    type Word = u64;
    type Sword = i64;
    type Endian = Endian;

    #[inline]
    fn r_offset(&self, endian: Self::Endian) -> Self::Word {
        self.r_offset.get(endian)
    }

    #[inline]
    fn r_info(&self, endian: Self::Endian) -> Self::Word {
        self.r_info.get(endian)
    }

    #[inline]
    fn r_addend(&self, endian: Self::Endian) -> Self::Sword {
        self.r_addend.get(endian)
    }

    #[inline]
    fn r_sym(&self, endian: Self::Endian) -> u32 {
        self.r_sym(endian)
    }

    #[inline]
    fn r_type(&self, endian: Self::Endian) -> u32 {
        self.r_type(endian)
    }
}
