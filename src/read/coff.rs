//! Support for reading Windows COFF files.
//!
//! Provides `CoffFile` and related types which implement the `Object` trait.

#[cfg(feature = "compression")]
use alloc::borrow::Cow;
use alloc::fmt;
use alloc::vec::Vec;
use core::convert::TryInto;
use core::{iter, slice, str};
use target_lexicon::Architecture;

use crate::endian::{LittleEndian as LE, U32Bytes};
use crate::pe;
use crate::pod::{Bytes, Pod};
use crate::read::util::StringTable;
use crate::read::{
    self, FileFlags, Object, ObjectSection, ObjectSegment, Relocation, RelocationEncoding,
    RelocationKind, RelocationTarget, SectionFlags, SectionIndex, SectionKind, Symbol, SymbolFlags,
    SymbolIndex, SymbolKind, SymbolMap, SymbolScope, SymbolSection,
};

/// A COFF object file.
#[derive(Debug)]
pub struct CoffFile<'data> {
    header: &'data pe::ImageFileHeader,
    sections: &'data [pe::ImageSectionHeader],
    // TODO: ImageSymbolExBytes
    symbols: SymbolTable<'data>,
    data: Bytes<'data>,
}

impl<'data> CoffFile<'data> {
    /// Parse the raw COFF file data.
    pub fn parse(data: &'data [u8]) -> Result<Self, &'static str> {
        let data = Bytes(data);
        let mut tail = data;
        let header = tail
            .read::<pe::ImageFileHeader>()
            .ok_or("Invalid COFF file header size or alignment")?;

        // Skip over the optional header and get the section headers.
        tail.skip(header.size_of_optional_header.get(LE) as usize)
            .ok_or("Invalid COFF optional header size")?;
        let sections = tail
            .read_slice(header.number_of_sections.get(LE) as usize)
            .ok_or("Invalid section headers")?;

        let symbols = SymbolTable::parse(header, data)?;

        // TODO: maybe validate that the machine is known?
        Ok(CoffFile {
            header,
            sections,
            symbols,
            data,
        })
    }
}

impl<'data> read::private::Sealed for CoffFile<'data> {}

impl<'data, 'file> Object<'data, 'file> for CoffFile<'data>
where
    'data: 'file,
{
    type Segment = CoffSegment<'data, 'file>;
    type SegmentIterator = CoffSegmentIterator<'data, 'file>;
    type Section = CoffSection<'data, 'file>;
    type SectionIterator = CoffSectionIterator<'data, 'file>;
    type SymbolIterator = CoffSymbolIterator<'data, 'file>;

    fn architecture(&self) -> Architecture {
        match self.header.machine.get(LE) {
            pe::IMAGE_FILE_MACHINE_I386 => Architecture::I386,
            pe::IMAGE_FILE_MACHINE_AMD64 => Architecture::X86_64,
            _ => Architecture::Unknown,
        }
    }

    #[inline]
    fn is_little_endian(&self) -> bool {
        true
    }

    #[inline]
    fn is_64(&self) -> bool {
        false
    }

    fn segments(&'file self) -> CoffSegmentIterator<'data, 'file> {
        CoffSegmentIterator {
            file: self,
            iter: self.sections.iter(),
        }
    }

    fn section_by_name(&'file self, section_name: &str) -> Option<CoffSection<'data, 'file>> {
        self.sections()
            .find(|section| section.name() == Some(section_name))
    }

    fn section_by_index(&'file self, index: SectionIndex) -> Option<CoffSection<'data, 'file>> {
        self.sections().find(|section| section.index() == index)
    }

    fn sections(&'file self) -> CoffSectionIterator<'data, 'file> {
        CoffSectionIterator {
            file: self,
            iter: self.sections.iter().enumerate(),
        }
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> Option<Symbol<'data>> {
        Some(parse_symbol(
            &self.symbols,
            index.0,
            self.symbols.get(index.0)?,
        ))
    }

    fn symbols(&'file self) -> CoffSymbolIterator<'data, 'file> {
        CoffSymbolIterator {
            symbols: &self.symbols,
            index: 0,
        }
    }

    fn dynamic_symbols(&'file self) -> CoffSymbolIterator<'data, 'file> {
        CoffSymbolIterator {
            symbols: &self.symbols,
            // Hack: don't return any.
            index: self.symbols.symbols.len(),
        }
    }

    fn symbol_map(&self) -> SymbolMap<'data> {
        // TODO: untested
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
            if section.name[..12] == b".debug_info\0"[..] {
                return true;
            }
        }
        false
    }

    #[inline]
    fn entry(&self) -> u64 {
        0
    }

    fn flags(&self) -> FileFlags {
        FileFlags::Coff {
            characteristics: self.header.characteristics.get(LE),
        }
    }
}

/// An iterator over the loadable sections of a `CoffFile`.
#[derive(Debug)]
pub struct CoffSegmentIterator<'data, 'file>
where
    'data: 'file,
{
    file: &'file CoffFile<'data>,
    iter: slice::Iter<'data, pe::ImageSectionHeader>,
}

impl<'data, 'file> Iterator for CoffSegmentIterator<'data, 'file> {
    type Item = CoffSegment<'data, 'file>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|section| CoffSegment {
            file: self.file,
            section,
        })
    }
}

/// A loadable section of a `CoffFile`.
#[derive(Debug)]
pub struct CoffSegment<'data, 'file>
where
    'data: 'file,
{
    file: &'file CoffFile<'data>,
    section: &'data pe::ImageSectionHeader,
}

impl<'data, 'file> CoffSegment<'data, 'file> {
    fn bytes(&self) -> Bytes<'data> {
        self.section
            .coff_bytes(self.file.data)
            .unwrap_or(Bytes(&[]))
    }
}

impl<'data, 'file> read::private::Sealed for CoffSegment<'data, 'file> {}

impl<'data, 'file> ObjectSegment<'data> for CoffSegment<'data, 'file> {
    #[inline]
    fn address(&self) -> u64 {
        u64::from(self.section.virtual_address.get(LE))
    }

    #[inline]
    fn size(&self) -> u64 {
        u64::from(self.section.virtual_size.get(LE))
    }

    #[inline]
    fn align(&self) -> u64 {
        self.section.coff_alignment()
    }

    #[inline]
    fn file_range(&self) -> (u64, u64) {
        let (offset, size) = self.section.coff_file_range().unwrap_or((0, 0));
        (u64::from(offset), u64::from(size))
    }

    fn data(&self) -> &'data [u8] {
        self.bytes().0
    }

    fn data_range(&self, address: u64, size: u64) -> Option<&'data [u8]> {
        read::data_range(self.bytes(), self.address(), address, size)
    }

    #[inline]
    fn name(&self) -> Option<&str> {
        self.section.name(self.file.symbols.strings)
    }
}

/// An iterator over the sections of a `CoffFile`.
#[derive(Debug)]
pub struct CoffSectionIterator<'data, 'file>
where
    'data: 'file,
{
    file: &'file CoffFile<'data>,
    iter: iter::Enumerate<slice::Iter<'data, pe::ImageSectionHeader>>,
}

impl<'data, 'file> Iterator for CoffSectionIterator<'data, 'file> {
    type Item = CoffSection<'data, 'file>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|(index, section)| CoffSection {
            file: self.file,
            index: SectionIndex(index),
            section,
        })
    }
}

/// A section of a `CoffFile`.
#[derive(Debug)]
pub struct CoffSection<'data, 'file>
where
    'data: 'file,
{
    file: &'file CoffFile<'data>,
    index: SectionIndex,
    section: &'data pe::ImageSectionHeader,
}

impl<'data, 'file> CoffSection<'data, 'file> {
    fn bytes(&self) -> Bytes<'data> {
        self.section
            .coff_bytes(self.file.data)
            .unwrap_or(Bytes(&[]))
    }
}

impl<'data, 'file> read::private::Sealed for CoffSection<'data, 'file> {}

impl<'data, 'file> ObjectSection<'data> for CoffSection<'data, 'file> {
    type RelocationIterator = CoffRelocationIterator<'data, 'file>;

    #[inline]
    fn index(&self) -> SectionIndex {
        self.index
    }

    #[inline]
    fn address(&self) -> u64 {
        u64::from(self.section.virtual_address.get(LE))
    }

    #[inline]
    fn size(&self) -> u64 {
        // TODO: This may need to be the length from the auxiliary symbol for this section.
        u64::from(self.section.size_of_raw_data.get(LE))
    }

    #[inline]
    fn align(&self) -> u64 {
        self.section.coff_alignment()
    }

    #[inline]
    fn file_range(&self) -> Option<(u64, u64)> {
        let (offset, size) = self.section.coff_file_range()?;
        Some((u64::from(offset), u64::from(size)))
    }

    fn data(&self) -> &'data [u8] {
        self.bytes().0
    }

    fn data_range(&self, address: u64, size: u64) -> Option<&'data [u8]> {
        read::data_range(self.bytes(), self.address(), address, size)
    }

    #[cfg(feature = "compression")]
    #[inline]
    fn uncompressed_data(&self) -> Option<Cow<'data, [u8]>> {
        Some(Cow::from(self.data()))
    }

    #[inline]
    fn name(&self) -> Option<&str> {
        self.section.name(self.file.symbols.strings)
    }

    #[inline]
    fn segment_name(&self) -> Option<&str> {
        None
    }

    #[inline]
    fn kind(&self) -> SectionKind {
        self.section.kind()
    }

    fn relocations(&self) -> CoffRelocationIterator<'data, 'file> {
        let pointer = self.section.pointer_to_relocations.get(LE) as usize;
        let number = self.section.number_of_relocations.get(LE) as usize;
        let relocations = self.file.data.read_slice_at(pointer, number).unwrap_or(&[]);
        CoffRelocationIterator {
            file: self.file,
            iter: relocations.iter(),
        }
    }

    fn flags(&self) -> SectionFlags {
        SectionFlags::Coff {
            characteristics: self.section.characteristics.get(LE),
        }
    }
}

/// An iterator over the symbols of a `CoffFile`.
pub struct CoffSymbolIterator<'data, 'file>
where
    'data: 'file,
{
    pub(crate) symbols: &'file SymbolTable<'data>,
    pub(crate) index: usize,
}

impl<'data, 'file> fmt::Debug for CoffSymbolIterator<'data, 'file> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoffSymbolIterator").finish()
    }
}

impl<'data, 'file> Iterator for CoffSymbolIterator<'data, 'file> {
    type Item = (SymbolIndex, Symbol<'data>);

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.index;
        let symbol = self.symbols.get::<pe::ImageSymbol>(index)?;
        self.index += 1 + symbol.number_of_aux_symbols as usize;
        Some((
            SymbolIndex(index),
            parse_symbol(self.symbols, index, symbol),
        ))
    }
}

pub(crate) fn parse_symbol<'data>(
    symbols: &SymbolTable<'data>,
    index: usize,
    symbol: &'data pe::ImageSymbol,
) -> Symbol<'data> {
    let value = symbol.value.get(LE);
    let section_number = symbol.section_number.get(LE);

    let name = if symbol.storage_class == pe::IMAGE_SYM_CLASS_FILE {
        // The file name is in the following auxiliary symbol.
        if symbol.number_of_aux_symbols > 0 {
            symbols.symbols.get(index + 1).map(|s| {
                // The name is padded with nulls.
                match s.0.iter().position(|&x| x == 0) {
                    Some(end) => &s.0[..end],
                    None => &s.0[..],
                }
            })
        } else {
            None
        }
    } else if symbol.name[0] == 0 {
        // If the name starts with 0 then the last 4 bytes are a string table offset.
        let offset = u32::from_le_bytes(symbol.name[4..8].try_into().unwrap());
        symbols.strings.get(offset)
    } else {
        // The name is inline and padded with nulls.
        Some(match symbol.name.iter().position(|&x| x == 0) {
            Some(end) => &symbol.name[..end],
            None => &symbol.name[..],
        })
    };
    let name = name.and_then(|s| str::from_utf8(s).ok());

    let derived_kind = if symbol.derived_type() == pe::IMAGE_SYM_DTYPE_FUNCTION {
        SymbolKind::Text
    } else {
        SymbolKind::Data
    };
    let mut flags = SymbolFlags::None;
    // FIXME: symbol.value is a section offset for non-absolute symbols, not an address
    let (kind, address, size) = match symbol.storage_class {
        pe::IMAGE_SYM_CLASS_STATIC => {
            if value == 0 && symbol.number_of_aux_symbols > 0 {
                let mut size = 0;
                if let Some(aux) = symbols.get::<pe::ImageAuxSymbolSection>(index + 1) {
                    size = u64::from(aux.length.get(LE));
                    // TODO: use high_number for bigobj
                    let number = aux.number.get(LE) as usize;
                    flags = SymbolFlags::CoffSection {
                        selection: aux.selection,
                        associative_section: SectionIndex(number),
                    };
                }
                (SymbolKind::Section, 0, size)
            } else {
                (derived_kind, u64::from(value), 0)
            }
        }
        pe::IMAGE_SYM_CLASS_EXTERNAL => {
            if section_number == pe::IMAGE_SYM_UNDEFINED {
                // Common data: symbol.value is the size.
                (derived_kind, 0, u64::from(value))
            } else if symbol.derived_type() == pe::IMAGE_SYM_DTYPE_FUNCTION
                && symbol.number_of_aux_symbols > 0
            {
                let mut size = 0;
                if let Some(aux) = symbols.get::<pe::ImageAuxSymbolFunction>(index + 1) {
                    size = u64::from(aux.total_size.get(LE));
                }
                (derived_kind, u64::from(value), size)
            } else {
                (derived_kind, u64::from(value), 0)
            }
        }
        pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL => (derived_kind, u64::from(value), 0),
        pe::IMAGE_SYM_CLASS_SECTION => (SymbolKind::Section, 0, 0),
        pe::IMAGE_SYM_CLASS_FILE => (SymbolKind::File, 0, 0),
        pe::IMAGE_SYM_CLASS_LABEL => (SymbolKind::Label, u64::from(value), 0),
        _ => {
            // No address because symbol.value could mean anything.
            (SymbolKind::Unknown, 0, 0)
        }
    };
    let section = match section_number {
        pe::IMAGE_SYM_UNDEFINED => {
            if symbol.storage_class == pe::IMAGE_SYM_CLASS_EXTERNAL {
                SymbolSection::Common
            } else {
                SymbolSection::Undefined
            }
        }
        pe::IMAGE_SYM_ABSOLUTE => SymbolSection::Absolute,
        pe::IMAGE_SYM_DEBUG => {
            if symbol.storage_class == pe::IMAGE_SYM_CLASS_FILE {
                SymbolSection::None
            } else {
                SymbolSection::Unknown
            }
        }
        index if index > 0 => SymbolSection::Section(SectionIndex(index as usize - 1)),
        _ => SymbolSection::Unknown,
    };
    let weak = symbol.storage_class == pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL;
    let scope = match symbol.storage_class {
        _ if section == SymbolSection::Undefined => SymbolScope::Unknown,
        pe::IMAGE_SYM_CLASS_EXTERNAL
        | pe::IMAGE_SYM_CLASS_EXTERNAL_DEF
        | pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL => {
            // TODO: determine if symbol is exported
            SymbolScope::Linkage
        }
        _ => SymbolScope::Compilation,
    };
    Symbol {
        name,
        address,
        size,
        kind,
        section,
        weak,
        scope,
        flags,
    }
}

/// An iterator over the relocations in a `CoffSection`.
pub struct CoffRelocationIterator<'data, 'file> {
    file: &'file CoffFile<'data>,
    iter: slice::Iter<'data, pe::ImageRelocation>,
}

impl<'data, 'file> Iterator for CoffRelocationIterator<'data, 'file> {
    type Item = (u64, Relocation);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|relocation| {
            let (kind, size, addend) = match self.file.header.machine.get(LE) {
                pe::IMAGE_FILE_MACHINE_I386 => match relocation.typ.get(LE) {
                    pe::IMAGE_REL_I386_DIR16 => (RelocationKind::Absolute, 16, 0),
                    pe::IMAGE_REL_I386_REL16 => (RelocationKind::Relative, 16, 0),
                    pe::IMAGE_REL_I386_DIR32 => (RelocationKind::Absolute, 32, 0),
                    pe::IMAGE_REL_I386_DIR32NB => (RelocationKind::ImageOffset, 32, 0),
                    pe::IMAGE_REL_I386_SECTION => (RelocationKind::SectionIndex, 16, 0),
                    pe::IMAGE_REL_I386_SECREL => (RelocationKind::SectionOffset, 32, 0),
                    pe::IMAGE_REL_I386_SECREL7 => (RelocationKind::SectionOffset, 7, 0),
                    pe::IMAGE_REL_I386_REL32 => (RelocationKind::Relative, 32, -4),
                    typ => (RelocationKind::Coff(typ), 0, 0),
                },
                pe::IMAGE_FILE_MACHINE_AMD64 => match relocation.typ.get(LE) {
                    pe::IMAGE_REL_AMD64_ADDR64 => (RelocationKind::Absolute, 64, 0),
                    pe::IMAGE_REL_AMD64_ADDR32 => (RelocationKind::Absolute, 32, 0),
                    pe::IMAGE_REL_AMD64_ADDR32NB => (RelocationKind::ImageOffset, 32, 0),
                    pe::IMAGE_REL_AMD64_REL32 => (RelocationKind::Relative, 32, -4),
                    pe::IMAGE_REL_AMD64_REL32_1 => (RelocationKind::Relative, 32, -5),
                    pe::IMAGE_REL_AMD64_REL32_2 => (RelocationKind::Relative, 32, -6),
                    pe::IMAGE_REL_AMD64_REL32_3 => (RelocationKind::Relative, 32, -7),
                    pe::IMAGE_REL_AMD64_REL32_4 => (RelocationKind::Relative, 32, -8),
                    pe::IMAGE_REL_AMD64_REL32_5 => (RelocationKind::Relative, 32, -9),
                    pe::IMAGE_REL_AMD64_SECTION => (RelocationKind::SectionIndex, 16, 0),
                    pe::IMAGE_REL_AMD64_SECREL => (RelocationKind::SectionOffset, 32, 0),
                    pe::IMAGE_REL_AMD64_SECREL7 => (RelocationKind::SectionOffset, 7, 0),
                    typ => (RelocationKind::Coff(typ), 0, 0),
                },
                _ => (RelocationKind::Coff(relocation.typ.get(LE)), 0, 0),
            };
            let target = RelocationTarget::Symbol(SymbolIndex(
                relocation.symbol_table_index.get(LE) as usize,
            ));
            (
                u64::from(relocation.virtual_address.get(LE)),
                Relocation {
                    kind,
                    encoding: RelocationEncoding::Generic,
                    size,
                    target,
                    addend,
                    implicit_addend: true,
                },
            )
        })
    }
}

impl<'data, 'file> fmt::Debug for CoffRelocationIterator<'data, 'file> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoffRelocationIterator").finish()
    }
}

impl pe::ImageSectionHeader {
    fn coff_file_range(&self) -> Option<(u32, u32)> {
        if self.characteristics.get(LE) & pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
            None
        } else {
            let offset = self.pointer_to_raw_data.get(LE);
            // Note: virtual size is not used for COFF.
            let size = self.size_of_raw_data.get(LE);
            Some((offset, size))
        }
    }

    fn coff_bytes<'data>(&self, data: Bytes<'data>) -> Option<Bytes<'data>> {
        let (offset, size) = self.coff_file_range()?;
        data.read_bytes_at(offset as usize, size as usize)
    }

    pub(crate) fn name<'data>(&'data self, strings: StringTable<'data>) -> Option<&'data str> {
        let bytes = &self.name;
        let name = if bytes[0] == b'/' {
            let mut offset = 0;
            if bytes[1] == b'/' {
                for byte in bytes[2..].iter() {
                    let digit = match byte {
                        b'A'..=b'Z' => byte - b'A',
                        b'a'..=b'z' => byte - b'a' + 26,
                        b'0'..=b'9' => byte - b'0' + 52,
                        b'+' => 62,
                        b'/' => 63,
                        _ => return None,
                    };
                    offset = offset * 64 + digit as u32;
                }
            } else {
                for byte in bytes[1..].iter() {
                    let digit = match byte {
                        b'0'..=b'9' => byte - b'0',
                        0 => break,
                        _ => return None,
                    };
                    offset = offset * 10 + digit as u32;
                }
            };
            strings.get(offset)?
        } else {
            match bytes.iter().position(|&x| x == 0) {
                Some(end) => &bytes[..end],
                None => &bytes[..],
            }
        };
        str::from_utf8(name).ok()
    }

    pub(crate) fn kind(&self) -> SectionKind {
        let characteristics = self.characteristics.get(LE);
        if characteristics & (pe::IMAGE_SCN_CNT_CODE | pe::IMAGE_SCN_MEM_EXECUTE) != 0 {
            SectionKind::Text
        } else if characteristics & pe::IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
            if characteristics & pe::IMAGE_SCN_MEM_DISCARDABLE != 0 {
                SectionKind::Other
            } else if characteristics & pe::IMAGE_SCN_MEM_WRITE != 0 {
                SectionKind::Data
            } else {
                SectionKind::ReadOnlyData
            }
        } else if characteristics & pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
            SectionKind::UninitializedData
        } else if characteristics & pe::IMAGE_SCN_LNK_INFO != 0 {
            SectionKind::Linker
        } else {
            SectionKind::Unknown
        }
    }

    fn coff_alignment(&self) -> u64 {
        match self.characteristics.get(LE) & pe::IMAGE_SCN_ALIGN_MASK {
            pe::IMAGE_SCN_ALIGN_1BYTES => 1,
            pe::IMAGE_SCN_ALIGN_2BYTES => 2,
            pe::IMAGE_SCN_ALIGN_4BYTES => 4,
            pe::IMAGE_SCN_ALIGN_8BYTES => 8,
            pe::IMAGE_SCN_ALIGN_16BYTES => 16,
            pe::IMAGE_SCN_ALIGN_32BYTES => 32,
            pe::IMAGE_SCN_ALIGN_64BYTES => 64,
            pe::IMAGE_SCN_ALIGN_128BYTES => 128,
            pe::IMAGE_SCN_ALIGN_256BYTES => 256,
            pe::IMAGE_SCN_ALIGN_512BYTES => 512,
            pe::IMAGE_SCN_ALIGN_1024BYTES => 1024,
            pe::IMAGE_SCN_ALIGN_2048BYTES => 2048,
            pe::IMAGE_SCN_ALIGN_4096BYTES => 4096,
            pe::IMAGE_SCN_ALIGN_8192BYTES => 8192,
            _ => 16,
        }
    }
}

#[derive(Debug)]
pub(crate) struct SymbolTable<'data> {
    pub symbols: &'data [pe::ImageSymbolBytes],
    pub strings: StringTable<'data>,
}

impl<'data> SymbolTable<'data> {
    pub fn parse(
        header: &pe::ImageFileHeader,
        mut data: Bytes<'data>,
    ) -> Result<Self, &'static str> {
        // The symbol table may not be present.
        let symbol_offset = header.pointer_to_symbol_table.get(LE) as usize;
        let (symbols, strings) = if symbol_offset != 0 {
            data.skip(symbol_offset)
                .ok_or("Invalid symbol table offset")?;
            let symbols = data
                .read_slice(header.number_of_symbols.get(LE) as usize)
                .ok_or("Invalid symbol table size")?;

            // Note: don't update data when reading length; the length includes itself.
            let length = data
                .read_at::<U32Bytes<_>>(0)
                .ok_or("Missing string table")?
                .get(LE);
            let strings = data
                .read_bytes(length as usize)
                .ok_or("Invalid string table length")?;

            (symbols, strings)
        } else {
            (&[][..], Bytes(&[]))
        };

        Ok(SymbolTable {
            symbols,
            strings: StringTable { data: strings },
        })
    }

    pub fn get<T: Pod>(&self, index: usize) -> Option<&'data T> {
        let bytes = self.symbols.get(index)?;
        Bytes(&bytes.0[..]).read()
    }
}
