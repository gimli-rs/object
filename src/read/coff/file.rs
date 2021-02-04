use alloc::vec::Vec;
use core::{mem, str};

use crate::read::{
    self, Architecture, Export, FileFlags, Import, NoDynamicRelocationIterator, Object,
    ObjectSection, ReadError, ReadRef, Result, SectionIndex, SymbolIndex,
};
use crate::{pe, Bytes, LittleEndian as LE};

use super::{
    CoffComdat, CoffComdatIterator, CoffSection, CoffSectionIterator, CoffSegment,
    CoffSegmentIterator, CoffSymbol, CoffSymbolIterator, CoffSymbolTable, SectionTable,
    SymbolTable,
};

/// The common parts of `PeFile` and `CoffFile`.
#[derive(Debug)]
pub(crate) struct CoffCommon<'data> {
    pub(crate) sections: SectionTable<'data>,
    // TODO: ImageSymbolExBytes
    pub(crate) symbols: SymbolTable<'data>,
    pub(crate) image_base: u64,
}

/// A COFF object file.
#[derive(Debug)]
pub struct CoffFile<'data, R: ReadRef<'data>> {
    pub(super) header: &'data pe::ImageFileHeader,
    pub(super) common: CoffCommon<'data>,
    pub(super) data: R,
}

impl<'data, R: ReadRef<'data>> CoffFile<'data, R> {
    /// Parse the raw COFF file data.
    pub fn parse(data: R) -> Result<Self> {
        let header = pe::ImageFileHeader::parse(data)?;
        let sections = header.sections(data)?;
        let symbols = header.symbols(data)?;

        Ok(CoffFile {
            header,
            common: CoffCommon {
                sections,
                symbols,
                image_base: 0,
            },
            data,
        })
    }
}

impl<'data, R: ReadRef<'data>> read::private::Sealed for CoffFile<'data, R> {}

impl<'data, 'file, R: ReadRef<'data>> Object<'data, 'file> for CoffFile<'data, R>
where
    'data: 'file,
{
    type Segment = CoffSegment<'data, 'file, R>;
    type SegmentIterator = CoffSegmentIterator<'data, 'file, R>;
    type Section = CoffSection<'data, 'file, R>;
    type SectionIterator = CoffSectionIterator<'data, 'file, R>;
    type Comdat = CoffComdat<'data, 'file, R>;
    type ComdatIterator = CoffComdatIterator<'data, 'file, R>;
    type Symbol = CoffSymbol<'data, 'file>;
    type SymbolIterator = CoffSymbolIterator<'data, 'file>;
    type SymbolTable = CoffSymbolTable<'data, 'file>;
    type DynamicRelocationIterator = NoDynamicRelocationIterator;

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
        // Windows COFF is always 32-bit, even for 64-bit architectures. This could be confusing.
        false
    }

    fn segments(&'file self) -> CoffSegmentIterator<'data, 'file, R> {
        CoffSegmentIterator {
            file: self,
            iter: self.common.sections.iter(),
        }
    }

    fn section_by_name(&'file self, section_name: &str) -> Option<CoffSection<'data, 'file, R>> {
        self.sections()
            .find(|section| section.name() == Ok(section_name))
    }

    fn section_by_index(&'file self, index: SectionIndex) -> Result<CoffSection<'data, 'file, R>> {
        let section = self.common.sections.section(index.0)?;
        Ok(CoffSection {
            file: self,
            index,
            section,
        })
    }

    fn sections(&'file self) -> CoffSectionIterator<'data, 'file, R> {
        CoffSectionIterator {
            file: self,
            iter: self.common.sections.iter().enumerate(),
        }
    }

    fn comdats(&'file self) -> CoffComdatIterator<'data, 'file, R> {
        CoffComdatIterator {
            file: self,
            index: 0,
        }
    }

    fn symbol_by_index(&'file self, index: SymbolIndex) -> Result<CoffSymbol<'data, 'file>> {
        let symbol = self.common.symbols.symbol(index.0)?;
        Ok(CoffSymbol {
            file: &self.common,
            index,
            symbol,
        })
    }

    fn symbols(&'file self) -> CoffSymbolIterator<'data, 'file> {
        CoffSymbolIterator {
            file: &self.common,
            index: 0,
        }
    }

    #[inline]
    fn symbol_table(&'file self) -> Option<CoffSymbolTable<'data, 'file>> {
        Some(CoffSymbolTable { file: &self.common })
    }

    fn dynamic_symbols(&'file self) -> CoffSymbolIterator<'data, 'file> {
        CoffSymbolIterator {
            file: &self.common,
            // Hack: don't return any.
            index: self.common.symbols.len(),
        }
    }

    #[inline]
    fn dynamic_symbol_table(&'file self) -> Option<CoffSymbolTable<'data, 'file>> {
        None
    }

    #[inline]
    fn dynamic_relocations(&'file self) -> Option<NoDynamicRelocationIterator> {
        None
    }

    #[inline]
    fn imports(&self) -> Result<Vec<Import<'data>>> {
        // TODO: this could return undefined symbols, but not needed yet.
        Ok(Vec::new())
    }

    #[inline]
    fn exports(&self) -> Result<Vec<Export<'data>>> {
        // TODO: this could return global symbols, but not needed yet.
        Ok(Vec::new())
    }

    fn has_debug_symbols(&self) -> bool {
        self.section_by_name(".debug_info").is_some()
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

impl pe::ImageFileHeader {
    /// Read the file header.
    ///
    /// The given data must be for the entire file.
    pub fn parse<'data, R: ReadRef<'data>>(data: R) -> read::Result<&'data Self> {
        data.read_at::<pe::ImageFileHeader>(0)
            .read_error("Invalid COFF file header size or alignment")
        // TODO: maybe validate that the machine is known?
    }

    /// Read the section table.
    ///
    /// `data` must be the entire file data.
    #[inline]
    pub fn sections<'data, R: ReadRef<'data>>(&self, data: R) -> read::Result<SectionTable<'data>> {
        // Skip over the optional header.
        let offset = mem::size_of::<Self>()
            .checked_add(self.size_of_optional_header.get(LE) as usize)
            .read_error("Invalid COFF optional header size")?;

        SectionTable::parse(self, data, offset)
    }

    /// Read the symbol table and string table.
    ///
    /// `data` must be the entire file data.
    #[inline]
    pub fn symbols<'data, R: ReadRef<'data>>(&self, data: R) -> read::Result<SymbolTable<'data>> {
        SymbolTable::parse(self, data)
    }
}
