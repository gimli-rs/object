use core::fmt::Debug;

use alloc::vec::Vec;

use crate::read::{self, Error, NoDynamicRelocationIterator, Object, ReadError, ReadRef, Result};

use crate::{
    xcoff, Architecture, BigEndian as BE, ObjectKind, ObjectSection, Pod, SectionIndex, SymbolIndex, FileFlags,
};

use super::{
    Rel, SectionHeader, SectionTable, Symbol, SymbolTable, XcoffComdat, XcoffComdatIterator,
    XcoffSection, XcoffSectionIterator, XcoffSegment, XcoffSegmentIterator, XcoffSymbol,
    XcoffSymbolIterator, XcoffSymbolTable,
};

/// A 32-bit XCOFF object file.
pub type XcoffFile32<'data, R = &'data [u8]> = XcoffFile<'data, xcoff::FileHeader32, R>;
/// A 64-bit XCOFF object file.
pub type XcoffFile64<'data, R = &'data [u8]> = XcoffFile<'data, xcoff::FileHeader64, R>;

/// A partially parsed XCOFF file.
///
/// Most of the functionality of this type is provided by the `Object` trait implementation.
#[derive(Debug)]
pub struct XcoffFile<'data, Xcoff, R = &'data [u8]>
where
    Xcoff: FileHeader,
    R: ReadRef<'data>,
{
    pub(super) data: R,
    pub(super) header: &'data Xcoff,
    pub(super) sections: SectionTable<'data, Xcoff>,
    pub(super) symbols: SymbolTable<'data, Xcoff, R>,
}

impl<'data, Xcoff, R> XcoffFile<'data, Xcoff, R>
where
    Xcoff: FileHeader,
    R: ReadRef<'data>,
{
    /// Parse the raw XCOFF file data.
    pub fn parse(data: R) -> Result<Self> {
        let mut offset = 0;
        let header = Xcoff::parse(data, &mut offset)?;
        let sections = header.sections(data, &mut offset)?;
        let symbols = header.symbols(data)?;
        Ok(XcoffFile {
            data,
            header,
            sections,
            symbols,
        })
    }

    /// Returns the raw data.
    pub fn data(&self) -> R {
        self.data
    }

    /// Returns the raw XCOFF file header.
    pub fn raw_header(&self) -> &'data Xcoff {
        self.header
    }
}

impl<'data, Xcoff, R> read::private::Sealed for XcoffFile<'data, Xcoff, R>
where
    Xcoff: FileHeader,
    R: ReadRef<'data>,
{
}

impl<'data, 'file, Xcoff, R> Object<'data, 'file> for XcoffFile<'data, Xcoff, R>
where
    'data: 'file,
    Xcoff: FileHeader,
    R: 'file + ReadRef<'data>,
{
    type Segment = XcoffSegment<'data, 'file, Xcoff, R>;
    type SegmentIterator = XcoffSegmentIterator<'data, 'file, Xcoff, R>;
    type Section = XcoffSection<'data, 'file, Xcoff, R>;
    type SectionIterator = XcoffSectionIterator<'data, 'file, Xcoff, R>;
    type Comdat = XcoffComdat<'data, 'file, Xcoff, R>;
    type ComdatIterator = XcoffComdatIterator<'data, 'file, Xcoff, R>;
    type Symbol = XcoffSymbol<'data, 'file, Xcoff, R>;
    type SymbolIterator = XcoffSymbolIterator<'data, 'file, Xcoff, R>;
    type SymbolTable = XcoffSymbolTable<'data, 'file, Xcoff, R>;
    type DynamicRelocationIterator = NoDynamicRelocationIterator;

    fn architecture(&self) -> crate::Architecture {
        if self.is_64() {
            Architecture::PowerPc64
        } else {
            Architecture::PowerPc
        }
    }

    fn is_little_endian(&self) -> bool {
        false
    }

    fn is_64(&self) -> bool {
        self.header.is_type_64()
    }

    fn kind(&self) -> ObjectKind {
        ObjectKind::Relocatable
    }

    fn segments(&'file self) -> XcoffSegmentIterator<'data, 'file, Xcoff, R> {
        unreachable!()
    }

    fn section_by_name_bytes(
        &'file self,
        section_name: &[u8],
    ) -> Option<XcoffSection<'data, 'file, Xcoff, R>> {
        self.sections()
            .find(|section| section.name_bytes() == Ok(section_name))
    }

    fn section_by_index(
        &'file self,
        index: SectionIndex,
    ) -> read::Result<XcoffSection<'data, 'file, Xcoff, R>> {
        let section = self.sections.section(index)?;
        Ok(XcoffSection {
            file: self,
            section,
            index,
        })
    }

    fn sections(&'file self) -> XcoffSectionIterator<'data, 'file, Xcoff, R> {
        XcoffSectionIterator {
            file: self,
            iter: self.sections.iter().enumerate(),
        }
    }

    fn comdats(&'file self) -> XcoffComdatIterator<'data, 'file, Xcoff, R> {
        unreachable!();
    }

    fn symbol_table(&'file self) -> Option<XcoffSymbolTable<'data, 'file, Xcoff, R>> {
        if self.symbols.is_empty() {
            return None;
        }
        Some(XcoffSymbolTable {
            symbols: &self.symbols,
            file: self,
        })
    }

    fn symbol_by_index(
        &'file self,
        index: SymbolIndex,
    ) -> read::Result<XcoffSymbol<'data, 'file, Xcoff, R>> {
        let symbol = self.symbols.symbol(index.0)?;
        Ok(XcoffSymbol {
            symbols: &self.symbols,
            index,
            symbol,
            file: self,
        })
    }

    fn symbols(&'file self) -> XcoffSymbolIterator<'data, 'file, Xcoff, R> {
        XcoffSymbolIterator {
            symbols: &self.symbols,
            index: 0,
            file: self,
        }
    }

    fn dynamic_symbol_table(&'file self) -> Option<XcoffSymbolTable<'data, 'file, Xcoff, R>> {
        None
    }

    fn dynamic_symbols(&'file self) -> XcoffSymbolIterator<'data, 'file, Xcoff, R> {
        XcoffSymbolIterator {
            file: self,
            symbols: &self.symbols,
            // Hack: don't return any.
            index: self.symbols.len(),
        }
    }

    fn dynamic_relocations(&'file self) -> Option<Self::DynamicRelocationIterator> {
        None
    }

    fn imports(&self) -> Result<alloc::vec::Vec<crate::Import<'data>>> {
        // TODO: not needed yet.
        Ok(Vec::new())
    }

    fn exports(&self) -> Result<alloc::vec::Vec<crate::Export<'data>>> {
        // TODO: not needed yet.
        Ok(Vec::new())
    }

    fn has_debug_symbols(&self) -> bool {
        self.section_by_name(".debug").is_some() || self.section_by_name(".dw").is_some()
    }

    fn relative_address_base(&'file self) -> u64 {
        0
    }

    fn entry(&'file self) -> u64 {
        // TODO: get from the auxiliary file header.
        0
    }

    fn flags(&self) -> FileFlags {
        FileFlags::Xcoff {
            f_flags: self.header.f_flags()
        }
    }
}

/// A trait for generic access to `FileHeader32` and `FileHeader64`.
#[allow(missing_docs)]
pub trait FileHeader: Debug + Pod {
    type Word: Into<u64>;
    type AuxHeader: AuxHeader<Word = Self::Word>;
    type SectionHeader: SectionHeader<Word = Self::Word>;
    type Symbol: Symbol<Word = Self::Word>;
    type Rel: Rel<Word = Self::Word>;

    /// Return true if this type is a 64-bit header.
    fn is_type_64(&self) -> bool;

    fn f_magic(&self) -> u16;
    fn f_nscns(&self) -> u16;
    fn f_timdat(&self) -> u32;
    fn f_symptr(&self) -> Self::Word;
    fn f_nsyms(&self) -> u32;
    fn f_opthdr(&self) -> u16;
    fn f_flags(&self) -> u16;

    // Provided methods.

    /// Read the file header.
    ///
    /// Also checks that the magic field in the file header is a supported format.
    fn parse<'data, R: ReadRef<'data>>(data: R, offset: &mut u64) -> read::Result<&'data Self> {
        let header = data
            .read::<Self>(offset)
            .read_error("Invalid XCOFF header size or alignment")?;
        if !header.is_supported() {
            return Err(Error("Unsupported XCOFF header"));
        }
        Ok(header)
    }

    /// TODO: currently only 64-bit is supported.
    fn is_supported(&self) -> bool {
        self.is_type_64()
    }

    /// Return the slice of auxiliary header.
    ///
    /// `data` must be the entire file data.
    /// `offset` must be after the file header.
    fn aux_headers<'data, R: ReadRef<'data>>(
        &self,
        data: R,
        offset: &mut u64,
    ) -> read::Result<&'data [Self::AuxHeader]> {
        let total_len = self.f_opthdr() as usize;
        let single_len = std::mem::size_of::<Self::AuxHeader>();
        if total_len % single_len != 0 {
            return Err(Error("Invalid aux header length"));
        }
        data.read_slice(offset, total_len / single_len)
            .read_error("Invalid XCOFF aux header offset/size/alignment")
    }

    /// Read the section table.
    #[inline]
    fn sections<'data, R: ReadRef<'data>>(
        &self,
        data: R,
        offset: &mut u64,
    ) -> Result<SectionTable<'data, Self>> {
        SectionTable::parse(*self, data, offset)
    }

    /// Return the symbol table.
    #[inline]
    fn symbols<'data, R: ReadRef<'data>>(&self, data: R) -> Result<SymbolTable<'data, Self, R>> {
        SymbolTable::parse(*self, data)
    }
}

impl FileHeader for xcoff::FileHeader32 {
    type Word = u32;
    type AuxHeader = xcoff::AuxHeader32;
    type SectionHeader = xcoff::SectionHeader32;
    type Symbol = xcoff::Symbol32;
    type Rel = xcoff::Rel32;

    fn is_type_64(&self) -> bool {
        false
    }

    fn f_magic(&self) -> u16 {
        self.f_magic.get(BE)
    }

    fn f_nscns(&self) -> u16 {
        self.f_nscns.get(BE)
    }

    fn f_timdat(&self) -> u32 {
        self.f_timdat.get(BE)
    }

    fn f_symptr(&self) -> Self::Word {
        self.f_symptr.get(BE)
    }

    fn f_nsyms(&self) -> u32 {
        self.f_nsyms.get(BE)
    }

    fn f_opthdr(&self) -> u16 {
        self.f_opthdr.get(BE)
    }

    fn f_flags(&self) -> u16 {
        self.f_flags.get(BE)
    }
}

impl FileHeader for xcoff::FileHeader64 {
    type Word = u64;
    type AuxHeader = xcoff::AuxHeader64;
    type SectionHeader = xcoff::SectionHeader64;
    type Symbol = xcoff::Symbol64;
    type Rel = xcoff::Rel64;

    fn is_type_64(&self) -> bool {
        true
    }

    fn f_magic(&self) -> u16 {
        self.f_magic.get(BE)
    }

    fn f_nscns(&self) -> u16 {
        self.f_nscns.get(BE)
    }

    fn f_timdat(&self) -> u32 {
        self.f_timdat.get(BE)
    }

    fn f_symptr(&self) -> Self::Word {
        self.f_symptr.get(BE)
    }

    fn f_nsyms(&self) -> u32 {
        self.f_nsyms.get(BE)
    }

    fn f_opthdr(&self) -> u16 {
        self.f_opthdr.get(BE)
    }

    fn f_flags(&self) -> u16 {
        self.f_flags.get(BE)
    }
}

#[allow(missing_docs)]
pub trait AuxHeader: Debug + Pod {
    type Word: Into<u64>;
}

impl AuxHeader for xcoff::AuxHeader32 {
    type Word = u32;
}

impl AuxHeader for xcoff::AuxHeader64 {
    type Word = u64;
}
