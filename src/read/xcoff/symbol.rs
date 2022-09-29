use alloc::fmt;
use core::fmt::Debug;
use core::str;

use crate::endian::{BigEndian as BE, U32Bytes};
use crate::pod::Pod;
use crate::read::util::StringTable;
use crate::{xcoff, Object};

use crate::read::{
    self, ObjectSymbol, ObjectSymbolTable, ReadError, ReadRef, Result, SectionIndex, SymbolFlags,
    SymbolIndex, SymbolKind, SymbolScope, SymbolSection,
};

use super::{FileHeader, XcoffFile};

/// A table of symbol entries in an XCOFF file.
///
/// Also includes the string table used for the symbol names.
#[derive(Debug)]
pub struct SymbolTable<'data, Xcoff, R = &'data [u8]>
where
    Xcoff: FileHeader,
    R: ReadRef<'data>,
{
    symbols: &'data [Xcoff::Symbol],
    strings: StringTable<'data, R>,
}

impl<'data, Xcoff, R> Default for SymbolTable<'data, Xcoff, R>
where
    Xcoff: FileHeader,
    R: ReadRef<'data>,
{
    fn default() -> Self {
        Self {
            symbols: &[],
            strings: StringTable::default(),
        }
    }
}

impl<'data, Xcoff, R> SymbolTable<'data, Xcoff, R>
where
    Xcoff: FileHeader,
    R: ReadRef<'data>,
{
    /// Parse the symbol table.
    pub fn parse(header: Xcoff, data: R) -> Result<Self> {
        let mut offset = header.f_symptr().into();
        let (symbols, strings) = if offset != 0 {
            let symbols = data
                .read_slice(&mut offset, header.f_nsyms() as usize)
                .read_error("Invalid XCOFF symbol table offset or size")?;

            // Parse the string table.
            // Note: don't update data when reading length; the length includes itself.
            let length = data
                .read_at::<U32Bytes<_>>(offset)
                .read_error("Missing XCOFF string table")?
                .get(BE);
            let str_end = offset
                .checked_add(length as u64)
                .read_error("Invalid XCOFF string table length")?;
            let strings = StringTable::new(data, offset, str_end);

            (symbols, strings)
        } else {
            (&[][..], StringTable::default())
        };

        Ok(SymbolTable { symbols, strings })
    }

    /// Return the symbol at the given index.
    pub fn symbol(&self, index: usize) -> read::Result<&'data Xcoff::Symbol> {
        self.symbols
            .get(index)
            .read_error("Invalid ELF symbol index")
    }

    /// Return true if the symbol table is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// The number of symbol table entries.
    ///
    /// This includes auxiliary symbol table entries.
    #[inline]
    pub fn len(&self) -> usize {
        self.symbols.len()
    }
}

/// A symbol table of an `XcoffFile32`.
pub type XcoffSymbolTable32<'data, 'file, R = &'data [u8]> =
    XcoffSymbolTable<'data, 'file, xcoff::FileHeader32, R>;
/// A symbol table of an `XcoffFile64`.
pub type XcoffSymbolTable64<'data, 'file, R = &'data [u8]> =
    XcoffSymbolTable<'data, 'file, xcoff::FileHeader64, R>;

/// A symbol table of an `XcoffFile`.
#[derive(Debug, Clone, Copy)]
pub struct XcoffSymbolTable<'data, 'file, Xcoff, R = &'data [u8]>
where
    'data: 'file,
    Xcoff: FileHeader,
    R: ReadRef<'data>,
{
    pub(crate) file: &'file XcoffFile<'data, Xcoff, R>,
    pub(super) symbols: &'file SymbolTable<'data, Xcoff, R>,
}

impl<'data, 'file, Xcoff: FileHeader, R: ReadRef<'data>> read::private::Sealed
    for XcoffSymbolTable<'data, 'file, Xcoff, R>
{
}

impl<'data, 'file, Xcoff: FileHeader, R: ReadRef<'data>> ObjectSymbolTable<'data>
    for XcoffSymbolTable<'data, 'file, Xcoff, R>
{
    type Symbol = XcoffSymbol<'data, 'file, Xcoff, R>;
    type SymbolIterator = XcoffSymbolIterator<'data, 'file, Xcoff, R>;

    fn symbols(&self) -> Self::SymbolIterator {
        XcoffSymbolIterator {
            file: self.file,
            symbols: self.symbols,
            index: 0,
        }
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> read::Result<Self::Symbol> {
        let symbol = self.symbols.symbol(index.0)?;
        Ok(XcoffSymbol {
            file: self.file,
            symbols: self.symbols,
            index,
            symbol,
        })
    }
}

/// An iterator over the symbols of an `XcoffFile32`.
pub type XcoffSymbolIterator32<'data, 'file, R = &'data [u8]> =
    XcoffSymbolIterator<'data, 'file, xcoff::FileHeader32, R>;
/// An iterator over the symbols of an `XcoffFile64`.
pub type XcoffSymbolIterator64<'data, 'file, R = &'data [u8]> =
    XcoffSymbolIterator<'data, 'file, xcoff::FileHeader64, R>;

/// An iterator over the symbols of an `XcoffFile`.
pub struct XcoffSymbolIterator<'data, 'file, Xcoff, R = &'data [u8]>
where
    'data: 'file,
    Xcoff: FileHeader,
    R: ReadRef<'data>,
{
    pub(crate) file: &'file XcoffFile<'data, Xcoff, R>,
    pub(super) symbols: &'file SymbolTable<'data, Xcoff, R>,
    pub(super) index: usize,
}

impl<'data, 'file, Xcoff: FileHeader, R: ReadRef<'data>> fmt::Debug
    for XcoffSymbolIterator<'data, 'file, Xcoff, R>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XcoffSymbolIterator").finish()
    }
}

impl<'data, 'file, Xcoff: FileHeader, R: ReadRef<'data>> Iterator
    for XcoffSymbolIterator<'data, 'file, Xcoff, R>
{
    type Item = XcoffSymbol<'data, 'file, Xcoff, R>;

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.index;
        let symbol = self.symbols.symbols.get(index)?;
        self.index += 1;
        Some(XcoffSymbol {
            file: self.file,
            symbols: self.symbols,
            index: SymbolIndex(index),
            symbol,
        })
    }
}

/// A symbol of an `XcoffFile32`.
pub type XcoffSymbol32<'data, 'file, R = &'data [u8]> =
    XcoffSymbol<'data, 'file, xcoff::FileHeader32, R>;
/// A symbol of an `XcoffFile64`.
pub type XcoffSymbol64<'data, 'file, R = &'data [u8]> =
    XcoffSymbol<'data, 'file, xcoff::FileHeader64, R>;

/// A symbol of an `XcoffFile`.
#[derive(Debug, Clone, Copy)]
pub struct XcoffSymbol<'data, 'file, Xcoff, R = &'data [u8]>
where
    'data: 'file,
    Xcoff: FileHeader,
    R: ReadRef<'data>,
{
    pub(crate) file: &'file XcoffFile<'data, Xcoff, R>,
    pub(super) symbols: &'file SymbolTable<'data, Xcoff, R>,
    pub(super) index: SymbolIndex,
    pub(super) symbol: &'data Xcoff::Symbol,
}

impl<'data, 'file, Xcoff: FileHeader, R: ReadRef<'data>> read::private::Sealed
    for XcoffSymbol<'data, 'file, Xcoff, R>
{
}

impl<'data, 'file, Xcoff: FileHeader, R: ReadRef<'data>> ObjectSymbol<'data>
    for XcoffSymbol<'data, 'file, Xcoff, R>
{
    #[inline]
    fn index(&self) -> SymbolIndex {
        self.index
    }

    fn name_bytes(&self) -> Result<&'data [u8]> {
        self.symbol.name(self.symbols.strings)
    }

    fn name(&self) -> Result<&'data str> {
        let name = self.name_bytes()?;
        str::from_utf8(name)
            .ok()
            .read_error("Non UTF-8 ELF symbol name")
    }

    #[inline]
    fn address(&self) -> u64 {
        return self.symbol.n_value().into();
    }

    #[inline]
    fn size(&self) -> u64 {
        // TODO: get the symbol size when the csect auxiliary symbol is supported.
        // Most symbols don't have sizes.
        0
    }

    fn kind(&self) -> SymbolKind {
        let section = self
            .file
            .section_by_index(SectionIndex(self.symbol.n_scnum() as usize))
            .unwrap();
        let derived_kind = if section.is_section_text() {
            SymbolKind::Text
        } else if section.is_section_data() || section.is_section_bss() {
            SymbolKind::Data
        } else {
            SymbolKind::Unknown
        };

        match self.symbol.n_sclass() {
            xcoff::C_FILE => SymbolKind::File,
            xcoff::C_NULL => SymbolKind::Null,
            xcoff::C_GTLS | xcoff::C_STTLS => SymbolKind::Tls,
            xcoff::C_DWARF => SymbolKind::Section,
            _ => derived_kind,
        }
    }

    fn section(&self) -> SymbolSection {
        // Section number in XCOFF is 1-based index.
        // We treat SectionIndex internally 0-based index.
        let index = self.symbol.n_scnum() - 1;
        SymbolSection::Section(SectionIndex(index as usize))
    }

    #[inline]
    fn is_undefined(&self) -> bool {
        self.symbol.is_undefined()
    }

    #[inline]
    fn is_definition(&self) -> bool {
        self.symbol.is_definition()
    }

    #[inline]
    fn is_common(&self) -> bool {
        self.symbol.n_sclass() == xcoff::C_EXT && self.symbol.n_scnum() == xcoff::N_UNDEF
    }

    #[inline]
    fn is_weak(&self) -> bool {
        self.symbol.n_sclass() == xcoff::C_WEAKEXT
    }

    fn scope(&self) -> SymbolScope {
        if self.symbol.n_scnum() == xcoff::N_UNDEF {
            SymbolScope::Unknown
        } else {
            match self.symbol.n_sclass() {
                xcoff::C_EXT | xcoff::C_WEAKEXT => {
                    // TODO: determine if symbol is exported
                    SymbolScope::Linkage
                }
                _ => SymbolScope::Compilation,
            }
        }
    }

    #[inline]
    fn is_global(&self) -> bool {
        match self.symbol.n_sclass() {
            xcoff::C_EXT | xcoff::C_WEAKEXT => true,
            _ => false,
        }
    }

    #[inline]
    fn is_local(&self) -> bool {
        !self.is_global()
    }

    #[inline]
    fn flags(&self) -> SymbolFlags<SectionIndex> {
        SymbolFlags::None
    }
}

/// A trait for generic access to `Symbol32` and `Symbol64`.
#[allow(missing_docs)]
pub trait Symbol: Debug + Pod {
    type Word: Into<u64>;

    fn n_value(&self) -> Self::Word;
    fn n_offset(&self) -> u32;
    fn n_scnum(&self) -> i16;
    fn n_type(&self) -> u16;
    fn n_sclass(&self) -> u8;
    fn n_numaux(&self) -> u8;

    /// Parse the symbol name from the string table.
    fn name<'data, R: ReadRef<'data>>(
        &self,
        strings: StringTable<'data, R>,
    ) -> read::Result<&'data [u8]> {
        strings
            .get(self.n_offset())
            .read_error("Invalid XCOFF symbol name offset")
    }

    /// Return true if the symbol is undefined.
    #[inline]
    fn is_undefined(&self) -> bool {
        let n_sclass = self.n_sclass();
        (n_sclass == xcoff::C_EXT || n_sclass == xcoff::C_WEAKEXT)
            && self.n_scnum() == xcoff::N_UNDEF
    }

    /// Return true if the symbol is a definition of a function or data object.
    /// TODO: get the x_smtyp value when csect auxiliary symbol is supported.
    fn is_definition(&self) -> bool {
        self.n_scnum() != xcoff::N_UNDEF
    }
}

impl Symbol for xcoff::Symbol64 {
    type Word = u64;

    fn n_value(&self) -> Self::Word {
        self.n_value.get(BE)
    }

    fn n_offset(&self) -> u32 {
        self.n_offset.get(BE)
    }

    fn n_scnum(&self) -> i16 {
        self.n_scnum.get(BE)
    }

    fn n_type(&self) -> u16 {
        self.n_type.get(BE)
    }

    fn n_sclass(&self) -> u8 {
        self.n_sclass
    }

    fn n_numaux(&self) -> u8 {
        self.n_numaux
    }
}

impl Symbol for xcoff::Symbol32 {
    type Word = u32;

    fn n_value(&self) -> Self::Word {
        self.n_value.get(BE)
    }

    fn n_offset(&self) -> u32 {
        0
    }

    fn n_scnum(&self) -> i16 {
        self.n_scnum.get(BE)
    }

    fn n_type(&self) -> u16 {
        self.n_type.get(BE)
    }

    fn n_sclass(&self) -> u8 {
        self.n_sclass
    }

    fn n_numaux(&self) -> u8 {
        self.n_numaux
    }
}
