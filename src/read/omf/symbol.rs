use core::str;

use crate::read::{
    self, Error, ObjectSymbol, ObjectSymbolTable, ReadRef, Result, SectionIndex, SymbolFlags,
    SymbolIndex, SymbolKind, SymbolScope, SymbolSection,
};

use super::OmfFile;

/// A symbol in an [`OmfFile`].
///
/// Most functionality is provided by the [`ObjectSymbol`] trait implementation.
#[derive(Debug, Clone)]
pub struct OmfSymbol<'data> {
    /// Symbol table index
    pub(super) index: SymbolIndex,
    /// Symbol name
    pub(super) name: &'data [u8],
    /// Symbol class (Public, External, etc.)
    pub(super) class: OmfSymbolClass,
    /// The section that defines this symbol, if any
    pub(super) section: Option<SectionIndex>,
    /// Whether this is an absolute symbol (PUBDEF with segment index 0)
    pub(super) absolute: bool,
    /// Frame number (for absolute symbols)
    pub(super) frame_number: u16,
    /// Offset within the section
    pub(super) offset: u64,
    /// Symbol size (communal length for COMDEF, section size for COMDAT)
    pub(super) size: u64,
    /// Type index (usually 0)
    pub(super) type_index: u16,
    /// Pre-computed symbol kind
    pub(super) kind: SymbolKind,
}

/// The kind of OMF record that defined a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OmfSymbolClass {
    /// Public symbol (PUBDEF)
    Public,
    /// Local public symbol (LPUBDEF)
    LocalPublic,
    /// External symbol (EXTDEF)
    External,
    /// Local external symbol (LEXTDEF)
    LocalExternal,
    /// Communal symbol (COMDEF)
    Communal,
    /// Local communal symbol (LCOMDEF)
    LocalCommunal,
    /// COMDAT external symbol (CEXTDEF)
    ComdatExternal,
    /// COMDAT symbol (COMDAT)
    Comdat,
    /// Local COMDAT symbol (COMDAT with the local flag)
    LocalComdat,
}

impl<'data> OmfSymbol<'data> {
    /// Get the symbol class, which corresponds to the kind of OMF record
    /// that defined the symbol.
    pub fn class(&self) -> OmfSymbolClass {
        self.class
    }

    /// Get the type index.
    pub fn type_index(&self) -> u16 {
        self.type_index
    }

    /// Get the frame number for absolute symbols.
    pub fn frame_number(&self) -> u16 {
        self.frame_number
    }
}

impl<'data> read::private::Sealed for OmfSymbol<'data> {}

impl<'data> ObjectSymbol<'data> for OmfSymbol<'data> {
    fn index(&self) -> SymbolIndex {
        self.index
    }

    fn name_bytes(&self) -> Result<&'data [u8]> {
        Ok(self.name)
    }

    fn name(&self) -> Result<&'data str> {
        str::from_utf8(self.name).map_err(|_| Error("Invalid UTF-8 in OMF symbol name"))
    }

    fn address(&self) -> u64 {
        if self.absolute {
            // For absolute symbols, compute the linear address from frame:offset.
            // Frame number is in paragraphs (16-byte units).
            ((self.frame_number as u64) << 4) + self.offset
        } else {
            self.offset
        }
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn kind(&self) -> SymbolKind {
        self.kind
    }

    fn section(&self) -> SymbolSection {
        if let Some(section) = self.section {
            SymbolSection::Section(section)
        } else if self.absolute {
            SymbolSection::Absolute
        } else if self.is_common() {
            SymbolSection::Common
        } else {
            SymbolSection::Undefined
        }
    }

    fn is_undefined(&self) -> bool {
        matches!(
            self.class,
            OmfSymbolClass::External
                | OmfSymbolClass::LocalExternal
                | OmfSymbolClass::ComdatExternal
        )
    }

    fn is_definition(&self) -> bool {
        self.section.is_some() || self.absolute
    }

    fn is_common(&self) -> bool {
        // Borland communal symbols with a virtual segment are defined in a
        // section, so they are not common.
        matches!(
            self.class,
            OmfSymbolClass::Communal | OmfSymbolClass::LocalCommunal
        ) && self.section.is_none()
    }

    fn is_weak(&self) -> bool {
        false
    }

    fn scope(&self) -> SymbolScope {
        match self.class {
            OmfSymbolClass::LocalPublic
            | OmfSymbolClass::LocalExternal
            | OmfSymbolClass::LocalCommunal
            | OmfSymbolClass::LocalComdat => SymbolScope::Compilation,
            OmfSymbolClass::Public | OmfSymbolClass::Communal | OmfSymbolClass::Comdat => {
                SymbolScope::Linkage
            }
            OmfSymbolClass::External | OmfSymbolClass::ComdatExternal => SymbolScope::Unknown,
        }
    }

    fn is_global(&self) -> bool {
        !self.is_local()
    }

    fn is_local(&self) -> bool {
        matches!(
            self.class,
            OmfSymbolClass::LocalPublic
                | OmfSymbolClass::LocalExternal
                | OmfSymbolClass::LocalCommunal
                | OmfSymbolClass::LocalComdat
        )
    }

    fn flags(&self) -> SymbolFlags<SectionIndex, SymbolIndex> {
        SymbolFlags::None
    }
}

/// An iterator for the symbols in an [`OmfFile`].
#[derive(Debug)]
pub struct OmfSymbolIterator<'data, 'file, R: ReadRef<'data> = &'data [u8]> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) index: usize,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfSymbolIterator<'data, 'file, R> {
    type Item = OmfSymbol<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        let symbol = self.file.symbols.get(self.index)?.clone();
        self.index += 1;
        Some(symbol)
    }
}

/// A symbol table in an [`OmfFile`].
#[derive(Debug)]
pub struct OmfSymbolTable<'data, 'file, R: ReadRef<'data>> {
    pub(super) file: &'file OmfFile<'data, R>,
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for OmfSymbolTable<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectSymbolTable<'data> for OmfSymbolTable<'data, 'file, R> {
    type Symbol = OmfSymbol<'data>;
    type SymbolIterator = OmfSymbolIterator<'data, 'file, R>;

    fn symbols(&self) -> Self::SymbolIterator {
        OmfSymbolIterator {
            file: self.file,
            index: 0,
        }
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> Result<Self::Symbol> {
        self.file
            .symbols
            .get(index.0)
            .cloned()
            .ok_or(Error("Symbol index out of bounds"))
    }
}
