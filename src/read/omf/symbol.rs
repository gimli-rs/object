//! OMF symbol implementation.

use core::str;

use crate::read::{
    self, ObjectSymbol, ObjectSymbolTable, ReadRef, Result, SectionIndex, SymbolFlags, SymbolIndex,
    SymbolKind, SymbolScope, SymbolSection,
};
use crate::Error;

use super::{OmfFile, OmfSymbol};

impl<'data> read::private::Sealed for OmfSymbol<'data> {}

impl<'data> ObjectSymbol<'data> for OmfSymbol<'data> {
    fn index(&self) -> SymbolIndex {
        SymbolIndex(self.symbol_index)
    }

    fn name_bytes(&self) -> Result<&'data [u8]> {
        Ok(self.name)
    }

    fn name(&self) -> Result<&'data str> {
        core::str::from_utf8(self.name).map_err(|_| Error("Invalid UTF-8 in OMF symbol name"))
    }

    fn address(&self) -> u64 {
        if self.segment_index == 0 && self.frame_number != 0 {
            // For absolute symbols, compute the linear address from frame:offset
            // Frame number is in paragraphs (16-byte units)
            ((self.frame_number as u64) << 4) + (self.offset as u64)
        } else {
            self.offset as u64
        }
    }

    fn size(&self) -> u64 {
        0 // OMF doesn't store symbol sizes
    }

    fn kind(&self) -> SymbolKind {
        self.kind
    }

    fn section(&self) -> SymbolSection {
        if self.segment_index == 0 {
            if self.frame_number != 0 {
                SymbolSection::Absolute
            } else {
                SymbolSection::Undefined
            }
        } else {
            SymbolSection::Section(SectionIndex(self.segment_index as usize))
        }
    }

    fn is_undefined(&self) -> bool {
        self.segment_index == 0 && self.frame_number == 0
    }

    fn is_definition(&self) -> bool {
        self.segment_index != 0 || self.frame_number != 0
    }

    fn is_common(&self) -> bool {
        matches!(
            self.class,
            super::OmfSymbolClass::Communal | super::OmfSymbolClass::LocalCommunal
        )
    }

    fn is_weak(&self) -> bool {
        false
    }

    fn scope(&self) -> SymbolScope {
        match self.class {
            super::OmfSymbolClass::LocalPublic
            | super::OmfSymbolClass::LocalExternal
            | super::OmfSymbolClass::LocalCommunal => SymbolScope::Compilation,
            super::OmfSymbolClass::Public
            | super::OmfSymbolClass::External
            | super::OmfSymbolClass::Communal
            | super::OmfSymbolClass::ComdatExternal => {
                if self.segment_index == 0 {
                    SymbolScope::Unknown
                } else {
                    SymbolScope::Linkage
                }
            }
        }
    }

    fn is_global(&self) -> bool {
        !self.is_local()
    }

    fn is_local(&self) -> bool {
        matches!(
            self.class,
            super::OmfSymbolClass::LocalPublic
                | super::OmfSymbolClass::LocalExternal
                | super::OmfSymbolClass::LocalCommunal
        )
    }

    fn flags(&self) -> SymbolFlags<SectionIndex, SymbolIndex> {
        SymbolFlags::None
    }
}

/// An iterator over OMF symbols.
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

/// An OMF symbol table.
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
