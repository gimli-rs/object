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
        // Communal symbols have segment_index == 0, frame_number == 0, but offset != 0
        // The offset field stores the size of the communal symbol
        // This excludes both externals (offset == 0) and absolute symbols (frame_number != 0)
        self.segment_index == 0 && self.frame_number == 0 && self.offset != 0
    }

    fn is_weak(&self) -> bool {
        false
    }

    fn scope(&self) -> SymbolScope {
        if self.segment_index == 0 {
            SymbolScope::Unknown
        } else {
            SymbolScope::Linkage
        }
    }

    fn is_global(&self) -> bool {
        true
    }

    fn is_local(&self) -> bool {
        false
    }

    fn flags(&self) -> SymbolFlags<SectionIndex, SymbolIndex> {
        SymbolFlags::None
    }
}

/// An iterator over OMF symbols.
#[derive(Debug)]
pub struct OmfSymbolIterator<'data, 'file> {
    pub(super) publics: &'file [OmfSymbol<'data>],
    pub(super) externals: &'file [OmfSymbol<'data>],
    pub(super) communals: &'file [OmfSymbol<'data>],
    pub(super) index: usize,
}

impl<'data, 'file> Iterator for OmfSymbolIterator<'data, 'file> {
    type Item = OmfSymbol<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        let total_publics = self.publics.len();
        let total_externals = self.externals.len();
        let total_before_communals = total_publics + total_externals;
        let total = total_before_communals + self.communals.len();

        if self.index >= total {
            return None;
        }

        let symbol = if self.index < total_publics {
            self.publics[self.index].clone()
        } else if self.index < total_before_communals {
            self.externals[self.index - total_publics].clone()
        } else {
            self.communals[self.index - total_before_communals].clone()
        };

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
    type SymbolIterator = OmfSymbolIterator<'data, 'file>;

    fn symbols(&self) -> Self::SymbolIterator {
        OmfSymbolIterator {
            publics: &self.file.publics,
            externals: &self.file.externals,
            communals: &self.file.communals,
            index: 0,
        }
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> Result<Self::Symbol> {
        self.file.symbol_by_index(index)
    }
}
