use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::slice;
use core::str;

use crate::BigEndian as BE;
use crate::ebcdic;
use crate::goff;
use crate::goff::*;

use crate::read::{
    self, Error, ObjectSymbol, ObjectSymbolTable, ReadError, Result, SectionIndex, SymbolFlags,
    SymbolIndex, SymbolKind, SymbolScope, SymbolSection,
};

use super::LogicalRecord;

/// A table of ESD records in a GOFF file.
#[derive(Debug)]
pub(super) struct GoffSymbolTableInternal<'data> {
    symbols: Vec<GoffSymbolInternal<'data>>,
}

impl<'data> GoffSymbolTableInternal<'data> {
    pub(super) fn new() -> Self {
        GoffSymbolTableInternal {
            symbols: Vec::new(),
        }
    }

    pub(super) fn add(
        &mut self,
        record: LogicalRecord<'data, goff::SymbolRecord>,
    ) -> Result<SymbolIndex> {
        let symbol = GoffSymbolInternal {
            record,
            name: record.esd_name()?,
            length: record.initial.length.get(BE),
            text: Vec::new(),
            relocations: Vec::new(),
        };
        // Ensure esdid matches the position we will push to.
        let symbol_index = symbol.esdid();
        if symbol_index.0 != self.symbols.len() + 1 {
            return Err(Error("Invalid ESDID in GOFF ESD record"));
        }
        // Ensure parent is valid to prevent cycles. Note that this accepts 0.
        let parent_index = symbol.parent_esdid();
        if parent_index.0 >= symbol_index.0 {
            return Err(Error("Invalid parent ESDID in GOFF ESD record"));
        }

        self.symbols.push(symbol);
        Ok(symbol_index)
    }

    /// Parses a LengthRecord and its continuations, extracting deferred element-length data items
    /// and updating the corresponding symbols with their lengths
    pub(super) fn add_len(
        &mut self,
        record: LogicalRecord<'data, goff::LengthRecord>,
    ) -> Result<()> {
        for item in record.len_items()? {
            let esdid = item.esdid.get(BE);
            let length = item.length.get(BE);
            let symbol = self
                .get_mut(SymbolIndex(esdid as usize))
                .ok_or(Error("LEN record references undefined symbol"))?;
            symbol.length = length;
        }
        Ok(())
    }

    pub(super) fn add_txt(&mut self, record: LogicalRecord<'data, goff::TextRecord>) -> Result<()> {
        let txt_record = record.initial;
        let esdid = SymbolIndex(txt_record.element_esdid.get(BE) as usize);
        let symbol = self
            .element_mut(esdid)
            .ok_or(Error("Invalid element ESDID in GOFF TXT record"))?;
        symbol.text.push(record);
        Ok(())
    }

    /// Parses a RelocationRecord and its continuations, extracting individual relocation items
    pub(super) fn add_rld(
        &mut self,
        record: LogicalRecord<'data, goff::RelocationRecord>,
    ) -> Result<()> {
        let mut relocations = record.rld_items()?;
        while let Some(relocation) = relocations.next()? {
            let symbol = self
                .element_mut(SymbolIndex(relocation.p_pointer as usize))
                .ok_or(Error("Invalid P pointer in GOFF RLD entry"))?;
            symbol.relocations.push(relocation);
        }
        Ok(())
    }

    /// Get the symbol at the given index.
    ///
    /// Returns an `None` for index 0 or an invalid index.
    pub(super) fn get(&self, index: SymbolIndex) -> Option<&GoffSymbolInternal<'data>> {
        self.symbols.get(index.0.wrapping_sub(1))
    }

    pub(super) fn get_mut(&mut self, index: SymbolIndex) -> Option<&mut GoffSymbolInternal<'data>> {
        self.symbols.get_mut(index.0.wrapping_sub(1))
    }

    /// Get the ED symbol that owns the data for the given ED or PR symbol index.
    ///
    /// Returns `None` for an invalid index, or if the symbol is not an ED or PR.
    pub(super) fn element_mut(
        &mut self,
        index: SymbolIndex,
    ) -> Option<&mut GoffSymbolInternal<'data>> {
        let mut index = index;
        let symbol = self.get(index)?;
        if symbol.record().symbol_type == goff::ESD_ST_PR {
            index = symbol.parent_esdid();
        }
        let symbol = self.get_mut(index)?;
        if symbol.record().symbol_type != goff::ESD_ST_ED {
            return None;
        }
        Some(symbol)
    }

    /// Iterate over the symbols.
    pub(super) fn iter(&self) -> slice::Iter<'_, GoffSymbolInternal<'data>> {
        self.symbols.iter()
    }
}

/// A symbol in a GOFF [`SymbolTable`].
#[derive(Debug)]
pub(super) struct GoffSymbolInternal<'data> {
    /// ESD record.
    record: LogicalRecord<'data, goff::SymbolRecord>,
    /// Symbol name (EBCDIC-encoded, flattened from ESD record and any continuation records)
    name: Cow<'data, [u8]>,
    /// Length (size of allocated memory of program element or section)
    ///
    /// May be from a LEN record.
    length: u32,
    /// TXT records which reference this ESD.
    text: Vec<LogicalRecord<'data, goff::TextRecord>>,
    /// Relocation data items which reference this ESD.
    relocations: Vec<goff::Relocation>,
}

impl<'data> GoffSymbolInternal<'data> {
    /// Get the raw GOFF ESD record.
    pub(super) fn record(&self) -> &'data goff::SymbolRecord {
        self.record.initial
    }

    /// Get the ESDID (ESD Identifier) of this symbol.
    ///
    /// This index is validated during parsing.
    #[inline]
    pub(super) fn esdid(&self) -> SymbolIndex {
        SymbolIndex(self.record.initial.esdid.get(BE) as usize)
    }

    /// Get the parent ESDID as a SymbolIndex.
    ///
    /// This index is validated during parsing.
    ///
    /// Returns `SymbolIndex(0)` if there is no parent, but does not
    /// validate whether the record type allows no parent.
    #[inline]
    pub(super) fn parent_esdid(&self) -> SymbolIndex {
        SymbolIndex(self.record.initial.parent_esdid.get(BE) as usize)
    }

    /// Get the raw EBCDIC-encoded name bytes of this symbol.
    ///
    /// The name is stored as a flat byte vector in EBCDIC encoding.
    /// Use [`ObjectSymbol::name_utf8`] to convert to UTF-8.
    #[inline]
    pub(super) fn name_bytes(&self) -> &[u8] {
        &self.name
    }

    /// Get the name converted to UTF-8.
    pub(super) fn name_utf8(&self) -> String {
        ebcdic::to_string(&self.name)
    }

    /// Get the length from the ESD or LEN record.
    pub(super) fn length(&self) -> u32 {
        self.length
    }

    /// Get the TXT records that reference this symbol.
    pub(super) fn text(&self) -> &[LogicalRecord<'data, goff::TextRecord>] {
        &self.text
    }

    pub(super) fn relocations(&self) -> &[goff::Relocation] {
        &self.relocations
    }
}

/// A reference to a symbol in an [`GoffFile`].
///
/// Most functionality is provided by the [`ObjectSymbol`] trait implementation.
#[derive(Clone, Copy)]
pub struct GoffSymbol<'data, 'file> {
    symbol: &'file GoffSymbolInternal<'data>,
}

impl<'data, 'file> fmt::Debug for GoffSymbol<'data, 'file> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoffSymbol")
            .field("esdid", &self.symbol.esdid())
            .field("name", &self.symbol.name_utf8())
            .field("symbol_type", &self.symbol.record().symbol_type)
            .finish_non_exhaustive()
    }
}

impl<'data, 'file> GoffSymbol<'data, 'file> {
    /// Get the raw GOFF ESD record.
    pub fn goff_record(&self) -> &'data goff::SymbolRecord {
        self.symbol.record()
    }

    /// Get the parent ESDID as a SymbolIndex.
    ///
    /// This index is validated during parsing.
    ///
    /// Returns `SymbolIndex(0)` if there is no parent, but does not
    /// validate whether the record type allows no parent.
    #[inline]
    pub fn goff_parent_esdid(&self) -> SymbolIndex {
        self.symbol.parent_esdid()
    }

    /// Get the raw EBCDIC-encoded name bytes of this symbol.
    ///
    /// The name is stored as a flat byte vector in EBCDIC encoding.
    /// Use [`ObjectSymbol::name_utf8`] to convert to UTF-8.
    pub fn goff_name_bytes(&self) -> &'file [u8] {
        self.symbol.name_bytes()
    }
}

impl<'data, 'file> read::private::Sealed for GoffSymbol<'data, 'file> {}

impl<'data, 'file> ObjectSymbol<'data> for GoffSymbol<'data, 'file> {
    #[inline]
    fn index(&self) -> SymbolIndex {
        self.symbol.esdid()
    }

    fn name_bytes(&self) -> Result<&'data [u8]> {
        Err(Error(
            "GOFF symbol names are non-contiguous EBCDIC. Use name_utf8() instead",
        ))
    }

    fn name(&self) -> Result<&'data str> {
        Err(Error(
            "GOFF symbol names use non-contiguous EBCDIC. Use name_utf8() instead",
        ))
    }

    fn name_utf8(&self) -> Result<Cow<'data, str>> {
        Ok(Cow::Owned(self.symbol.name_utf8()))
    }

    #[inline]
    fn address(&self) -> u64 {
        0
    }

    #[inline]
    fn size(&self) -> u64 {
        self.symbol.length.into()
    }

    fn kind(&self) -> SymbolKind {
        match self.goff_record().symbol_type {
            // Section Definition (SD) - defines a control section.
            goff::ESD_ST_SD => SymbolKind::Section,
            // Element Definition (ED) - defines an element (part/class).
            goff::ESD_ST_ED => SymbolKind::Section,
            // Label Definition (LD) - defines a label within a section.
            goff::ESD_ST_LD => SymbolKind::Label,
            // Part Reference (PR) - references a part of an element.
            goff::ESD_ST_PR => SymbolKind::Section,
            // External Reference (ER) - references an external symbol.
            goff::ESD_ST_ER => SymbolKind::Unknown,
            _ => SymbolKind::Unknown,
        }
    }

    fn section(&self) -> SymbolSection {
        SymbolSection::Unknown
    }

    #[inline]
    fn is_undefined(&self) -> bool {
        let esd = self.goff_record();
        match esd.symbol_type {
            // Section Definition (SD) - defines a control section.
            goff::ESD_ST_SD => false,
            // Element Definition (ED) - defines an element (part/class).
            goff::ESD_ST_ED => false,
            // Label Definition (LD) - defines a label within a section.
            goff::ESD_ST_LD => false,
            // Part Reference (PR) - references a part of an element.
            // A PR is undefined if length is 0 AND one of:
            // - namespace is a pseudo-register
            // - part reference represents a symbol in a dynamic library
            // - PR is a weak reference variant
            goff::ESD_ST_PR => {
                self.symbol.length == 0
                    && (esd.namespace == ESD_NS_PSEUDO_REGISTER
                        || esd.behavioral_attributes.binding_strength() == goff::ESD_BST_WEAK
                        || esd.behavioral_attributes.binding_scope() == goff::ESD_BSC_IMPORT_EXPORT)
            }
            // External Reference (ER) - references an external symbol.
            goff::ESD_ST_ER => true,
            _ => true,
        }
    }

    /// Return true if the symbol is a definition of a function or data object.
    #[inline]
    fn is_definition(&self) -> bool {
        !self.is_undefined()
    }

    #[inline]
    fn is_common(&self) -> bool {
        let esd = self.goff_record();
        match esd.symbol_type {
            // A PR is common if the binding algorithm is MERGE
            goff::ESD_ST_PR => esd.behavioral_attributes.binding_algorithm() == goff::ESD_BA_MERGE,
            _ => false,
        }
    }

    #[inline]
    fn is_weak(&self) -> bool {
        self.goff_record().behavioral_attributes.binding_strength() == goff::ESD_BST_WEAK
    }

    fn scope(&self) -> SymbolScope {
        match self.goff_record().behavioral_attributes.binding_scope() {
            goff::ESD_BSC_SECTION => SymbolScope::Compilation,
            goff::ESD_BSC_MODULE => SymbolScope::Linkage,
            goff::ESD_BSC_LIBRARY => SymbolScope::Linkage,
            goff::ESD_BSC_IMPORT_EXPORT => SymbolScope::Dynamic,
            _ => SymbolScope::Unknown,
        }
    }

    #[inline]
    fn is_global(&self) -> bool {
        let esd = self.goff_record();
        // Section definitions and Element definitions are local by default
        !matches!(esd.symbol_type, goff::ESD_ST_SD | goff::ESD_ST_ED)
        // Symbol identifiers that are a single EBCDIC encoded space are local
        && *self.symbol.name != [0x40u8]
        // If binding scope is section or module symbol is local
        && !matches!(
            esd.behavioral_attributes.binding_scope(),
            goff::ESD_BSC_SECTION | goff::ESD_BSC_MODULE
        )
    }

    #[inline]
    fn is_local(&self) -> bool {
        !self.is_global()
    }

    #[inline]
    fn flags(&self) -> SymbolFlags<SectionIndex, SymbolIndex> {
        let esd = self.goff_record();
        SymbolFlags::Goff {
            symbol_type: esd.symbol_type,
            flags: esd.flags,
            namespace: esd.namespace,
            behavioral_attributes: esd.behavioral_attributes,
        }
    }
}

/// A reference to a symbol table in a [`GoffFile`].
#[derive(Debug, Clone, Copy)]
pub struct GoffSymbolTable<'data, 'file> {
    symbols: &'file GoffSymbolTableInternal<'data>,
}

impl<'data, 'file> GoffSymbolTable<'data, 'file> {
    pub(super) fn new(symbols: &'file GoffSymbolTableInternal<'data>) -> Self {
        Self { symbols }
    }
}

/// An iterator for symbol entries in an GOFF file.
///
/// Yields the index and symbol structure for each symbol.
#[derive(Debug)]
pub struct GoffSymbolIterator<'data, 'file> {
    iter: slice::Iter<'file, GoffSymbolInternal<'data>>,
}

impl<'data, 'file> GoffSymbolIterator<'data, 'file> {
    pub(super) fn new(symbols: &'file GoffSymbolTableInternal<'data>) -> Self {
        GoffSymbolIterator {
            iter: symbols.iter(),
        }
    }

    pub(super) fn empty() -> Self {
        GoffSymbolIterator { iter: [].iter() }
    }
}

impl<'data, 'file> Iterator for GoffSymbolIterator<'data, 'file> {
    type Item = GoffSymbol<'data, 'file>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|symbol| GoffSymbol { symbol })
    }
}

impl<'data, 'file> read::private::Sealed for GoffSymbolTable<'data, 'file> {}

impl<'data, 'file> ObjectSymbolTable<'data> for GoffSymbolTable<'data, 'file> {
    type Symbol = GoffSymbol<'data, 'file>;
    type SymbolIterator = GoffSymbolIterator<'data, 'file>;

    fn symbols(&self) -> Self::SymbolIterator {
        GoffSymbolIterator::new(self.symbols)
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> Result<Self::Symbol> {
        let symbol = self
            .symbols
            .get(index)
            .read_error("Invalid GOFF symbol index")?;
        Ok(GoffSymbol { symbol })
    }
}
