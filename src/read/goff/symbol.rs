use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::slice;
use core::str;

use crate::BigEndian as BE;
use crate::ebcdic::{EbcdicArray, EbcdicStr, EbcdicString};
use crate::goff;
use crate::read::{
    self, Error, ObjectSymbol, ObjectSymbolTable, ReadError, Result, SectionIndex, SymbolFlags,
    SymbolIndex, SymbolKind, SymbolScope, SymbolSection,
};

use super::{GoffSectionTableInternal, GoffSubsectionIndex, LogicalRecord};

/// 0-based index into GoffSymbolTableInternal::symbols that is always valid.
#[derive(Debug, Clone, Copy)]
pub(super) struct GoffSymbolIndex(usize);

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

    pub(super) fn add_esd(
        &mut self,
        record: LogicalRecord<'data, goff::SymbolRecord>,
        sections: &mut GoffSectionTableInternal<'data>,
    ) -> Result<()> {
        let name = match record.esd_name()? {
            Cow::Borrowed(name) => Cow::Borrowed(EbcdicStr::from_bytes(name)),
            Cow::Owned(name) => Cow::Owned(EbcdicString::from_bytes(name)),
        };
        let mut symbol = GoffSymbolInternal {
            record,
            name,
            section: None,
            // The ESD offset is only valid for LD records.
            // We give PR records an artificial offset later.
            offset: if record.initial.symbol_type == goff::ESD_ST_LD {
                record.initial.offset.get(BE)
            } else {
                0
            },
            length: record.initial.length.get(BE),
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

        let index = GoffSymbolIndex(self.symbols.len());
        symbol.section = sections.add_esd(self, &symbol, index);
        self.symbols.push(symbol);
        Ok(())
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

    /// Get the symbol with the given ESDID.
    ///
    /// Returns an `None` for ESDID 0 or an invalid ESDID.
    pub(super) fn get(&self, index: SymbolIndex) -> Option<&GoffSymbolInternal<'data>> {
        self.symbols.get(index.0.wrapping_sub(1))
    }

    pub(super) fn get_mut(&mut self, index: SymbolIndex) -> Option<&mut GoffSymbolInternal<'data>> {
        self.symbols.get_mut(index.0.wrapping_sub(1))
    }

    /// Iterate over the symbols.
    pub(super) fn iter(&self) -> slice::Iter<'_, GoffSymbolInternal<'data>> {
        self.symbols.iter()
    }

    /// Get the symbol at the given index.
    pub(super) fn get_by_index(&self, index: GoffSymbolIndex) -> &GoffSymbolInternal<'data> {
        // GoffSymbolIndex is always valid.
        &self.symbols[index.0]
    }

    pub(super) fn set_offset(&mut self, index: GoffSymbolIndex, offset: u32) {
        self.symbols[index.0].offset = offset;
    }
}

/// The section and subsection containing a GOFF symbol.
#[derive(Debug, Clone, Copy)]
pub(super) struct GoffSymbolSection {
    pub(super) section: SectionIndex,
    pub(super) subsection: GoffSubsectionIndex,
}

/// A symbol in a GOFF [`SymbolTable`].
#[derive(Debug)]
pub(super) struct GoffSymbolInternal<'data> {
    /// ESD record.
    record: LogicalRecord<'data, goff::SymbolRecord>,
    /// Symbol name (flattened from ESD record and any continuation records)
    name: Cow<'data, EbcdicStr>,
    /// The section and subsection this symbol belongs to.
    ///
    /// Set for ED symbols, or LD/PR symbols with an ED parent.
    section: Option<GoffSymbolSection>,
    /// The offset of the symbol within the section.
    ///
    /// Set for LD/PR symbols.
    offset: u32,
    /// Length (size of allocated memory of program element or section)
    ///
    /// May be from a LEN record.
    length: u32,
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
    /// Use [`ObjectSymbol::decoded_name`] to convert to UTF-8.
    #[inline]
    pub(super) fn name(&self) -> &EbcdicStr {
        &self.name
    }

    /// Get the name converted to UTF-8.
    pub(super) fn decoded_name(&self) -> String {
        self.name.to_utf8()
    }

    /// Get the length from the ESD or LEN record.
    pub(super) fn length(&self) -> u32 {
        self.length
    }

    /// Get the section this symbol belongs to.
    ///
    /// Set for ED symbols, or LD/PR symbols with an ED parent.
    pub(super) fn section(&self) -> Option<GoffSymbolSection> {
        self.section
    }

    pub(super) fn is_undefined_pr(&self) -> bool {
        // A PR is undefined if length is 0 AND one of:
        // - namespace is a pseudo-register
        // - part reference represents a symbol in a library
        // - PR is a weak reference variant
        let esd = self.record();
        esd.symbol_type == goff::ESD_ST_PR
            && self.length == 0
            && (esd.namespace == goff::ESD_NS_PSEUDO_REGISTER
                || esd.behavioral_attributes.binding_strength() == goff::ESD_BST_WEAK
                || esd.behavioral_attributes.binding_scope() == goff::ESD_BSC_LIBRARY
                || esd.behavioral_attributes.binding_scope() == goff::ESD_BSC_IMPORT_EXPORT)
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
            .field("name", &self.symbol.decoded_name())
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

    /// Get the associated data ESDID as a SymbolIndex.
    ///
    /// Does not validate the index.
    ///
    /// Returns `SymbolIndex(0)` if there is no associated data ESDID.
    #[inline]
    pub fn goff_ada_esdid(&self) -> SymbolIndex {
        SymbolIndex(self.symbol.record().ada_esdid.get(BE) as usize)
    }

    /// Get the raw EBCDIC-encoded name bytes of this symbol.
    ///
    /// Use [`ObjectSymbol::decoded_name_bytes`] to convert to UTF-8 bytes.
    pub fn goff_name_bytes(&self) -> &'file [u8] {
        self.symbol.name().as_bytes()
    }

    pub(super) fn goff_name(&self) -> &'file EbcdicStr {
        self.symbol.name()
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
            "GOFF symbol names are non-contiguous EBCDIC. Use decoded_name_bytes() instead",
        ))
    }

    fn name(&self) -> Result<&'data str> {
        Err(Error(
            "GOFF symbol names are non-contiguous EBCDIC. Use decoded_name() instead",
        ))
    }

    fn decoded_name_bytes(&self) -> Result<Cow<'data, [u8]>> {
        Ok(Cow::Owned(self.symbol.decoded_name().into_bytes()))
    }

    fn decoded_name(&self) -> Result<Cow<'data, str>> {
        Ok(Cow::Owned(self.symbol.decoded_name()))
    }

    #[inline]
    fn address(&self) -> u64 {
        u64::from(self.symbol.offset)
    }

    #[inline]
    fn size(&self) -> u64 {
        self.symbol.length.into()
    }

    fn kind(&self) -> SymbolKind {
        let esd = self.goff_record();
        match esd.symbol_type {
            goff::ESD_ST_ED => SymbolKind::Section,
            goff::ESD_ST_LD | goff::ESD_ST_PR | goff::ESD_ST_ER => {
                match (esd.behavioral_attributes.executable(), esd.symbol_type) {
                    (goff::EXEC_DATA, _) => SymbolKind::Data,
                    (goff::EXEC_CODE, _) => SymbolKind::Text,
                    // TODO: inherit from ED
                    (_, goff::ESD_ST_LD) => SymbolKind::Label,
                    (_, goff::ESD_ST_PR) => SymbolKind::Data,
                    _ => SymbolKind::Unknown,
                }
            }
            _ => SymbolKind::Unknown,
        }
    }

    fn section(&self) -> SymbolSection {
        if let Some(section) = self.symbol.section {
            return SymbolSection::Section(section.section);
        }
        let esd = self.symbol.record();
        match esd.symbol_type {
            goff::ESD_ST_SD => SymbolSection::None,
            goff::ESD_ST_PR => {
                if self.symbol.is_undefined_pr() {
                    SymbolSection::Undefined
                } else {
                    SymbolSection::Unknown
                }
            }
            goff::ESD_ST_ER => SymbolSection::Undefined,
            _ => SymbolSection::Unknown,
        }
    }

    #[inline]
    fn is_undefined(&self) -> bool {
        let esd = self.symbol.record();
        match esd.symbol_type {
            // Section Definition (SD) - defines a control section.
            goff::ESD_ST_SD => false,
            // Element Definition (ED) - defines an element (part/class).
            goff::ESD_ST_ED => false,
            // Label Definition (LD) - defines a label within a section.
            goff::ESD_ST_LD => false,
            // Part Reference (PR) - references a part of an element.
            goff::ESD_ST_PR => self.symbol.is_undefined_pr(),
            // External Reference (ER) - references an external symbol.
            goff::ESD_ST_ER => true,
            _ => false,
        }
    }

    /// Return true if the symbol is a definition of a function or data object.
    #[inline]
    fn is_definition(&self) -> bool {
        match self.goff_record().symbol_type {
            goff::ESD_ST_LD => true,
            goff::ESD_ST_PR => self.symbol.section.is_some(),
            _ => false,
        }
    }

    #[inline]
    fn is_common(&self) -> bool {
        // TODO: need a reliable way to distinguish common symbols.
        // LLVM uses ESD_BA_MERGE on the ED parent for most data, not just common
        false
    }

    #[inline]
    fn is_weak(&self) -> bool {
        self.goff_record().behavioral_attributes.binding_strength() == goff::ESD_BST_WEAK
    }

    fn scope(&self) -> SymbolScope {
        let esd = self.goff_record();
        // Section definitions and Element definitions are not referenced as symbols.
        if matches!(esd.symbol_type, goff::ESD_ST_SD | goff::ESD_ST_ED) {
            return SymbolScope::Compilation;
        }
        // Symbol identifiers that are a single EBCDIC encoded space are local.
        const EBCDIC_SPACE: EbcdicArray<1> = EbcdicArray::from_ascii(*b" ");
        if *self.symbol.name == *EBCDIC_SPACE {
            return SymbolScope::Compilation;
        }
        match esd.behavioral_attributes.binding_scope() {
            goff::ESD_BSC_SECTION | goff::ESD_BSC_MODULE => SymbolScope::Compilation,
            goff::ESD_BSC_LIBRARY => SymbolScope::Linkage,
            goff::ESD_BSC_IMPORT_EXPORT => SymbolScope::Dynamic,
            _ => SymbolScope::Unknown,
        }
    }

    #[inline]
    fn is_global(&self) -> bool {
        self.scope() != SymbolScope::Compilation
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
            parent: Some(self.goff_parent_esdid()).filter(|id| id.0 != 0),
            ada: Some(self.goff_ada_esdid()).filter(|id| id.0 != 0),
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
