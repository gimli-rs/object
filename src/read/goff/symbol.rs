use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::str;

use crate::ebcdic;
use crate::goff;
use crate::goff::*;

use crate::read::{
    self, Error, ObjectSymbol, ObjectSymbolTable, ReadRef, Result, SectionIndex, SymbolFlags,
    SymbolIndex, SymbolKind, SymbolScope, SymbolSection,
};

use super::GoffFile;

/// A symbol in an [`GoffFile`].
///
/// Most functionality is provided by the [`ObjectSymbol`] trait implementation.
#[derive(Debug, Clone)]
pub struct GoffSymbol {
    /// Symbol table index (same as the ESD Identifier)
    pub(super) symbol_index: SymbolIndex,
    /// ESD Identifier (ESDID).
    pub(super) esdid: u32,
    /// Symbol name (EBCDIC-encoded, flattened from ESD record and any continuation records)
    pub(super) name: Vec<u8>,
    /// Symbol Type
    pub(super) symbol_type: SymbolType,
    /// Parent of Owning ESDID
    pub(super) parent_esdid: SymbolIndex,
    /// Offset.
    pub(super) offset: u32,
    /// Length (size of allocated memory of program element or section)
    pub(super) length: u32,
    /// Extended Attribute ESDID
    pub(super) ea_esdid: u32,
    /// Extended Attribute Data Offset
    pub(super) ea_data_offset: u32,
    /// Name Space ID
    pub(super) namespace: goff::SymbolNamespace,
    /// Symbol Flags.
    pub(super) flags: goff::SymbolFlags,
    /// Fill Byte Value (the specific 1-byte value used to pad memory)
    pub(super) fill_byte_value: u8,
    /// Associated data ID
    pub(super) ada_esdid: u32,
    /// Priority
    pub(super) priority: u32,
    /// Behavioral Attributes
    pub(super) behavioral_attributes: BehavioralAttributes,
    /// Name Length
    pub(super) name_length: u16,
}

impl GoffSymbol {
    /// Get the ESDID (ESD Identifier) of this symbol.
    #[inline]
    pub fn esdid(&self) -> u32 {
        self.esdid
    }

    /// Get the symbol type.
    #[inline]
    pub fn symbol_type(&self) -> SymbolType {
        self.symbol_type
    }

    /// Get the parent ESDID as a SymbolIndex.
    #[inline]
    pub fn parent_esdid(&self) -> SymbolIndex {
        self.parent_esdid
    }

    /// Get the offset of this symbol.
    #[inline]
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Get the length (size) of this symbol.
    #[inline]
    pub fn length(&self) -> u32 {
        self.length
    }

    /// Get the extended attribute ESDID.
    #[inline]
    pub fn ea_esdid(&self) -> u32 {
        self.ea_esdid
    }

    /// Get the extended attribute data offset.
    #[inline]
    pub fn ea_data_offset(&self) -> u32 {
        self.ea_data_offset
    }

    /// Get the fill byte value used to pad memory.
    #[inline]
    pub fn fill_byte_value(&self) -> u8 {
        self.fill_byte_value
    }

    /// Get the associated data ESDID.
    #[inline]
    pub fn ada_esdid(&self) -> u32 {
        self.ada_esdid
    }

    /// Get the priority value.
    #[inline]
    pub fn priority(&self) -> u32 {
        self.priority
    }

    /// Get the name length.
    #[inline]
    pub fn name_length(&self) -> u16 {
        self.name_length
    }

    /// Get the raw EBCDIC-encoded name bytes of this symbol.
    ///
    /// The name is stored as a flat byte vector in EBCDIC encoding.
    /// Use [`ObjectSymbol::name_utf8`] to convert to UTF-8.
    #[inline]
    pub fn name_bytes_owned(&self) -> &[u8] {
        &self.name
    }

    /// `behavioral_attributes` field in the ESD record.
    #[inline]
    pub fn behavioral_attributes(&self) -> BehavioralAttributes {
        self.behavioral_attributes
    }
}

impl read::private::Sealed for GoffSymbol {}

impl<'data> ObjectSymbol<'data> for GoffSymbol {
    #[inline]
    fn index(&self) -> SymbolIndex {
        self.symbol_index
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
        Ok(Cow::Owned(ebcdic::to_string(&self.name)))
    }

    #[inline]
    fn address(&self) -> u64 {
        0
    }

    #[inline]
    fn size(&self) -> u64 {
        self.length().into()
    }

    fn kind(&self) -> SymbolKind {
        match self.symbol_type() {
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
        match self.symbol_type() {
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
                self.length == 0
                    && (self.namespace == ESD_NS_PSEUDO_REGISTER
                        || self.behavioral_attributes.binding_strength() == goff::ESD_BST_WEAK
                        || self.behavioral_attributes.binding_scope()
                            == goff::ESD_BSC_IMPORT_EXPORT)
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
        match self.symbol_type() {
            // A PR is common if the binding algorithm is MERGE
            goff::ESD_ST_PR => self.behavioral_attributes.binding_algorithm() == goff::ESD_BA_MERGE,
            _ => false,
        }
    }

    #[inline]
    fn is_weak(&self) -> bool {
        self.behavioral_attributes.binding_strength() == goff::ESD_BST_WEAK
    }

    fn scope(&self) -> SymbolScope {
        match self.behavioral_attributes.binding_scope() {
            goff::ESD_BSC_SECTION => SymbolScope::Compilation,
            goff::ESD_BSC_MODULE => SymbolScope::Linkage,
            goff::ESD_BSC_LIBRARY => SymbolScope::Linkage,
            goff::ESD_BSC_IMPORT_EXPORT => SymbolScope::Dynamic,
            _ => SymbolScope::Unknown,
        }
    }

    #[inline]
    fn is_global(&self) -> bool {
        // Section definitions and Element definitions are local by default
        self.symbol_type() != goff::ESD_ST_SD && self.symbol_type() != goff::ESD_ST_ED
        // Symbol identifiers that are a single EBCDIC encoded space are local
        && self.name_bytes_owned() != [0x40u8]
        // If binding scope is section then the symbol is local.
        && self.behavioral_attributes.binding_scope() != goff::ESD_BSC_SECTION
    }

    #[inline]
    fn is_local(&self) -> bool {
        !self.is_global()
    }

    #[inline]
    fn flags(&self) -> SymbolFlags<SectionIndex, SymbolIndex> {
        SymbolFlags::Goff {
            symbol_type: self.symbol_type,
            flags: self.flags,
            namespace: self.namespace,
            behavioral_attributes: self.behavioral_attributes,
        }
    }
}

/// A table of symbol entries in a GOFF file.
///
/// Note: This table filters out [`goff::ESD_ST_ED`] (Element Definition) and
/// [`goff::ESD_ST_SD`] (Section Definition) symbols from the public API, as these
/// represent structural metadata rather than user-visible symbols. Internal
/// code can access all symbols via `symbol_records()`.
///
/// The public API exposes:
/// - [`goff::ESD_ST_LD`] (Label Definition) - labels within sections
/// - [`goff::ESD_ST_PR`] (Part Reference) - part references
/// - [`goff::ESD_ST_ER`] (External Reference) - external symbols
///
/// Also includes the string table used for the symbol names.
#[derive(Debug)]
pub struct GoffSymbolTable<'data, 'file, R = &'data [u8]>
where
    R: ReadRef<'data>,
{
    pub(super) file: &'file GoffFile<'data, R>,
}

impl<'data, 'file, R> GoffSymbolTable<'data, 'file, R>
where
    R: ReadRef<'data>,
{
    /// Iterate over the symbols.
    #[inline]
    pub fn iter(&self) -> GoffSymbolIterator<'data, 'file, R> {
        GoffSymbolIterator {
            file: self.file,
            index: SymbolIndex(1),
        }
    }

    /// Empty symbol iterator
    #[inline]
    pub(super) fn iter_none(&self) -> GoffSymbolIterator<'data, 'file, R> {
        GoffSymbolIterator {
            file: self.file,
            // ESDIDs are 1-based; index past the last valid ESDID to produce an empty iterator
            index: SymbolIndex(self.file.symbols.len() + 1),
        }
    }

    /// Return true if the symbol table is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.file.symbols.is_empty()
    }

    /// The number of symbol table entries.
    ///
    /// This includes auxiliary symbol table entries.
    #[inline]
    pub fn len(&self) -> usize {
        self.file.symbols.len()
    }
}

/// An iterator for symbol entries in an GOFF file.
///
/// Yields the index and symbol structure for each symbol.
#[derive(Debug)]
pub struct GoffSymbolIterator<'data, 'file, R = &'data [u8]>
where
    R: ReadRef<'data>,
{
    pub(super) file: &'file GoffFile<'data, R>,
    pub(super) index: SymbolIndex,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for GoffSymbolIterator<'data, 'file, R> {
    type Item = GoffSymbol;

    fn next(&mut self) -> Option<Self::Item> {
        let SymbolIndex(index) = self.index;
        // ESDIDs are 1-based; Vec index is esdid - 1
        let symbol = self.file.symbols.get(index - 1)?.clone();
        self.index = SymbolIndex(index + 1);
        Some(symbol)
    }
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for GoffSymbolTable<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectSymbolTable<'data>
    for GoffSymbolTable<'data, 'file, R>
{
    type Symbol = GoffSymbol;
    type SymbolIterator = GoffSymbolIterator<'data, 'file, R>;

    fn symbols(&self) -> Self::SymbolIterator {
        GoffSymbolIterator {
            file: self.file,
            index: SymbolIndex(1),
        }
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> Result<Self::Symbol> {
        // ESDIDs are 1-based; Vec index is esdid - 1
        let symbol = self
            .file
            .symbols
            .get(index.0 - 1)
            .ok_or(Error("Symbol index out of bounds"))?;

        Ok(symbol.clone())
    }
}
