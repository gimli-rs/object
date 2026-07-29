use alloc::vec::Vec;
use core::fmt::Debug;
use core::str;

use crate::goff::*;
use crate::goff::{ESD_SYMTYPE_ED, ESD_SYMTYPE_SD};

#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
use alloc::collections::BTreeMap as HashMap;
#[cfg(feature = "std")]
#[allow(unused_imports)]
use std::collections::HashMap;

use crate::read::{
    self, Error, ObjectSymbol, ObjectSymbolTable, ReadRef, Result, SectionIndex, SymbolFlags,
    SymbolIndex, SymbolKind, SymbolScope, SymbolSection,
};

use super::GoffFile;

/// A symbol in an [`GoffFile64`](super::GoffFile64).
pub type GoffSymbol64<'data> = GoffSymbol<'data>;

/// A symbol in an [`GoffFile`].
///
/// Most functionality is provided by the [`ObjectSymbol`] trait implementation.
#[derive(Debug, Clone)]
pub struct GoffSymbol<'data> {
    /// Symbol table index (same as the ESD Identifier)
    pub(super) symbolindex: SymbolIndex,
    /// ESD Identifier (ESDID).
    pub(super) esdid: u32,
    /// Symbol name
    pub(super) name: Vec<&'data [u8]>,
    /// Symbol Type
    pub(super) symboltype: SymbolType,
    /// Parent of Owning ESDID
    pub(super) parentesdid: SymbolIndex,
    /// Offset.
    pub(super) offset: u32,
    /// Length (size of allocated memory of program element or section)
    pub(super) length: u32,
    /// Extended Attribute ESDID
    pub(super) eaesdid: u32,
    /// Extended Attribute Data Offset
    pub(super) eadataoffset: u32,
    /// Name Space ID
    pub(super) namespaceid: EsdNameSpace,
    /// Symbol Flags.
    pub(super) symflags: u8,
    /// Fill Byte Value (the specific 1-byte value used to pad memory)
    pub(super) fillbytevalue: u8,
    /// Associated data ID
    pub(super) adaesdid: u32,
    /// Priority
    pub(super) priority: u32,
    /// Behavioral Attributes
    pub(super) behavioralattributes: [u8; 10],
    /// Name Length
    pub(super) namelength: u16,
}

impl<'data> GoffSymbol<'data> {
    /// Get the ESDID (ESD Identifier) of this symbol.
    #[inline]
    pub fn esdid(&self) -> u32 {
        self.esdid
    }

    /// Get the symbol type.
    #[inline]
    pub fn symboltype(&self) -> SymbolType {
        self.symboltype
    }

    /// Get the parent ESDID as a SymbolIndex.
    #[inline]
    pub fn parentesdid(&self) -> SymbolIndex {
        self.parentesdid
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
    pub fn eaesdid(&self) -> u32 {
        self.eaesdid
    }

    /// Get the extended attribute data offset.
    #[inline]
    pub fn eadataoffset(&self) -> u32 {
        self.eadataoffset
    }

    /// Get the fill byte value used to pad memory.
    #[inline]
    pub fn fillbytevalue(&self) -> u8 {
        self.fillbytevalue
    }

    /// Get the associated data ESDID.
    #[inline]
    pub fn adaesdid(&self) -> u32 {
        self.adaesdid
    }

    /// Get the priority value.
    #[inline]
    pub fn priority(&self) -> u32 {
        self.priority
    }

    /// Get the name length.
    #[inline]
    pub fn namelength(&self) -> u16 {
        self.namelength
    }

    /// Get the raw EBCDIC-encoded name parts of this symbol.
    ///
    /// The name is stored as a vector of byte slices in EBCDIC encoding.
    /// Use `ebcdic::ebcdic::Ebcdic::ebcdic_to_ascii` to convert to ASCII.
    #[inline]
    pub fn name_parts(&self) -> &[&'data [u8]] {
        &self.name
    }

    /// Convert the behavioral attributes byte array to a structured SectionFlags
    #[inline]
    pub fn behavioral_flags(&self) -> SectionFlags {
        SectionFlags {
            amode: AmodeFlags(self.behavioralattributes[0]),
            rmode: RmodeFlags(self.behavioralattributes[1]),
            text_and_binding: self.behavioralattributes[2],
            tasking_and_exec: self.behavioralattributes[3],
            dup_and_strength: self.behavioralattributes[4],
            loading_and_scope: self.behavioralattributes[5],
            linkage_and_align: self.behavioralattributes[6],
            reserved: [
                self.behavioralattributes[7],
                self.behavioralattributes[8],
                self.behavioralattributes[9],
            ],
        }
    }
}

impl<'data> read::private::Sealed for GoffSymbol<'data> {}

impl<'data> ObjectSymbol<'data> for GoffSymbol<'data> {
    #[inline]
    fn index(&self) -> SymbolIndex {
        self.symbolindex
    }

    fn name_bytes(&self) -> Result<&'data [u8]> {
        match &self.name[..] {
            [] => Err(Error("Invalid GoffSymbol, empty symbol name")),
            [single_chunk] => Ok(single_chunk),
            [..] => Err(Error(
                "symbol name data is non-contiguous, call TODO method instead",
            )),
        }
    }

    fn name(&self) -> Result<&'data str> {
        // GOFF symbol names are always stored as ebcidic, not utf-8
        Err(Error("GOFF symbol names use EBCDIC encodings, ot utf-8"))
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
        match self.symboltype() {
            // Section Definition (SD) - defines a control section.
            ESD_SYMTYPE_SD => SymbolKind::Section,
            // Element Definition (ED) - defines an element (part/class).
            ESD_SYMTYPE_ED => SymbolKind::Section,
            // Label Definition (LD) - defines a label within a section.
            ESD_SYMTYPE_LD => SymbolKind::Label,
            // Part Reference (PR) - references a part of an element.
            ESD_SYMTYPE_PR => SymbolKind::Section,
            // External Reference (ER) - references an external symbol.
            ESD_SYMTYPE_ER => SymbolKind::Unknown,
            _ => SymbolKind::Unknown,
        }
    }

    fn section(&self) -> SymbolSection {
        SymbolSection::Unknown
    }

    #[inline]
    fn is_undefined(&self) -> bool {
        match self.symboltype() {
            // Section Definition (SD) - defines a control section.
            ESD_SYMTYPE_SD => false,
            // Element Definition (ED) - defines an element (part/class).
            ESD_SYMTYPE_ED => false,
            // Label Definition (LD) - defines a label within a section.
            ESD_SYMTYPE_LD => false,
            // Part Reference (PR) - references a part of an element.
            // A PR is undefined if length is 0 AND one of:
            // - namespace is a pseudo-register (ESD_NS_PSEUDO_REGISTER = 2)
            // - part reference represents a symbol in a dynamic library (bit 0x20 in behavioralattributes[6])
            // - PR is a weak reference variant (bit 0x10 in behavioralattributes[4])
            ESD_SYMTYPE_PR => {
                if self.length != 0 {
                    return false;
                }
                // Check if namespace is pseudo-register
                if self.namespaceid.0 == ESD_NS_PSEUDO_REGISTER.0 {
                    return true;
                }
                // Check if weak reference (bit 0x10 in behavioral attributes byte 4)
                if (self.behavioralattributes[4] & 0x10) != 0 {
                    return true;
                }
                // Check if dynamic library reference (bit 0x20 in behavioral attributes byte 6)
                if (self.behavioralattributes[5] & 0x40) != 0 {
                    return true;
                }
                false
            }
            // External Reference (ER) - references an external symbol.
            ESD_SYMTYPE_ER => true,
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
        match self.symboltype() {
            // A PR is common if the binding algorithm is MERGE
            ESD_SYMTYPE_PR => (self.behavioralattributes[2] & 0x10) != 0,
            _ => false,
        }
    }

    #[inline]
    fn is_weak(&self) -> bool {
        // Binding Strength attribute = b'0001'
        (self.behavioralattributes[4] & 0x10) != 0
    }

    fn scope(&self) -> SymbolScope {
        // Binding scope is at offset 5.4 in behavioralattributes (byte 5, bits 4-7)
        // Extract the 4-bit scope value
        let scope_bits = (self.behavioralattributes[5] >> 4) & 0x0F;

        match scope_bits {
            0x01 => SymbolScope::Compilation, // Section scope ("local")
            0x02 => SymbolScope::Linkage,     // Module scope ("global")
            0x03 => SymbolScope::Linkage,     // Library scope (treat as linkage)
            0x04 => SymbolScope::Dynamic,     // Import-Export scope
            _ => SymbolScope::Unknown,        // Unspecified or unknown
        }
    }

    #[inline]
    fn is_global(&self) -> bool {
        // Section definitions and Element definitions are local by default
        let is_section = self.symboltype() == ESD_SYMTYPE_SD || self.symboltype() == ESD_SYMTYPE_ED;
        // Symbol identifiers that are a single EBCDIC encoded space are local
        let is_local_name = self.name_parts().len() == 1 && self.name_parts()[0] == [0x40];
        // If binding scope is section or module symbol is local
        let scope = self.behavioral_flags().binding_scope();
        if is_section || is_local_name || scope == GOFF_SCOPE_SECTION || scope == GOFF_SCOPE_MODULE
        {
            return false;
        }
        // otherwise global
        true
    }

    #[inline]
    fn is_local(&self) -> bool {
        !self.is_global()
    }

    #[inline]
    fn flags(&self) -> SymbolFlags<SectionIndex, SymbolIndex> {
        SymbolFlags::Goff {
            symboltype: self.symboltype,
            symflags: self.symflags,
            namespaceid: self.namespaceid.0,
            behavioral_attributes: self.behavioralattributes,
        }
    }
}

/// A table of symbol entries in a GOFF file.
///
/// Note: This table filters out `ESD_SYMTYPE_ED` (Element Definition) and
/// `ESD_SYMTYPE_SD` (Section Definition) symbols from the public API, as these
/// represent structural metadata rather than user-visible symbols. Internal
/// code can access all symbols via `symbol_records()`.
///
/// The public API exposes:
/// - `ESD_SYMTYPE_LD` (Label Definition) - labels within sections
/// - `ESD_SYMTYPE_PR` (Part Reference) - part references
/// - `ESD_SYMTYPE_ER` (External Reference) - external symbols
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
    ///
    /// Note: This filters out ED (Element Definition) and SD (Section Definition)
    /// symbols as they represent structural metadata rather than user-visible symbols.
    #[inline]
    pub fn iter(&self) -> GoffSymbolIterator<'data, 'file, R> {
        GoffSymbolIterator {
            file: self.file,
            index: SymbolIndex(0),
            esdid_map: self
                .file
                .symbols
                .keys()
                .filter(|idx| {
                    if let Some(sym) = self.file.symbols.get(idx) {
                        sym.symboltype != ESD_SYMTYPE_ED && sym.symboltype != ESD_SYMTYPE_SD
                    } else {
                        false
                    }
                })
                .copied()
                .collect(),
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
    pub(super) esdid_map: Vec<SymbolIndex>,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for GoffSymbolIterator<'data, 'file, R> {
    type Item = GoffSymbol<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        let SymbolIndex(index) = self.index;
        let esdid = self.esdid_map.get(index)?;
        let symbol = self.file.symbols.get(esdid)?.clone();
        self.index = SymbolIndex(index + 1);
        Some(symbol)
    }
}

/// A symbol table in an [`GoffFile64`](super::GoffFile64).
pub type GoffSymbolTable64<'data, 'file, R = &'data [u8]> = GoffSymbolTable<'data, 'file, R>;

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for GoffSymbolTable<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectSymbolTable<'data>
    for GoffSymbolTable<'data, 'file, R>
{
    type Symbol = GoffSymbol<'data>;
    type SymbolIterator = GoffSymbolIterator<'data, 'file, R>;

    fn symbols(&self) -> Self::SymbolIterator {
        GoffSymbolIterator {
            file: self.file,
            index: SymbolIndex(0),
            esdid_map: self
                .file
                .symbols
                .keys()
                .filter(|idx| {
                    if let Some(sym) = self.file.symbols.get(idx) {
                        sym.symboltype != ESD_SYMTYPE_ED && sym.symboltype != ESD_SYMTYPE_SD
                    } else {
                        false
                    }
                })
                .copied()
                .collect(),
        }
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> Result<Self::Symbol> {
        let symbol = self
            .file
            .symbols
            .get(&index)
            .ok_or(Error("Symbol index out of bounds"))?;

        // Reject ED and SD symbols from public API
        if symbol.symboltype == ESD_SYMTYPE_ED || symbol.symboltype == ESD_SYMTYPE_SD {
            return Err(Error(
                "ED and SD symbols are internal and not exposed in public API",
            ));
        }

        Ok(symbol.clone())
    }
}
