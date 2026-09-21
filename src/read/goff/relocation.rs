use alloc::fmt;
use core::fmt::Debug;

use crate::goff;
use crate::read::{
    ReadRef, Relocation, RelocationEncoding, RelocationKind, RelocationTarget, SymbolIndex,
};

use super::GoffFile;

/// All the necessary data for a GOFF Relocation item
#[derive(Debug)]
pub struct GoffRelocation {
    /// Flags describing this RLD item. The flags determine which fields are present or absent.
    pub flags: goff::RelocationFlags,
    /// ESDID of the ESD entry (ED or ER) which will be used as the basis for relocation.
    ///
    /// For internal references: ED ESDID defining the referenced element.
    /// For external references: ER or PR ESDID describing the referenced symbol.
    pub r_pointer: u32,
    /// ESDID of the element within which this address constant resides.
    pub p_pointer: u32,
    /// Offset within the element described by the P pointer where the adcon is located.
    ///
    /// This is the fixup target, relocation target, or target field to be updated.
    pub offset: u32,
}

/// An iterator for the relocations in a [`GoffSection`](super::GoffSection).
pub struct GoffRelocationIterator<'data, 'file, R = &'data [u8]>
where
    R: ReadRef<'data>,
{
    pub(super) file: &'file GoffFile<'data, R>,
    pub(super) section_esdid: SymbolIndex,
    pub(super) index: usize,
}

impl<'data, 'file, R> GoffRelocationIterator<'data, 'file, R>
where
    R: ReadRef<'data>,
{
    /// Check if an ESDID is a descendant (child, grandchild, etc.) of a parent ESDID
    fn is_descendant_of(&self, esdid: &SymbolIndex, parent_esdid: &SymbolIndex) -> bool {
        // ESDID 0 means "no parent"; guard against underflow and false positives
        if esdid.0 == 0 {
            return false;
        }
        if let Some(symbol) = self.file.symbols.get(esdid.0 - 1) {
            if symbol.parent_esdid == *parent_esdid {
                return true;
            }
            // Recursively check if this symbol's parent is a descendant
            if symbol.parent_esdid != *esdid {
                return self.is_descendant_of(&symbol.parent_esdid, parent_esdid);
            }
        }
        false
    }

    /// Get the symbol type for a given ESDID
    fn get_symbol_type(&self, esdid: u32) -> Option<goff::SymbolType> {
        // ESDIDs are 1-based; Vec index is esdid - 1
        self.file
            .symbols
            .get(esdid as usize - 1)
            .map(|s| s.symbol_type)
    }

    /// Find the section index for a given ESDID
    fn find_section_index(&self, esdid: u32) -> Option<crate::read::SectionIndex> {
        let symbol_index = SymbolIndex(esdid as usize);
        self.file
            .sections
            .iter()
            .position(|&si| si == symbol_index)
            .map(crate::read::SectionIndex)
    }

    /// Map R-pointer to RelocationTarget
    fn map_target(&self, r_pointer: u32) -> Option<RelocationTarget> {
        let symbol_type = self.get_symbol_type(r_pointer)?;
        let symbol_index = SymbolIndex(r_pointer as usize);

        if symbol_type == goff::ESD_ST_ED {
            // Element Definition - map to section
            self.find_section_index(r_pointer)
                .map(RelocationTarget::Section)
        } else if symbol_type == goff::ESD_ST_ER || symbol_type == goff::ESD_ST_PR {
            // External/Part Reference - map to symbol
            Some(RelocationTarget::Symbol(symbol_index))
        } else {
            // Other types - treat as symbol
            Some(RelocationTarget::Symbol(symbol_index))
        }
    }

    /// Map GOFF relocation flags to RelocationKind
    fn map_kind(&self, flags: &goff::RelocationFlags) -> RelocationKind {
        match (flags.reference_type(), flags.action()) {
            (goff::RLD_RT_ADDRESS, goff::RLD_ACT_ADD) => RelocationKind::Absolute,
            (goff::RLD_RT_ADDRESS, goff::RLD_ACT_SUBTRACT) => RelocationKind::Relative,
            (goff::RLD_RT_OFFSET, _) => RelocationKind::SectionOffset,
            (goff::RLD_RT_RELATIVE_IMMEDIATE, _) => RelocationKind::Relative,
            _ => RelocationKind::Unknown,
        }
    }
}

impl<'data, 'file, R> Iterator for GoffRelocationIterator<'data, 'file, R>
where
    R: ReadRef<'data>,
{
    type Item = (u64, Relocation);

    fn next(&mut self) -> Option<Self::Item> {
        // Find next relocation for this section
        while self.index < self.file.relocations.len() {
            let goff_reloc = &self.file.relocations[self.index];
            self.index += 1;

            let p_pointer_index = SymbolIndex(goff_reloc.p_pointer as usize);

            // Check if this relocation belongs to our section or descendants
            if p_pointer_index != self.section_esdid
                && !self.is_descendant_of(&p_pointer_index, &self.section_esdid)
            {
                // Not our section, skip
                continue;
            }

            // Map to common Relocation format
            let offset = goff_reloc.offset as u64;
            let target = match self.map_target(goff_reloc.r_pointer) {
                Some(t) => t,
                None => continue, // Skip invalid relocations
            };

            let kind = self.map_kind(&goff_reloc.flags);
            let size = goff_reloc.flags.total_bit_width() as u8;

            let relocation = Relocation {
                kind,
                encoding: RelocationEncoding::Generic,
                size,
                target,
                subtractor: None, // TODO: Handle subtract operations
                addend: 0,
                implicit_addend: true,
                flags: crate::read::RelocationFlags::Goff {
                    flags: goff_reloc.flags,
                },
            };

            return Some((offset, relocation));
        }

        None
    }
}

impl<'data, 'file, R> fmt::Debug for GoffRelocationIterator<'data, 'file, R>
where
    R: ReadRef<'data>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoffRelocationIterator")
            .field("section_esdid", &self.section_esdid)
            .field("index", &self.index)
            .field("total_relocations", &self.file.relocations.len())
            .finish()
    }
}
