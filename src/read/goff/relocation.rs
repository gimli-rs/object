use alloc::borrow::Cow;
use alloc::fmt;

use crate::goff;
use crate::read::{
    Bytes, ReadError, ReadRef, Relocation, RelocationEncoding, RelocationKind, RelocationTarget,
    Result, SymbolIndex,
};
use crate::{BigEndian as BE, U32, U64};

use super::{GoffFile, LogicalRecord};

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
    fn is_descendant_of(&self, esdid: SymbolIndex, parent_esdid: SymbolIndex) -> bool {
        // ESDID 0 means "no parent"; guard against underflow and false positives
        if esdid.0 == 0 {
            return false;
        }
        if let Some(symbol) = self.file.symbols.get(esdid.0 - 1) {
            if symbol.parent_esdid() == parent_esdid {
                return true;
            }
            // Recursively check if this symbol's parent is a descendant
            if symbol.parent_esdid() != esdid {
                return self.is_descendant_of(symbol.parent_esdid(), parent_esdid);
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
            .map(|s| s.record.initial.symbol_type)
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
                && !self.is_descendant_of(p_pointer_index, self.section_esdid)
            {
                // Not our section, skip
                continue;
            }

            // Map to common Relocation format
            let offset = goff_reloc.offset;
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

impl<'data> LogicalRecord<'data, goff::RelocationRecord> {
    /// Iterate over the relocations in the initial record and the continuation records.
    pub fn rld_items(&self) -> Result<RelocationIterator<'data>> {
        Ok(RelocationIterator {
            data: self.rld_data()?,
            offset: 0,
            r_pointer: None,
            p_pointer: None,
            p_offset: None,
        })
    }
}

/// An iterator over the relocations in a RLD record.
///
/// Returned by [`LogicalRecord::rld_items`].
#[derive(Debug)]
pub struct RelocationIterator<'data> {
    // TODO: this could avoid allocation
    data: Cow<'data, [u8]>,
    offset: usize,
    r_pointer: Option<u32>,
    p_pointer: Option<u32>,
    p_offset: Option<u64>,
}

impl<'data> RelocationIterator<'data> {
    /// Return the next relocation data item.
    pub fn next(&mut self) -> Result<Option<goff::Relocation>> {
        if self.offset >= self.data.len() {
            return Ok(None);
        }
        let result = self.parse().map(Some);
        if result.is_err() {
            self.offset = self.data.len();
        }
        result
    }

    fn parse(&mut self) -> Result<goff::Relocation> {
        let mut data = Bytes(&self.data[self.offset..]);
        let len = data.len();

        let flags = *data
            .read::<goff::RelocationFlags>()
            .read_error("Invalid GOFF relocation data item")?;
        data.skip(2)
            .read_error("Invalid GOFF relocation data item")?;

        // Parse R-pointer (conditionally)
        let r_pointer = if flags.is_same_r_id() {
            self.r_pointer
                .read_error("GOFF R-pointer compression without previous value")?
        } else {
            data.read::<U32<_>>()
                .read_error("Invalid GOFF relocation R-pointer")?
                .get(BE)
        };

        // Parse P-pointer (conditionally)
        let p_pointer = if flags.is_same_p_id() {
            self.p_pointer
                .read_error("GOFF P-pointer compression without previous value")?
        } else {
            data.read::<U32<_>>()
                .read_error("Invalid GOFF relocation P-pointer")?
                .get(BE)
        };

        // Parse Offset (conditionally)
        let p_offset = if flags.is_same_offset() {
            self.p_offset
                .read_error("GOFF offset compression without previous value")?
        } else if flags.is_offset64() {
            data.read::<U64<_>>()
                .read_error("Invalid GOFF relocation offset")?
                .get(BE)
        } else {
            u64::from(
                data.read::<U32<_>>()
                    .read_error("Invalid GOFF relocation offset")?
                    .get(BE),
            )
        };

        // Update previous values for next iteration
        self.r_pointer = Some(r_pointer);
        self.p_pointer = Some(p_pointer);
        self.p_offset = Some(p_offset);

        self.offset += len - data.len();

        // Create and store relocation
        Ok(goff::Relocation {
            flags,
            r_pointer,
            p_pointer,
            offset: p_offset,
        })
    }
}

impl<'data> Iterator for RelocationIterator<'data> {
    type Item = Result<goff::Relocation>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next().transpose()
    }
}
