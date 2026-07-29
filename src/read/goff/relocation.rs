use alloc::fmt;
use core::fmt::Debug;

use crate::Relocation;

use crate::read::{ReadRef, RelocationEncoding, RelocationKind, RelocationTarget, SymbolIndex};

use super::GoffFile;
use crate::goff::{ESD_SYMTYPE_ED, ESD_SYMTYPE_ER, ESD_SYMTYPE_PR, SymbolType};

/// GOFF Relocation Flags - complete 6-byte structure from RLD records
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelocationFlags {
    /// Byte 0: Compression and mode flags
    pub compression_and_mode: u8,
    /// Byte 1: R-Pointer indicators (reference type and referent type)
    pub r_pointer_indicators: u8,
    /// Byte 2: Action/operation flags
    pub action_flags: u8,
    /// Byte 3: Reserved
    pub reserved: u8,
    /// Byte 4: Target field byte length
    pub target_field_length: u8,
    /// Byte 5: Bit-level field specifications
    pub bit_field_specs: u8,
}

impl RelocationFlags {
    /// Create RelocationFlags from a 6-byte array
    pub fn from_bytes(bytes: [u8; 6]) -> Self {
        Self {
            compression_and_mode: bytes[0],
            r_pointer_indicators: bytes[1],
            action_flags: bytes[2],
            reserved: bytes[3],
            target_field_length: bytes[4],
            bit_field_specs: bytes[5],
        }
    }

    /// Convert to 6-byte array
    pub fn to_bytes(self) -> [u8; 6] {
        [
            self.compression_and_mode,
            self.r_pointer_indicators,
            self.action_flags,
            self.reserved,
            self.target_field_length,
            self.bit_field_specs,
        ]
    }

    // Byte 0 - Compression and Mode Flags

    /// Same R-ID flag: true if R pointer is same as previous RLD item (R-ID field omitted)
    pub fn same_r_id(self) -> bool {
        (self.compression_and_mode & 0x80) != 0
    }

    /// Same P-ID flag: true if P pointer is same as previous RLD item (P-ID field omitted)
    pub fn same_p_id(self) -> bool {
        (self.compression_and_mode & 0x40) != 0
    }

    /// Same Offset flag: true if offset is same as previous RLD item (Offset field omitted)
    pub fn same_offset(self) -> bool {
        (self.compression_and_mode & 0x20) != 0
    }

    /// Offset Length flag: true if offset has alternate length
    pub fn offset_length_flag(self) -> bool {
        (self.compression_and_mode & 0x02) != 0
    }

    /// Addressing Mode Sensitivity: true if mode sensitive (set addressing-mode bits according to AMODE)
    pub fn is_amode_sensitive(self) -> bool {
        (self.compression_and_mode & 0x01) != 0
    }

    // Byte 1 - R-Pointer Indicators

    /// Reference Type (upper 4 bits): indicates data type for second operand
    /// 0=R-address, 1=R-Offset, 2=R-Length, 6=R-Relative-Immediate, 7=R-type, 9=Long-Displacement
    pub fn reference_type(self) -> u8 {
        (self.r_pointer_indicators >> 4) & 0x0F
    }

    /// Referent Type (lower 4 bits): indicates type of referent item
    /// 0=Label, 1=Element, 2=Class, 3=Part
    pub fn referent_type(self) -> u8 {
        self.r_pointer_indicators & 0x0F
    }

    // Byte 2 - Action/Operation Flags

    /// Action or Operation (upper 7 bits): operation type
    /// 0=add, 1=subtract
    pub fn action_operation(self) -> u8 {
        (self.action_flags >> 1) & 0x7F
    }

    /// Fixup Target Field Fetch/Store Flag:
    /// false=fetch target field contents and use as first operand
    /// true=ignore initial contents, store fixup quantity over it
    pub fn ignore_target_contents(self) -> bool {
        (self.action_flags & 0x01) != 0
    }

    // Byte 4 - Target Field Length

    /// Target Field Byte Length: unsigned byte length of the target field (adcon)
    pub fn target_byte_length(self) -> u8 {
        self.target_field_length
    }

    // Byte 5 - Bit-Level Field Specifications

    /// Bit Length (upper 3 bits): for non-byte-aligned fields
    /// Total bit width = 8 × Byte_Length + Bit_Length
    pub fn bit_length(self) -> u8 {
        (self.bit_field_specs >> 5) & 0x07
    }

    /// Conditional Sequential Resolution Flag:
    /// true if part of conditional sequential resolution group
    pub fn is_conditional_sequential(self) -> bool {
        (self.bit_field_specs & 0x10) != 0
    }

    /// Bit Offset (lower 3 bits): position of first bit in the byte that is part of the field
    pub fn bit_offset(self) -> u8 {
        self.bit_field_specs & 0x07
    }

    /// Calculate total field width in bits
    pub fn total_bit_width(self) -> u16 {
        (self.target_byte_length() as u16) * 8 + (self.bit_length() as u16)
    }
}

/// All the necessary data for a GOFF Relocation item
#[derive(Debug)]
pub struct GoffRelocation {
    /// Flags describing this RLD item. The flags determine which fields are present or absent.
    pub flags: RelocationFlags,
    /// ESDID of the ESD entry (ED or ER) which will be used as the basis for relocation.
    /// For internal references: ED ESDID defining the referenced element.
    /// For external references: ER or PR ESDID describing the referenced symbol.
    pub r_pointer: u32,
    /// ESDID of the element within which this address constant resides.
    pub p_pointer: u32,
    /// Offset within the element described by the P pointer where the adcon is located.
    /// This is the fixup target, relocation target, or target field to be updated.
    pub offset: u32,
}

/// An iterator for the relocations in an [`GoffSection64`](super::GoffSection64).
pub type GoffRelocationIterator64<'data, 'file, R = &'data [u8]> =
    GoffRelocationIterator<'data, 'file, R>;

/// An iterator for the relocations in a `GoffSection`.
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
        if let Some(symbol) = self.file.symbols.get(esdid) {
            if symbol.parentesdid == *parent_esdid {
                return true;
            }
            // Recursively check if this symbol's parent is a descendant
            if symbol.parentesdid != *esdid {
                return self.is_descendant_of(&symbol.parentesdid, parent_esdid);
            }
        }
        false
    }

    /// Get the symbol type for a given ESDID
    fn get_symbol_type(&self, esdid: u32) -> Option<SymbolType> {
        let symbol_index = SymbolIndex(esdid as usize);
        self.file.symbols.get(&symbol_index).map(|s| s.symboltype)
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

        if symbol_type == ESD_SYMTYPE_ED {
            // Element Definition - map to section
            self.find_section_index(r_pointer)
                .map(RelocationTarget::Section)
        } else if symbol_type == ESD_SYMTYPE_ER || symbol_type == ESD_SYMTYPE_PR {
            // External/Part Reference - map to symbol
            Some(RelocationTarget::Symbol(symbol_index))
        } else {
            // Other types - treat as symbol
            Some(RelocationTarget::Symbol(symbol_index))
        }
    }

    /// Map GOFF relocation flags to RelocationKind
    fn map_kind(&self, flags: &RelocationFlags) -> RelocationKind {
        let ref_type = flags.reference_type();
        let action = flags.action_operation();

        match (ref_type, action) {
            (0, 0) => RelocationKind::Absolute,      // R-address + add
            (0, 1) => RelocationKind::Relative,      // R-address + subtract
            (1, _) => RelocationKind::SectionOffset, // R-Offset
            (6, _) => RelocationKind::Relative,      // R-Relative-Immediate
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
