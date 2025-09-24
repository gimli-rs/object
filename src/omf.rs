//! Object Module Format (OMF) definitions for classic DOS object files.
//!
//! This module provides type definitions and constants for working with OMF files,
//! as defined in the TIS Relocatable Object Module Format (OMF) Specification v1.1.
//!
//! OMF was commonly used by DOS compilers like Borland C++ and Watcom C.

use crate::endian::U16;
use crate::pod::Pod;

/// OMF record type constants
pub mod record_type {
    /// Translator Header Record
    pub const THEADR: u8 = 0x80;
    /// Library Module Header Record
    pub const LHEADR: u8 = 0x82;
    /// Comment Record
    pub const COMENT: u8 = 0x88;
    /// Module End Record (16-bit)
    pub const MODEND: u8 = 0x8A;
    /// Module End Record (32-bit)
    pub const MODEND32: u8 = 0x8B;
    /// External Names Definition Record
    pub const EXTDEF: u8 = 0x8C;
    /// Type Definition Record (obsolete)
    pub const TYPDEF: u8 = 0x8E;
    /// Public Names Definition Record (16-bit)
    pub const PUBDEF: u8 = 0x90;
    /// Public Names Definition Record (32-bit)
    pub const PUBDEF32: u8 = 0x91;
    /// Line Numbers Record (16-bit)
    pub const LINNUM: u8 = 0x94;
    /// Line Numbers Record (32-bit)
    pub const LINNUM32: u8 = 0x95;
    /// List of Names Record
    pub const LNAMES: u8 = 0x96;
    /// Segment Definition Record (16-bit)
    pub const SEGDEF: u8 = 0x98;
    /// Segment Definition Record (32-bit)
    pub const SEGDEF32: u8 = 0x99;
    /// Group Definition Record
    pub const GRPDEF: u8 = 0x9A;
    /// Fixup Record (16-bit)
    pub const FIXUPP: u8 = 0x9C;
    /// Fixup Record (32-bit)
    pub const FIXUPP32: u8 = 0x9D;
    /// Logical Enumerated Data Record (16-bit)
    pub const LEDATA: u8 = 0xA0;
    /// Logical Enumerated Data Record (32-bit)
    pub const LEDATA32: u8 = 0xA1;
    /// Logical Iterated Data Record (16-bit)
    pub const LIDATA: u8 = 0xA2;
    /// Logical Iterated Data Record (32-bit)
    pub const LIDATA32: u8 = 0xA3;
    /// Communal Names Definition Record
    pub const COMDEF: u8 = 0xB0;
    /// Backpatch Record (16-bit)
    pub const BAKPAT: u8 = 0xB2;
    /// Backpatch Record (32-bit)
    pub const BAKPAT32: u8 = 0xB3;
    /// Local External Names Definition Record (16-bit)
    pub const LEXTDEF: u8 = 0xB4;
    /// Local External Names Definition Record (32-bit)
    pub const LEXTDEF32: u8 = 0xB5;
    /// Local Public Names Definition Record (16-bit)
    pub const LPUBDEF: u8 = 0xB6;
    /// Local Public Names Definition Record (32-bit)
    pub const LPUBDEF32: u8 = 0xB7;
    /// Local Communal Names Definition Record
    pub const LCOMDEF: u8 = 0xB8;
    /// COMDAT External Names Definition Record
    pub const CEXTDEF: u8 = 0xBC;
    /// Initialized Communal Data Record (16-bit)
    pub const COMDAT: u8 = 0xC2;
    /// Initialized Communal Data Record (32-bit)
    pub const COMDAT32: u8 = 0xC3;
    /// Symbol Line Numbers Record (16-bit)
    pub const LINSYM: u8 = 0xC4;
    /// Symbol Line Numbers Record (32-bit)
    pub const LINSYM32: u8 = 0xC5;
    /// Alias Definition Record
    pub const ALIAS: u8 = 0xC6;
    /// Named Backpatch Record (16-bit)
    pub const NBKPAT: u8 = 0xC8;
    /// Named Backpatch Record (32-bit)
    pub const NBKPAT32: u8 = 0xC9;
    /// Local Logical Names Definition Record
    pub const LLNAMES: u8 = 0xCA;
    /// OMF Version Number Record
    pub const VERNUM: u8 = 0xCC;
    /// Vendor-specific OMF Extension Record
    pub const VENDEXT: u8 = 0xCE;
}

/// OMF record header
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RecordHeader {
    /// Record type identifier
    pub record_type: u8,
    /// Length of the record contents (excluding header and checksum)
    pub length: U16<crate::endian::LittleEndian>,
}

unsafe impl Pod for RecordHeader {}

/// Segment alignment types for SEGDEF records
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SegmentAlignment {
    /// Absolute segment
    Absolute = 0,
    /// Byte aligned
    Byte = 1,
    /// Word (2-byte) aligned
    Word = 2,
    /// Paragraph (16-byte) aligned
    Paragraph = 3,
    /// Page (256-byte) aligned
    Page = 4,
    /// Double word (4-byte) aligned
    DWord = 5,
    /// 4K page aligned
    Page4K = 6,
}

/// Segment combination types for SEGDEF records
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SegmentCombination {
    /// Private segment
    Private = 0,
    /// Public segment (concatenated)
    Public = 2,
    /// Stack segment
    Stack = 5,
    /// Common segment (overlapped)
    Common = 6,
}

/// Fixup location types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FixupLocation {
    /// Low-order byte
    LowByte = 0,
    /// 16-bit offset
    Offset = 1,
    /// 16-bit base/segment
    Base = 2,
    /// 32-bit pointer (16:16)
    Pointer = 3,
    /// High-order byte
    HighByte = 4,
    /// 16-bit loader-resolved offset
    LoaderOffset = 5,
    /// 32-bit offset
    Offset32 = 9,
    /// 48-bit pointer (16:32)
    Pointer48 = 11,
    /// 32-bit loader-resolved offset
    LoaderOffset32 = 13,
}

/// Target method types for fixups
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TargetMethod {
    /// Segment index
    SegmentIndex = 0,
    /// Group index
    GroupIndex = 1,
    /// External index
    ExternalIndex = 2,
    /// Frame number (absolute)
    FrameNumber = 3,
}

/// Frame method types for fixups
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameMethod {
    /// Segment index
    SegmentIndex = 0,
    /// Group index
    GroupIndex = 1,
    /// External index
    ExternalIndex = 2,
    /// Frame number (absolute)
    FrameNumber = 3,
    /// Location (use fixup location)
    Location = 4,
    /// Target (use target's frame)
    Target = 5,
}

/// Check if a byte is a valid OMF record type
pub(crate) fn is_omf_record_type(byte: u8) -> bool {
    use record_type::*;
    matches!(
        byte,
        THEADR
            | LHEADR
            | COMENT
            | MODEND
            | MODEND32
            | EXTDEF
            | TYPDEF
            | PUBDEF
            | PUBDEF32
            | LINNUM
            | LINNUM32
            | LNAMES
            | SEGDEF
            | SEGDEF32
            | GRPDEF
            | FIXUPP
            | FIXUPP32
            | LEDATA
            | LEDATA32
            | LIDATA
            | LIDATA32
            | COMDEF
            | BAKPAT
            | BAKPAT32
            | LEXTDEF
            | LEXTDEF32
            | LPUBDEF
            | LPUBDEF32
            | LCOMDEF
            | CEXTDEF
            | COMDAT
            | COMDAT32
            | LINSYM
            | LINSYM32
            | ALIAS
            | NBKPAT
            | NBKPAT32
            | LLNAMES
            | VERNUM
            | VENDEXT
    )
}

/// Helper to read an OMF index (1 or 2 bytes)
pub(crate) fn read_index(data: &[u8]) -> Option<(u16, usize)> {
    if data.is_empty() {
        return None;
    }

    let first_byte = data[0];
    if first_byte & 0x80 == 0 {
        // 1-byte index
        Some((first_byte as u16, 1))
    } else if data.len() >= 2 {
        // 2-byte index
        let high = (first_byte & 0x7F) as u16;
        let low = data[1] as u16;
        Some((high << 8 | low, 2))
    } else {
        None
    }
}

/// Helper to read a counted string (length byte followed by string)
pub(crate) fn read_counted_string(data: &[u8]) -> Option<(&[u8], usize)> {
    if data.is_empty() {
        return None;
    }

    let length = data[0] as usize;
    if data.len() > length {
        Some((&data[1..1 + length], 1 + length))
    } else {
        None
    }
}

/// Read an encoded value (used in LIDATA for repeat counts and block counts)
/// Returns the value and number of bytes consumed
pub(crate) fn read_encoded_value(data: &[u8]) -> Option<(u32, usize)> {
    if data.is_empty() {
        return None;
    }

    let first_byte = data[0];
    if first_byte < 0x80 {
        // Single byte value (0-127)
        Some((first_byte as u32, 1))
    } else if first_byte == 0x81 {
        // Two byte value: 0x81 followed by 16-bit little-endian value
        if data.len() >= 3 {
            let value = u16::from_le_bytes([data[1], data[2]]) as u32;
            Some((value, 3))
        } else {
            None
        }
    } else if first_byte == 0x84 {
        // Three byte value: 0x84 followed by 24-bit little-endian value
        if data.len() >= 4 {
            let value = u32::from_le_bytes([data[1], data[2], data[3], 0]);
            Some((value, 4))
        } else {
            None
        }
    } else if first_byte == 0x88 {
        // Four byte value: 0x88 followed by 32-bit little-endian value
        if data.len() >= 5 {
            let value = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            Some((value, 5))
        } else {
            None
        }
    } else {
        // Unknown encoding
        None
    }
}
