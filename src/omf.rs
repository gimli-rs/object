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

    /// Return true if the record type is valid
    pub fn is_valid(record_type: u8) -> bool {
        matches!(
            record_type,
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
}

/// The addressing mode for an OMF relocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FixupMode {
    /// Self-relative relocation (`M = 0`).
    SelfRelative = 0,
    /// Segment-relative relocation (`M = 1`).
    SegmentRelative = 1,
}

/// Frame datum variants as defined by the OMF specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FixupFrame {
    /// Segment frame datum referencing a 1-based segment index.
    Segment(u16),
    /// Group frame datum referencing a 1-based group index.
    Group(u16),
    /// External frame datum referencing a 1-based entry in the external-name table.
    External(u16),
    /// Explicit frame number datum.
    FrameNumber(u16),
    /// Use the location of the fixup as the frame datum.
    Location,
    /// Use the target's frame datum.
    Target,
}

/// Target datum variants as defined by the OMF specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FixupTarget {
    /// Segment target datum referencing a 1-based segment index.
    Segment(u16),
    /// Group target datum referencing a 1-based group index.
    Group(u16),
    /// External target datum referencing a 1-based entry in the external-name table.
    External(u16),
    /// Explicit frame number datum.
    FrameNumber(u16),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// Return true if the data looks like an OMF file.
pub(crate) fn is_omf<'data, R: crate::ReadRef<'data>>(data: R, offset: u64) -> bool {
    let Ok(header) = data.read_at::<RecordHeader>(offset) else {
        return false;
    };
    if !matches!(
        header.record_type,
        record_type::THEADR | record_type::LHEADR
    ) {
        return false;
    }
    let length = header.length.get(crate::endian::LittleEndian) as usize;
    if length < 1 {
        return false;
    }
    // Read the full record including the checksum byte
    let Ok(record) = data.read_bytes_at(offset, (3 + length) as u64) else {
        return false;
    };
    // Verify the record checksum
    if !verify_checksum(record) {
        return false;
    }
    // Check that the translator or module name string fits in the record
    if length > 1 {
        let name_len = record[3] as usize;
        if name_len > length - 1 {
            return false;
        }
    }
    true
}

/// Verify the checksum of an OMF record
///
/// The checksum is calculated so that the sum of all bytes in the record,
/// including the checksum byte itself, equals 0 (modulo 256).
///
/// Some compilers write 0 rather than computing the checksum,
/// so we accept that as valid.
pub(crate) fn verify_checksum(record: &[u8]) -> bool {
    let checksum = record.last().copied().unwrap_or(0);
    checksum == 0 || record.iter().copied().fold(0u8, u8::wrapping_add) == 0
}
