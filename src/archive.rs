//! Archive definitions.
//!
//! These definitions are independent of read/write support, although we do implement
//! some traits useful for those.

use crate::pod::Pod;

/// File identification bytes stored at the beginning of the file.
pub const MAGIC: [u8; 8] = *b"!<arch>\n";

/// File identification bytes stored at the beginning of a thin archive.
///
/// A thin archive only contains a symbol table and file names.
pub const THIN_MAGIC: [u8; 8] = *b"!<thin>\n";
/// Big archive magic
pub const BIG_MAGIC: [u8; 8] = *b"<bigaf>\n";

/// The terminator for each archive member header.
pub const TERMINATOR: [u8; 2] = *b"`\n";

/// The header at the start of an archive member.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Header {
    /// The file name.
    pub name: [u8; 16],
    /// File modification timestamp in decimal.
    pub date: [u8; 12],
    /// User ID in decimal.
    pub uid: [u8; 6],
    /// Group ID in decimal.
    pub gid: [u8; 6],
    /// File mode in octal.
    pub mode: [u8; 8],
    /// File size in decimal.
    pub size: [u8; 10],
    /// Must be equal to `TERMINATOR`.
    pub terminator: [u8; 2],
}

/// The fixed length header at the start of a big archive.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BigFixedLengthHeader {
    /// Offset to member table.
    pub memoff: [u8; 20],
    /// Offset to global symbol table.
    pub gstoff: [u8; 20],
    /// Offset global symbol table for 64-bit objects.
    pub gst64off: [u8; 20],
    /// Offset to first archive member.
    pub fstmoff: [u8; 20],
    /// Offset to last archive member.
    pub lstmoff: [u8; 20],
    /// Offset to last archive member.
    pub freeoff: [u8; 20],
}

/// The header at the start of a big archive member.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BigHeader {
    /// File size in decimal.
    pub size: [u8; 20],
    /// Next member offset in decimal.
    pub nxtmem: [u8; 20],
    /// Previous member offset in decimal.
    pub prvmem: [u8; 20],
    /// File modification timestamp in decimal.
    pub date: [u8; 12],
    /// User ID in decimal.
    pub uid: [u8; 12],
    /// Group ID in decimal.
    pub gid: [u8; 12],
    /// File mode in octal.
    pub mode: [u8; 12],
    /// Name length in decimal.
    pub namelen: [u8; 4],
    // Begining of name, or TERMINATOR.
    // We deal with it manually.
    // pub name: [u8; 2]
}

unsafe_impl_pod!(Header);
unsafe_impl_pod!(BigHeader);
unsafe_impl_pod!(BigFixedLengthHeader);
