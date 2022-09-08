//! Archive definitions.
//!
//! These definitions are independent of read/write support, although we do implement
//! some traits useful for those.

use crate::pod::Pod;

/// File identification bytes stored at the beginning of the file.
pub const MAGIC: [u8; 8] = *b"!<arch>\n";

/// File identification bytes at the beginning of AIX big archive.
pub const AIX_BIG_MAGIC: [u8; 8] = *b"<bigaf>\n";

/// File identification bytes stored at the beginning of a thin archive.
///
/// A thin archive only contains a symbol table and file names.
pub const THIN_MAGIC: [u8; 8] = *b"!<thin>\n";

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

/// The header at the start of an AIX big archive member, without name.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct AixHeader {
    /// Member size in decimal.
    pub size: [u8; 20],
    /// Offset of next member in decimal.
    pub next_member: [u8; 20],
    /// Offset of previous member in decimal.
    pub prev_member: [u8; 20],
    /// File modification timestamp in decimal.
    pub date: [u8; 12],
    /// User ID in decimal.
    pub uid: [u8; 12],
    /// Group ID in decimal.
    pub gid: [u8; 12],
    /// File mode in octal.
    pub mode: [u8; 12],
    /// Name length in decimal.
    pub name_length: [u8; 4],
}

/// Discriminated union for multiple type headers
#[derive(Debug, Clone, Copy)]
pub enum MemberHeader {
    /// GNU or BSD style header
    SystemV(Header),
    /// AIX style big archive header
    AixBig(AixHeader),
}

unsafe_impl_pod!(Header);
unsafe_impl_pod!(AixHeader);

/// The AIX big archive fixed len header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct AIXBigFixedHeader {
    /// We read the magic number in advance , so don't put this in struct.
    /// Offset to member table
    pub memoffset: [u8; 20],
    /// Offset to Global offset
    pub globsymoffset: [u8; 20],
    /// Offset to 64 bit Sym
    pub globsym64offset: [u8; 20],
    /// Offset to first Child
    pub firstchildoffset: [u8; 20],
    /// Offset to last child
    pub lastchildoffset: [u8; 20],
    /// Offset to free list
    pub freeoffset: [u8; 20],
}

unsafe_impl_pod!(AIXBigFixedHeader);
