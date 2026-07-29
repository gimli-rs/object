use alloc::vec::Vec;
use core::fmt::Debug;
use core::str;

#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
use alloc::collections::btree_map as hash_map;
#[cfg(feature = "std")]
#[allow(unused_imports)]
use std::collections::hash_map;

use crate::goff::*;
use crate::read::{self, Error, ObjectSegment, ReadRef, Result};
use crate::{Permissions, SegmentFlags, SymbolIndex};

use super::{GoffFile, GoffSymbol};

/// An iterator for the segments in a [`GoffFile`].
#[derive(Debug)]
pub struct GoffSegmentIterator<'data, 'file, R = &'data [u8]>
where
    R: ReadRef<'data>,
{
    #[allow(unused)]
    pub(super) file: &'file GoffFile<'data, R>,
    pub(super) iter: hash_map::Values<'file, SymbolIndex, GoffSegment<'data>>,
}

impl<'data, 'file, R> Iterator for GoffSegmentIterator<'data, 'file, R>
where
    R: ReadRef<'data>,
{
    type Item = GoffSegment<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().cloned()
    }
}

/// Text References in a [`GoffFile`]
/// Can be the text payload of the ED directly or a PR
#[derive(Debug, Clone)]
pub struct GoffTextReference<'data> {
    /// ESDID (either a PR, LD or ED)
    pub(super) esdid: SymbolIndex,
    /// Text Record Style
    pub(super) recordstyle: TxtRecordStyle,
    /// Starting offset from the element or part origin of the text
    pub(super) offset: u32,
    /// Text length after data encoding expansion (zero if encoding is zero)
    pub(super) true_length: u32,
    /// Text encoding
    pub(super) text_encoding: u16,
    /// Text data length
    pub(super) data_length: u16,
    /// Data Payload
    pub(super) text_data: Vec<&'data [u8]>,
}

impl<'data> GoffTextReference<'data> {
    /// Returns the ESDID (either a PR, LD or ED).
    pub fn esdid(&self) -> SymbolIndex {
        self.esdid
    }

    /// Returns the text record style.
    pub fn recordstyle(&self) -> TxtRecordStyle {
        self.recordstyle
    }

    /// Returns the starting offset from the element or part origin of the text.
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Returns the text length after data encoding expansion (zero if encoding is zero).
    pub fn true_length(&self) -> u32 {
        self.true_length
    }

    /// Returns the text encoding.
    pub fn text_encoding(&self) -> u16 {
        self.text_encoding
    }

    /// Returns the text data length.
    pub fn data_length(&self) -> u16 {
        self.data_length
    }

    /// Returns a reference to the text data payload.
    pub fn text_data(&self) -> &[&'data [u8]] {
        &self.text_data
    }
}

/// A segment in an [`GoffFile`].
///
/// This is either a segment or metadata
#[derive(Debug, Clone)]
pub struct GoffSegment<'data> {
    /// The symbol corresponding to this segment's ESDID
    pub(super) symbol: GoffSymbol<'data>,
    /// Data Payload
    pub(super) text_refs: Vec<GoffTextReference<'data>>,
}

impl<'data> GoffSegment<'data> {
    /// Returns a reference to the symbol corresponding to this segment's ESDID.
    pub fn symbol(&self) -> &GoffSymbol<'data> {
        &self.symbol
    }

    /// Returns a reference to the text references in this segment.
    pub fn text_refs(&self) -> &[GoffTextReference<'data>] {
        &self.text_refs
    }
}

impl<'data> read::private::Sealed for GoffSegment<'data> {}

impl<'data> ObjectSegment<'data> for GoffSegment<'data> {
    fn address(&self) -> u64 {
        // Find the first text reference with the lowest offset
        let first_text_ref = match self.text_refs.iter().min_by_key(|tr| tr.offset) {
            Some(tr) => tr,
            None => return 0,
        };

        let mut address = first_text_ref.offset as u64;

        // If the text record is in a PR (Part Reference), add the PR's offset
        // The segment's esdid is the ED, so if text_ref.esdid != self.symbol.esdid,
        // then the text is in a PR and we need to add the PR's offset
        if first_text_ref.esdid != SymbolIndex(self.symbol.esdid() as usize) {
            // The text reference is from a PR, add the PR's offset to get absolute address
            address += self.symbol.offset as u64;
        }

        address
    }

    fn size(&self) -> u64 {
        self.text_refs
            .iter()
            .map(|text_ref| text_ref.data_length as u64)
            .sum()
    }

    fn align(&self) -> u64 {
        // Use the behavioral_flags method to get SectionFlags, then extract alignment
        let flags = self.symbol.behavioral_flags();
        match flags.alignment() {
            GOFF_ALIGN_BYTE => 1,
            GOFF_ALIGN_HALFWORD => 2,
            GOFF_ALIGN_FULLWORD => 4,
            GOFF_ALIGN_DOUBLEWORD => 8,
            GOFF_ALIGN_QUADWORD => 16,
            GOFF_ALIGN_32BYTE => 32,
            GOFF_ALIGN_64BYTE => 64,
            GOFF_ALIGN_128BYTE => 128,
            GOFF_ALIGN_256BYTE => 256,
            GOFF_ALIGN_512BYTE => 512,
            GOFF_ALIGN_1024BYTE => 1024,
            GOFF_ALIGN_2KB => 2048,
            GOFF_ALIGN_4KB => 4096,
            _ => 1, // Default to byte alignment
        }
    }

    fn file_range(&self) -> (u64, u64) {
        let start = self.address();

        // Find the text reference with the largest offset
        let last_text_ref = match self.text_refs.iter().max_by_key(|tr| tr.offset) {
            Some(tr) => tr,
            None => return (start, start),
        };

        // Calculate end as: largest offset + its data length
        let end = start + last_text_ref.offset as u64 + last_text_ref.data_length as u64;

        (start, end)
    }

    fn data(&self) -> Result<&'data [u8]> {
        Err(Error(
            "GOFF segment data is non-contiguous, use GoffSection::uncompressed_data() instead",
        ))
    }

    fn data_range(&self, _address: u64, _size: u64) -> Result<Option<&'data [u8]>> {
        Err(Error(
            "GOFF segment data is non-contiguous, and should not be index by a given range",
        ))
    }

    fn name_bytes(&self) -> Result<Option<&[u8]>> {
        Err(Error("GOFF segments are not named"))
    }

    fn name(&self) -> Result<Option<&str>> {
        Err(Error("GOFF segments are not named"))
    }

    fn flags(&self) -> SegmentFlags {
        SegmentFlags::GOFF {
            behavioral_attributes: self.symbol.behavioral_flags(),
        }
    }

    fn permissions(&self) -> Permissions {
        let flags = self.symbol.behavioral_flags();

        // Read: GOFF doesn't have a no-read flag, so always readable
        let read = true;

        // Write: writable if NOT read-only
        let write = !flags.is_read_only();

        // Execute: executable if marked as code
        let execute = flags.executable() == GOFF_EXEC_CODE;

        Permissions::new(read, write, execute)
    }
}
