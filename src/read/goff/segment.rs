use alloc::vec::Vec;
use core::fmt::Debug;
use core::str;

use crate::goff::TextRecordStyle;
use crate::read::{self, ObjectSegment, ReadRef, Result};
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
}

impl<'data, 'file, R> Iterator for GoffSegmentIterator<'data, 'file, R>
where
    R: ReadRef<'data>,
{
    type Item = GoffSegmentRef<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

/// Text References in a [`GoffFile`]
/// Can be the text payload of the ED directly or a PR
#[derive(Debug, Clone)]
pub struct GoffTextReference<'data> {
    /// ESDID (either a PR, LD or ED)
    pub(super) esdid: SymbolIndex,
    /// Text Record Style
    pub(super) record_style: TextRecordStyle,
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
    pub fn record_style(&self) -> TextRecordStyle {
        self.record_style
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
    pub(super) symbol: GoffSymbol,
    /// Data Payload
    pub(super) text_refs: Vec<GoffTextReference<'data>>,
}

impl<'data> GoffSegment<'data> {
    /// Returns a reference to the symbol corresponding to this segment's ESDID.
    pub fn symbol(&self) -> &GoffSymbol {
        &self.symbol
    }

    /// Returns a reference to the text references in this segment.
    pub fn text_refs(&self) -> &[GoffTextReference<'data>] {
        &self.text_refs
    }
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for GoffSegmentRef<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectSegment<'data> for GoffSegmentRef<'data, 'file, R> {
    fn address(&self) -> u64 {
        unreachable!()
    }

    fn size(&self) -> u64 {
        unreachable!()
    }

    fn align(&self) -> u64 {
        unreachable!()
    }

    fn file_range(&self) -> (u64, u64) {
        unreachable!()
    }

    fn data(&self) -> Result<&'data [u8]> {
        unreachable!()
    }

    fn data_range(&self, _address: u64, _size: u64) -> Result<Option<&'data [u8]>> {
        unreachable!()
    }

    fn name_bytes(&self) -> Result<Option<&[u8]>> {
        unreachable!()
    }

    fn name(&self) -> Result<Option<&str>> {
        unreachable!()
    }

    fn flags(&self) -> SegmentFlags {
        unreachable!()
    }

    fn permissions(&self) -> Permissions {
        unreachable!()
    }
}

/// A reference to a segment in a [`GoffFile`].
#[derive(Debug)]
#[allow(dead_code)]
pub struct GoffSegmentRef<'data, 'file, R: ReadRef<'data>> {
    pub(super) file: &'file GoffFile<'data, R>,
    pub(super) index: SymbolIndex,
}
