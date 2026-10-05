use core::fmt::Debug;
use core::str;

use crate::read::{self, ObjectSegment, ReadRef, Result};
use crate::{Permissions, SegmentFlags};

use super::GoffFile;

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
    type Item = GoffSegment<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for GoffSegment<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectSegment<'data> for GoffSegment<'data, 'file, R> {
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
pub struct GoffSegment<'data, 'file, R: ReadRef<'data>> {
    #[allow(dead_code)]
    pub(super) file: &'file GoffFile<'data, R>,
}
