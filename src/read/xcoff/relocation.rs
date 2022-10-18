use alloc::fmt;
use core::fmt::Debug;

use crate::pod::Pod;
use crate::{xcoff, Relocation};

use crate::read::ReadRef;

use super::{FileHeader, XcoffFile};

/// An iterator over the relocations in a `XcoffSection32`.
pub type XcoffRelocationIterator32<'data, 'file, R = &'data [u8]> =
    XcoffRelocationIterator<'data, 'file, xcoff::FileHeader32, R>;
/// An iterator over the relocations in a `XcoffSection64`.
pub type XcoffRelocationIterator64<'data, 'file, R = &'data [u8]> =
    XcoffRelocationIterator<'data, 'file, xcoff::FileHeader64, R>;

/// An iterator over the relocations in a `XcoffSection`.
pub struct XcoffRelocationIterator<'data, 'file, Xcoff, R = &'data [u8]>
where
    'data: 'file,
    Xcoff: FileHeader,
    R: ReadRef<'data>,
{
    #[allow(unused)]
    pub(super) file: &'file XcoffFile<'data, Xcoff, R>,
}

impl<'data, 'file, Xcoff, R> Iterator for XcoffRelocationIterator<'data, 'file, Xcoff, R>
where
    Xcoff: FileHeader,
    R: ReadRef<'data>,
{
    type Item = (u64, Relocation);

    fn next(&mut self) -> Option<Self::Item> {
        // TODO: return the relocations in the section.
        None
    }
}

impl<'data, 'file, Xcoff, R> fmt::Debug for XcoffRelocationIterator<'data, 'file, Xcoff, R>
where
    Xcoff: FileHeader,
    R: ReadRef<'data>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XcoffRelocationIterator").finish()
    }
}

/// A trait for generic access to `Rel32` and `Rel64`.
#[allow(missing_docs)]
pub trait Rel: Debug + Pod {
    type Word: Into<u64>;
}

impl Rel for xcoff::Rel32 {
    type Word = u32;
}

impl Rel for xcoff::Rel64 {
    type Word = u64;
}
