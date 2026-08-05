//! GOFF doesn't support the COMDAT section.

use core::fmt::Debug;

use crate::read::{self, ComdatKind, ObjectComdat, ReadRef, Result, SectionIndex, SymbolIndex};

use super::GoffFile;

/// An iterator for the COMDAT section groups in a [`GoffFile64`](super::GoffFile64).
pub type GoffComdatIterator64<'data, 'file, R = &'data [u8]> = GoffComdatIterator<'data, 'file, R>;

/// An iterator for the COMDAT section groups in a [`GoffFile`].
///
/// This is a stub that doesn't implement any functionality.
#[derive(Debug)]
pub struct GoffComdatIterator<'data, 'file, R = &'data [u8]>
where
    R: ReadRef<'data>,
{
    #[allow(unused)]
    pub(crate) file: &'file GoffFile<'data, R>,
}

impl<'data, 'file, R> Iterator for GoffComdatIterator<'data, 'file, R>
where
    R: ReadRef<'data>,
{
    type Item = GoffComdat<'data, 'file, R>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

/// A COMDAT section group in a [`GoffFile64`](super::GoffFile64).
pub type GoffComdat64<'data, 'file, R = &'data [u8]> = GoffComdat<'data, 'file, R>;

/// A COMDAT section group in a [`GoffFile`].
///
/// This is a stub that doesn't implement any functionality.
#[derive(Debug)]
pub struct GoffComdat<'data, 'file, R = &'data [u8]>
where
    R: ReadRef<'data>,
{
    #[allow(unused)]
    file: &'file GoffFile<'data, R>,
}

impl<'data, 'file, R> read::private::Sealed for GoffComdat<'data, 'file, R> where R: ReadRef<'data> {}

impl<'data, 'file, R> ObjectComdat<'data> for GoffComdat<'data, 'file, R>
where
    R: ReadRef<'data>,
{
    type SectionIterator = GoffComdatSectionIterator<'data, 'file, R>;

    #[inline]
    fn kind(&self) -> ComdatKind {
        unreachable!();
    }

    #[inline]
    fn symbol(&self) -> SymbolIndex {
        unreachable!();
    }

    #[inline]
    fn name_bytes(&self) -> Result<&'data [u8]> {
        unreachable!();
    }

    #[inline]
    fn name(&self) -> Result<&'data str> {
        unreachable!();
    }

    #[inline]
    fn sections(&self) -> Self::SectionIterator {
        unreachable!();
    }
}

/// An iterator for the sections in a COMDAT section group in a [`GoffFile64`](super::GoffFile64).
pub type GoffComdatSectionIterator64<'data, 'file, R = &'data [u8]> =
    GoffComdatSectionIterator<'data, 'file, R>;

/// An iterator for the sections in a COMDAT section group in a [`GoffFile`].
///
/// This is a stub that doesn't implement any functionality.
#[derive(Debug)]
pub struct GoffComdatSectionIterator<'data, 'file, R = &'data [u8]>
where
    R: ReadRef<'data>,
{
    #[allow(unused)]
    file: &'file GoffFile<'data, R>,
}

impl<'data, 'file, R> Iterator for GoffComdatSectionIterator<'data, 'file, R>
where
    R: ReadRef<'data>,
{
    type Item = SectionIndex;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}
