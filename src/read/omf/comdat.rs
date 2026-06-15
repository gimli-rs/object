use crate::read::{self, Error, Result};
use crate::{ComdatKind, ObjectComdat, ReadRef, SectionIndex, SymbolIndex};

use super::OmfFile;

/// Internal representation of a COMDAT.
#[derive(Debug, Clone)]
pub(super) struct OmfComdatData<'data> {
    /// Symbol name
    pub(super) name: &'data [u8],
    /// Index of the synthesized section (0-based index into `sections`)
    pub(super) section: usize,
    /// Index of the synthesized symbol
    pub(super) symbol: SymbolIndex,
    /// Selection criteria
    pub(super) selection: OmfComdatSelection,
}

/// COMDAT selection criteria
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OmfComdatSelection {
    /// Explicit: may not be combined, produce error if multiple definitions
    Explicit,
    /// Use any: pick any instance
    UseAny,
    /// Same size: all instances must be same size
    SameSize,
    /// Exact match: all instances must have identical content
    ExactMatch,
}

/// A COMDAT section group in an [`OmfFile`].
///
/// Most functionality is provided by the [`ObjectComdat`] trait implementation.
#[derive(Debug)]
pub struct OmfComdat<'data, 'file, R: ReadRef<'data>> {
    file: &'file OmfFile<'data, R>,
    index: usize,
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for OmfComdat<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectComdat<'data> for OmfComdat<'data, 'file, R> {
    type SectionIterator = OmfComdatSectionIterator<'data, 'file, R>;

    fn kind(&self) -> ComdatKind {
        match self.file.comdats[self.index].selection {
            OmfComdatSelection::Explicit => ComdatKind::NoDuplicates,
            OmfComdatSelection::UseAny => ComdatKind::Any,
            OmfComdatSelection::SameSize => ComdatKind::SameSize,
            OmfComdatSelection::ExactMatch => ComdatKind::ExactMatch,
        }
    }

    fn symbol(&self) -> SymbolIndex {
        self.file.comdats[self.index].symbol
    }

    fn name_bytes(&self) -> Result<&'data [u8]> {
        Ok(self.file.comdats[self.index].name)
    }

    fn name(&self) -> Result<&'data str> {
        core::str::from_utf8(self.file.comdats[self.index].name)
            .map_err(|_| Error("Invalid UTF-8 in COMDAT name"))
    }

    fn sections(&self) -> Self::SectionIterator {
        OmfComdatSectionIterator {
            section: Some(SectionIndex(self.file.comdats[self.index].section + 1)),
            _phantom: core::marker::PhantomData,
        }
    }
}

/// An iterator for the COMDAT section groups in an [`OmfFile`].
#[derive(Debug)]
pub struct OmfComdatIterator<'data, 'file, R: ReadRef<'data>> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) index: usize,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfComdatIterator<'data, 'file, R> {
    type Item = OmfComdat<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.file.comdats.len() {
            let comdat = OmfComdat {
                file: self.file,
                index: self.index,
            };
            self.index += 1;
            Some(comdat)
        } else {
            None
        }
    }
}

/// An iterator for the sections in a [`OmfComdat`].
#[derive(Debug)]
pub struct OmfComdatSectionIterator<'data, 'file, R: ReadRef<'data>> {
    section: Option<SectionIndex>,
    _phantom: core::marker::PhantomData<(&'data (), &'file (), R)>,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfComdatSectionIterator<'data, 'file, R> {
    type Item = SectionIndex;

    fn next(&mut self) -> Option<Self::Item> {
        self.section.take()
    }
}
