//! OMF section implementation.

use alloc::borrow::Cow;
use alloc::vec;
use core::str;

use crate::{
    read::{
        self, CompressedData, CompressedFileRange, Error, ObjectSection, ReadRef, RelocationMap,
        Result, SectionFlags, SectionIndex, SectionKind,
    },
    ComdatKind, ObjectComdat, SymbolIndex,
};

use super::{relocation::OmfRelocationIterator, OmfDataChunk, OmfFile, OmfSegment};

/// A section in an OMF file.
#[derive(Debug)]
pub struct OmfSection<'data, 'file, R: ReadRef<'data>> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) index: usize,
}

impl<'data, 'file, R: ReadRef<'data>> OmfSection<'data, 'file, R> {
    fn segment(&self) -> &OmfSegment<'data> {
        &self.file.segments[self.index]
    }
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for OmfSection<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectSection<'data> for OmfSection<'data, 'file, R> {
    type RelocationIterator = OmfRelocationIterator<'data, 'file, R>;

    fn index(&self) -> SectionIndex {
        SectionIndex(self.index + 1)
    }

    fn address(&self) -> u64 {
        0
    }

    fn size(&self) -> u64 {
        self.segment().length as u64
    }

    fn align(&self) -> u64 {
        match self.segment().alignment {
            crate::omf::SegmentAlignment::Byte => 1,
            crate::omf::SegmentAlignment::Word => 2,
            crate::omf::SegmentAlignment::Paragraph => 16,
            crate::omf::SegmentAlignment::Page => 256,
            crate::omf::SegmentAlignment::DWord => 4,
            crate::omf::SegmentAlignment::Page4K => 4096,
            _ => 1,
        }
    }

    fn file_range(&self) -> Option<(u64, u64)> {
        None
    }

    fn data(&self) -> Result<&'data [u8]> {
        let segment = self.segment();

        // Check if we have a single contiguous chunk that doesn't need expansion
        if let Some(data) = segment.get_single_chunk() {
            return Ok(data);
        }

        // If we have no chunks, return empty slice
        if segment.data_chunks.is_empty() {
            return Ok(&[]);
        }

        // For multiple chunks, LIDATA, or non-contiguous data, we can't return a reference
        Err(Error(
            "OMF segment data is not contiguous; use uncompressed_data() instead",
        ))
    }

    fn data_range(&self, address: u64, size: u64) -> Result<Option<&'data [u8]>> {
        let segment = self.segment();
        let offset = address as usize;
        let end = offset
            .checked_add(size as usize)
            .ok_or(Error("Invalid data range"))?;

        // Check if we have a single contiguous chunk that covers the range
        if let Some(data) = segment.get_single_chunk() {
            if offset > data.len() || end > data.len() {
                return Ok(None);
            }
            return Ok(Some(&data[offset..end]));
        }

        // For multiple chunks, check if the requested range is within a single chunk
        for (chunk_offset, chunk) in &segment.data_chunks {
            let chunk_start = *chunk_offset as usize;

            // Only handle direct data chunks for now
            if let OmfDataChunk::Direct(chunk_data) = chunk {
                let chunk_end = chunk_start + chunk_data.len();

                if offset >= chunk_start && end <= chunk_end {
                    let relative_offset = offset - chunk_start;
                    let relative_end = end - chunk_start;
                    return Ok(Some(&chunk_data[relative_offset..relative_end]));
                }
            }
        }

        // Range spans multiple chunks, includes LIDATA, or is not available
        Ok(None)
    }

    fn compressed_file_range(&self) -> Result<CompressedFileRange> {
        Ok(CompressedFileRange::none(self.file_range()))
    }

    fn compressed_data(&self) -> Result<CompressedData<'data>> {
        Ok(CompressedData::none(self.data()?))
    }

    fn uncompressed_data(&self) -> Result<Cow<'data, [u8]>> {
        let segment = self.segment();

        // Check if we have a single contiguous chunk that doesn't need expansion
        if let Some(data) = segment.get_single_chunk() {
            return Ok(Cow::Borrowed(data));
        }

        // If we have no chunks, return empty
        if segment.data_chunks.is_empty() {
            return Ok(Cow::Borrowed(&[]));
        }

        // We need to construct the full segment data
        let mut result = vec![0u8; segment.length as usize];

        for (offset, chunk) in &segment.data_chunks {
            let start = *offset as usize;

            match chunk {
                OmfDataChunk::Direct(data) => {
                    // Direct data
                    let end = start + data.len();
                    if end <= result.len() {
                        result[start..end].copy_from_slice(data);
                    } else {
                        return Err(Error("OMF segment data chunk exceeds segment length"));
                    }
                }
                OmfDataChunk::Iterated(lidata) => {
                    // LIDATA needs expansion
                    if let Ok(expanded) = self.file.expand_lidata_block(lidata) {
                        let end = start + expanded.len();
                        if end <= result.len() {
                            result[start..end].copy_from_slice(&expanded);
                        } else {
                            return Err(Error("OMF LIDATA expansion exceeds segment length"));
                        }
                    }
                }
            }
        }

        Ok(Cow::Owned(result))
    }

    fn name_bytes(&self) -> Result<&'data [u8]> {
        let segment = self.segment();
        self.file
            .get_name(segment.name_index)
            .ok_or(Error("Invalid segment name index"))
    }

    fn name(&self) -> Result<&'data str> {
        str::from_utf8(self.name_bytes()?).map_err(|_| Error("Invalid UTF-8 in segment name"))
    }

    fn segment_name_bytes(&self) -> Result<Option<&'data [u8]>> {
        Ok(None)
    }

    fn segment_name(&self) -> Result<Option<&'data str>> {
        Ok(None)
    }

    fn kind(&self) -> SectionKind {
        self.file.segment_section_kind(self.index)
    }

    fn relocations(&self) -> Self::RelocationIterator {
        OmfRelocationIterator {
            file: self.file,
            segment_index: self.index,
            index: 0,
        }
    }

    fn relocation_map(&self) -> Result<RelocationMap> {
        RelocationMap::new(self.file, self)
    }

    fn flags(&self) -> SectionFlags {
        let segment = self.segment();
        let flags = SectionFlags::None;

        // Set flags based on segment properties
        match segment.combination {
            crate::omf::SegmentCombination::Public => {
                // Public segments are like COMDAT sections
            }
            crate::omf::SegmentCombination::Stack => {
                // Stack segments
            }
            _ => {}
        }

        flags
    }
}

/// An iterator over OMF sections.
#[derive(Debug)]
pub struct OmfSectionIterator<'data, 'file, R: ReadRef<'data>> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) index: usize,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfSectionIterator<'data, 'file, R> {
    type Item = OmfSection<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.file.segments.len() {
            let section = OmfSection {
                file: self.file,
                index: self.index,
            };
            self.index += 1;
            Some(section)
        } else {
            None
        }
    }
}

/// A COMDAT section in an OMF file.
#[derive(Debug)]
pub struct OmfComdat<'data, 'file, R: ReadRef<'data>> {
    file: &'file OmfFile<'data, R>,
    index: usize,
    _phantom: core::marker::PhantomData<&'data ()>,
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for OmfComdat<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectComdat<'data> for OmfComdat<'data, 'file, R> {
    type SectionIterator = OmfComdatSectionIterator<'data, 'file, R>;

    fn kind(&self) -> ComdatKind {
        let comdat = &self.file.comdats[self.index];
        match comdat.selection {
            super::OmfComdatSelection::Explicit => ComdatKind::NoDuplicates,
            super::OmfComdatSelection::UseAny => ComdatKind::Any,
            super::OmfComdatSelection::SameSize => ComdatKind::SameSize,
            super::OmfComdatSelection::ExactMatch => ComdatKind::ExactMatch,
        }
    }

    fn symbol(&self) -> SymbolIndex {
        // COMDAT symbols don't have a direct symbol index in OMF
        SymbolIndex(usize::MAX)
    }

    fn name_bytes(&self) -> Result<&'data [u8]> {
        let comdat = &self.file.comdats[self.index];
        Ok(comdat.name)
    }

    fn name(&self) -> Result<&'data str> {
        let comdat = &self.file.comdats[self.index];
        core::str::from_utf8(comdat.name).map_err(|_| Error("Invalid UTF-8 in COMDAT name"))
    }

    fn sections(&self) -> Self::SectionIterator {
        let comdat = &self.file.comdats[self.index];
        OmfComdatSectionIterator {
            segment_index: (comdat.segment_index as usize).checked_sub(1),
            returned: false,
            _phantom: core::marker::PhantomData,
        }
    }
}

/// An iterator over COMDAT sections.
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
                _phantom: core::marker::PhantomData,
            };
            self.index += 1;
            Some(comdat)
        } else {
            None
        }
    }
}

/// An iterator over sections in a COMDAT.
#[derive(Debug)]
pub struct OmfComdatSectionIterator<'data, 'file, R: ReadRef<'data>> {
    segment_index: Option<usize>,
    returned: bool,
    _phantom: core::marker::PhantomData<(&'data (), &'file (), R)>,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfComdatSectionIterator<'data, 'file, R> {
    type Item = SectionIndex;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.returned {
            self.returned = true;
            self.segment_index.map(|idx| SectionIndex(idx + 1))
        } else {
            None
        }
    }
}
