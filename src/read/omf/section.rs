use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::str;

use crate::read::{
    self, CompressedData, CompressedFileRange, Error, ObjectSection, ReadRef, RelocationMap,
    Result, SectionFlags, SectionIndex, SectionKind,
};

use super::{OmfDataChunk, OmfFile, OmfRelocationIterator, OmfSegment};

/// A section in an [`OmfFile`].
///
/// This is either a segment from a SEGDEF record, or a section synthesized
/// from COMDAT records.
#[derive(Debug)]
pub struct OmfSection<'data, 'file, R: ReadRef<'data>> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) index: usize,
}

/// An OMF group definition
#[derive(Debug, Clone)]
pub(super) struct OmfGroup {
    /// Group name index (into names table)
    pub(super) name_index: u16,
    /// Segment indices in this group (1-based SEGDEF indices)
    #[allow(unused)]
    pub(super) segments: Vec<u16>,
}

impl<'data, 'file, R: ReadRef<'data>> OmfSection<'data, 'file, R> {
    fn segment(&self) -> &'file OmfSegment<'data> {
        &self.file.sections[self.index]
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
        self.segment().length
    }

    fn align(&self) -> u64 {
        self.segment().align_bytes()
    }

    fn file_range(&self) -> Option<(u64, u64)> {
        // OMF section data is not contiguous in the file.
        None
    }

    fn data(&self) -> Result<&'data [u8]> {
        self.segment().data()
    }

    fn data_range(&self, address: u64, size: u64) -> Result<Option<&'data [u8]>> {
        let segment = self.segment();
        let offset = address as usize;
        let end = offset
            .checked_add(size as usize)
            .ok_or(Error("Invalid data range"))?;

        // Check if the requested range is within a single direct chunk.
        for (chunk_offset, chunk) in &segment.data_chunks {
            let chunk_start = *chunk_offset as usize;
            if let OmfDataChunk::Direct(chunk_data) = chunk {
                let chunk_end = chunk_start + chunk_data.len();
                if offset >= chunk_start && end <= chunk_end {
                    return Ok(Some(&chunk_data[offset - chunk_start..end - chunk_start]));
                }
            }
        }

        // Range spans multiple chunks, includes iterated data, or is not available.
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
        if segment.data_chunks.is_empty() {
            return Ok(Cow::Borrowed(&[]));
        }
        if let Some(data) = segment.single_chunk() {
            return Ok(Cow::Borrowed(data));
        }
        // The data is non-contiguous or iterated, so it must be copied.
        segment.build_data().map(Cow::Owned)
    }

    fn name_bytes(&self) -> Result<&'data [u8]> {
        Ok(self.segment().name)
    }

    fn name(&self) -> Result<&'data str> {
        str::from_utf8(self.name_bytes()?).map_err(|_| Error("Invalid UTF-8 in OMF section name"))
    }

    fn segment_name_bytes(&self) -> Result<Option<&'data [u8]>> {
        Ok(None)
    }

    fn segment_name(&self) -> Result<Option<&'data str>> {
        Ok(None)
    }

    fn kind(&self) -> SectionKind {
        self.file.section_kind(self.index)
    }

    fn relocations(&self) -> Self::RelocationIterator {
        OmfRelocationIterator {
            file: self.file,
            section_index: self.index,
            index: 0,
        }
    }

    fn relocation_map(&self) -> Result<RelocationMap> {
        RelocationMap::new(self.file, self)
    }

    fn flags(&self) -> SectionFlags {
        SectionFlags::None
    }
}

/// An iterator for the sections in an [`OmfFile`].
#[derive(Debug)]
pub struct OmfSectionIterator<'data, 'file, R: ReadRef<'data>> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) index: usize,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfSectionIterator<'data, 'file, R> {
    type Item = OmfSection<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.file.sections.len() {
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
