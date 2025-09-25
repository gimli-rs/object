use alloc::vec::Vec;

use crate::read::{self, ObjectSegment, ReadRef, Result};
use crate::{omf, SegmentFlags};

use super::{OmfFile, OmfFixup};

/// An OMF segment definition
#[derive(Debug, Clone)]
pub struct OmfSegment<'data> {
    /// Segment name index (into names table)
    pub(super) name_index: u16,
    /// Class name index (into names table)
    pub(super) class_index: u16,
    /// Overlay name index (into names table)
    #[allow(unused)] // TODO
    pub(super) overlay_index: u16,
    /// Segment alignment
    pub(super) alignment: omf::SegmentAlignment,
    /// Segment combination
    pub(super) combination: omf::SegmentCombination,
    /// Whether this is a 32-bit segment
    #[allow(unused)] // TODO
    pub(super) use32: bool,
    /// Segment length
    pub(super) length: u32,
    /// Segment data chunks (offset, data)
    /// Multiple LEDATA/LIDATA records can contribute to a single segment
    pub(super) data_chunks: Vec<(u32, OmfDataChunk<'data>)>,
    /// Relocations for this segment
    pub(super) relocations: Vec<OmfFixup>,
}

/// Data chunk for a segment
#[derive(Debug, Clone)]
pub(super) enum OmfDataChunk<'data> {
    /// Direct data from LEDATA record
    Direct(&'data [u8]),
    /// Compressed/iterated data from LIDATA record (needs expansion)
    Iterated(&'data [u8]),
}

impl<'data> OmfSegment<'data> {
    /// Get the raw data of the segment if it's a single contiguous chunk
    pub fn get_single_chunk(&self) -> Option<&'data [u8]> {
        if self.data_chunks.len() == 1 {
            let (offset, chunk) = &self.data_chunks[0];
            if *offset == 0 {
                match chunk {
                    OmfDataChunk::Direct(data) if data.len() == self.length as usize => {
                        return Some(data);
                    }
                    _ => {}
                }
            }
        }
        None
    }

    /// Check if any data chunk needs expansion (LIDATA)
    pub fn has_iterated_data(&self) -> bool {
        self.data_chunks
            .iter()
            .any(|(_, chunk)| matches!(chunk, OmfDataChunk::Iterated(_)))
    }
}

/// An OMF segment reference.
#[derive(Debug)]
pub struct OmfSegmentRef<'data, 'file, R: ReadRef<'data>> {
    file: &'file OmfFile<'data, R>,
    index: usize,
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for OmfSegmentRef<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectSegment<'data> for OmfSegmentRef<'data, 'file, R> {
    fn address(&self) -> u64 {
        0
    }

    fn size(&self) -> u64 {
        self.file.segments[self.index].length as u64
    }

    fn align(&self) -> u64 {
        match self.file.segments[self.index].alignment {
            crate::omf::SegmentAlignment::Byte => 1,
            crate::omf::SegmentAlignment::Word => 2,
            crate::omf::SegmentAlignment::Paragraph => 16,
            crate::omf::SegmentAlignment::Page => 256,
            crate::omf::SegmentAlignment::DWord => 4,
            crate::omf::SegmentAlignment::Page4K => 4096,
            _ => 1,
        }
    }

    fn file_range(&self) -> (u64, u64) {
        (0, 0)
    }

    fn data(&self) -> Result<&'data [u8]> {
        // OMF segments don't have direct file mapping
        Ok(&[])
    }

    fn data_range(&self, _address: u64, _size: u64) -> Result<Option<&'data [u8]>> {
        Ok(None)
    }

    fn name_bytes(&self) -> Result<Option<&'data [u8]>> {
        Ok(self
            .file
            .get_name(self.file.segments[self.index].name_index))
    }

    fn name(&self) -> Result<Option<&'data str>> {
        let index = self.file.segments[self.index].name_index;
        let name_opt = self.file.get_name(index);
        match name_opt {
            Some(bytes) => Ok(core::str::from_utf8(bytes).ok()),
            None => Ok(None),
        }
    }

    fn flags(&self) -> SegmentFlags {
        SegmentFlags::None
    }
}

/// An iterator over OMF segments.
#[derive(Debug)]
pub struct OmfSegmentIterator<'data, 'file, R: ReadRef<'data>> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) index: usize,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfSegmentIterator<'data, 'file, R> {
    type Item = OmfSegmentRef<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.file.segments.len() {
            let segment = OmfSegmentRef {
                file: self.file,
                index: self.index,
            };
            self.index += 1;
            Some(segment)
        } else {
            None
        }
    }
}
