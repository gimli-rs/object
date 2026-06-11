use alloc::vec::Vec;

use crate::read::{self, Error, ObjectSegment, ReadRef, Result, SectionKind};
use crate::{omf, Permissions, SegmentFlags};

use super::{expand_iterated_data, iterated_data_expanded_len, OmfFile, OmfFixup};

/// A section in an OMF file.
///
/// This is either a segment from a SEGDEF record, or a section synthesized
/// from COMDAT records.
#[derive(Debug, Clone)]
pub struct OmfSegment<'data> {
    /// Segment name.
    ///
    /// For sections synthesized from COMDAT or Borland COMDEF records, this
    /// is the symbol name.
    pub(super) name: &'data [u8],
    /// Class name (resolved from the names table)
    pub(super) class: &'data [u8],
    /// Segment name index (into names table), or 0 if the name doesn't come
    /// from the names table.
    pub(super) name_index: u16,
    /// Class name index (into names table)
    pub(super) class_index: u16,
    /// Overlay name index (into names table)
    pub(super) overlay_index: u16,
    /// Segment alignment
    pub(super) alignment: omf::SegmentAlignment,
    /// Segment combination
    pub(super) combination: omf::SegmentCombination,
    /// Whether this is a 32-bit segment
    pub(super) use32: bool,
    /// Segment length in bytes
    pub(super) length: u64,
    /// Section kind for COMDAT sections with non-explicit allocation
    pub(super) kind: Option<SectionKind>,
    /// Whether this section was synthesized from COMDAT records
    pub(super) comdat: bool,
    /// Segment data chunks (offset, data)
    ///
    /// Multiple LEDATA/LIDATA/COMDAT records can contribute to a single section.
    pub(super) data_chunks: Vec<(u32, OmfDataChunk<'data>)>,
    /// Relocations for this section
    pub(super) relocations: Vec<OmfFixup>,
}

/// Data chunk for a section
#[derive(Debug, Clone)]
pub(super) enum OmfDataChunk<'data> {
    /// Direct data from a LEDATA or COMDAT record
    Direct(&'data [u8]),
    /// Iterated data from a LIDATA or COMDAT record (needs expansion)
    Iterated {
        data: &'data [u8],
        /// Whether repeat counts are 32-bit (from a 32-bit record type)
        is_32bit: bool,
    },
}

impl<'data> OmfDataChunk<'data> {
    /// Get the size of the chunk after expansion
    pub(super) fn expanded_len(&self) -> Result<u64> {
        match *self {
            OmfDataChunk::Direct(data) => Ok(data.len() as u64),
            OmfDataChunk::Iterated { data, is_32bit } => iterated_data_expanded_len(data, is_32bit),
        }
    }
}

impl<'data> OmfSegment<'data> {
    /// Get the segment name.
    pub fn name(&self) -> &'data [u8] {
        self.name
    }

    /// Get the class name.
    pub fn class(&self) -> &'data [u8] {
        self.class
    }

    /// Get the segment name index (into the names table).
    ///
    /// For COMDAT sections, this is the public name index. This is 0 for
    /// sections whose name doesn't come from the names table.
    pub fn name_index(&self) -> u16 {
        self.name_index
    }

    /// Get the class name index (into the names table).
    ///
    /// This is 0 for COMDAT sections without a base segment.
    pub fn class_index(&self) -> u16 {
        self.class_index
    }

    /// Get the overlay name index (into the names table).
    pub fn overlay_index(&self) -> u16 {
        self.overlay_index
    }

    /// Get the segment alignment.
    pub fn alignment(&self) -> omf::SegmentAlignment {
        self.alignment
    }

    /// Get the segment combination.
    pub fn combination(&self) -> omf::SegmentCombination {
        self.combination
    }

    /// Return true if this is a 32-bit segment.
    pub fn use32(&self) -> bool {
        self.use32
    }

    /// Get the segment length in bytes.
    pub fn length(&self) -> u64 {
        self.length
    }

    /// Return true if this section was synthesized from COMDAT records.
    pub fn is_comdat(&self) -> bool {
        self.comdat
    }

    /// Get the alignment in bytes.
    pub(super) fn align_bytes(&self) -> u64 {
        match self.alignment {
            omf::SegmentAlignment::Absolute => 1,
            omf::SegmentAlignment::Byte => 1,
            omf::SegmentAlignment::Word => 2,
            omf::SegmentAlignment::Paragraph => 16,
            omf::SegmentAlignment::Page => 256,
            omf::SegmentAlignment::DWord => 4,
            omf::SegmentAlignment::Page4K => 4096,
        }
    }

    /// Get the raw data of the section if it's a single contiguous chunk
    pub(super) fn single_chunk(&self) -> Option<&'data [u8]> {
        if let [(0, OmfDataChunk::Direct(data))] = self.data_chunks[..] {
            if data.len() as u64 == self.length {
                return Some(data);
            }
        }
        None
    }

    /// Get the data of the section if it can be returned without copying.
    ///
    /// Returns an error if the data is non-contiguous or requires expansion.
    pub(super) fn data(&self) -> Result<&'data [u8]> {
        if self.data_chunks.is_empty() {
            return Ok(&[]);
        }
        self.single_chunk().ok_or(Error(
            "OMF section data is not contiguous; use uncompressed_data() instead",
        ))
    }

    /// Build the complete section data, expanding iterated data if needed.
    pub(super) fn build_data(&self) -> Result<Vec<u8>> {
        let length = usize::try_from(self.length).map_err(|_| Error("OMF section too large"))?;
        let mut result = alloc::vec![0u8; length];

        for (offset, chunk) in &self.data_chunks {
            let start = *offset as usize;
            match chunk {
                OmfDataChunk::Direct(data) => {
                    let end = start + data.len();
                    if end > result.len() {
                        return Err(Error("OMF section data chunk exceeds section length"));
                    }
                    result[start..end].copy_from_slice(data);
                }
                OmfDataChunk::Iterated { data, is_32bit } => {
                    let expanded = expand_iterated_data(data, *is_32bit)?;
                    let end = start + expanded.len();
                    if end > result.len() {
                        return Err(Error("OMF section data chunk exceeds section length"));
                    }
                    result[start..end].copy_from_slice(&expanded);
                }
            }
        }

        Ok(result)
    }
}

/// A loadable section in an [`OmfFile`].
///
/// Most functionality is provided by the [`ObjectSegment`] trait implementation.
#[derive(Debug)]
pub struct OmfSegmentRef<'data, 'file, R: ReadRef<'data>> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) index: usize,
}

impl<'data, 'file, R: ReadRef<'data>> OmfSegmentRef<'data, 'file, R> {
    fn segment(&self) -> &'file OmfSegment<'data> {
        &self.file.sections[self.index]
    }
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for OmfSegmentRef<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectSegment<'data> for OmfSegmentRef<'data, 'file, R> {
    fn address(&self) -> u64 {
        0
    }

    fn size(&self) -> u64 {
        self.segment().length
    }

    fn align(&self) -> u64 {
        self.segment().align_bytes()
    }

    fn file_range(&self) -> (u64, u64) {
        // OMF section data is not contiguous in the file.
        (0, 0)
    }

    fn data(&self) -> Result<&'data [u8]> {
        self.segment().data()
    }

    fn data_range(&self, _address: u64, _size: u64) -> Result<Option<&'data [u8]>> {
        // OMF sections have no address.
        Ok(None)
    }

    fn name_bytes(&self) -> Result<Option<&'data [u8]>> {
        Ok(Some(self.segment().name))
    }

    fn name(&self) -> Result<Option<&'data str>> {
        Ok(core::str::from_utf8(self.segment().name).ok())
    }

    fn flags(&self) -> SegmentFlags {
        SegmentFlags::None
    }

    fn permissions(&self) -> Permissions {
        // OMF segment definitions don't carry permission flags, so derive them
        // from the section kind.
        match self.file.section_kind(self.index) {
            SectionKind::Text => Permissions::new(true, false, true),
            SectionKind::ReadOnlyData | SectionKind::ReadOnlyString | SectionKind::Debug => {
                Permissions::new(true, false, false)
            }
            _ => Permissions::new(true, true, false),
        }
    }
}

/// An iterator for the loadable sections in an [`OmfFile`].
#[derive(Debug)]
pub struct OmfSegmentIterator<'data, 'file, R: ReadRef<'data>> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) index: usize,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfSegmentIterator<'data, 'file, R> {
    type Item = OmfSegmentRef<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.file.sections.len() {
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
