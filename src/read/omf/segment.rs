use crate::{read, ObjectSegment, ReadRef, Result, SegmentFlags};

use super::OmfFile;

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
