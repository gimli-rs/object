#[cfg(feature = "compression")]
use alloc::borrow::Cow;
use core::{iter, result, slice, str};

use crate::endian::LittleEndian as LE;
use crate::pe;
use crate::pod::Bytes;
use crate::read::util::StringTable;
use crate::read::{
    self, Error, ObjectSection, ObjectSegment, ReadError, Result, SectionFlags, SectionIndex,
    SectionKind,
};

use super::{CoffFile, CoffRelocationIterator};

/// An iterator over the loadable sections of a `CoffFile`.
#[derive(Debug)]
pub struct CoffSegmentIterator<'data, 'file>
where
    'data: 'file,
{
    pub(super) file: &'file CoffFile<'data>,
    pub(super) iter: slice::Iter<'data, pe::ImageSectionHeader>,
}

impl<'data, 'file> Iterator for CoffSegmentIterator<'data, 'file> {
    type Item = CoffSegment<'data, 'file>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|section| CoffSegment {
            file: self.file,
            section,
        })
    }
}

/// A loadable section of a `CoffFile`.
#[derive(Debug)]
pub struct CoffSegment<'data, 'file>
where
    'data: 'file,
{
    pub(super) file: &'file CoffFile<'data>,
    pub(super) section: &'data pe::ImageSectionHeader,
}

impl<'data, 'file> CoffSegment<'data, 'file> {
    fn bytes(&self) -> Result<Bytes<'data>> {
        self.section
            .coff_bytes(self.file.data)
            .read_error("Invalid COFF section offset or size")
    }
}

impl<'data, 'file> read::private::Sealed for CoffSegment<'data, 'file> {}

impl<'data, 'file> ObjectSegment<'data> for CoffSegment<'data, 'file> {
    #[inline]
    fn address(&self) -> u64 {
        u64::from(self.section.virtual_address.get(LE))
    }

    #[inline]
    fn size(&self) -> u64 {
        u64::from(self.section.virtual_size.get(LE))
    }

    #[inline]
    fn align(&self) -> u64 {
        self.section.coff_alignment()
    }

    #[inline]
    fn file_range(&self) -> (u64, u64) {
        let (offset, size) = self.section.coff_file_range().unwrap_or((0, 0));
        (u64::from(offset), u64::from(size))
    }

    fn data(&self) -> Result<&'data [u8]> {
        Ok(self.bytes()?.0)
    }

    fn data_range(&self, address: u64, size: u64) -> Result<Option<&'data [u8]>> {
        Ok(read::data_range(
            self.bytes()?,
            self.address(),
            address,
            size,
        ))
    }

    #[inline]
    fn name(&self) -> Result<Option<&str>> {
        let name = self.section.name(self.file.symbols.strings)?;
        Ok(Some(
            str::from_utf8(name)
                .ok()
                .read_error("Non UTF-8 COFF section name")?,
        ))
    }
}

/// An iterator over the sections of a `CoffFile`.
#[derive(Debug)]
pub struct CoffSectionIterator<'data, 'file>
where
    'data: 'file,
{
    pub(super) file: &'file CoffFile<'data>,
    pub(super) iter: iter::Enumerate<slice::Iter<'data, pe::ImageSectionHeader>>,
}

impl<'data, 'file> Iterator for CoffSectionIterator<'data, 'file> {
    type Item = CoffSection<'data, 'file>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|(index, section)| CoffSection {
            file: self.file,
            index: SectionIndex(index),
            section,
        })
    }
}

/// A section of a `CoffFile`.
#[derive(Debug)]
pub struct CoffSection<'data, 'file>
where
    'data: 'file,
{
    pub(super) file: &'file CoffFile<'data>,
    pub(super) index: SectionIndex,
    pub(super) section: &'data pe::ImageSectionHeader,
}

impl<'data, 'file> CoffSection<'data, 'file> {
    fn bytes(&self) -> Result<Bytes<'data>> {
        self.section
            .coff_bytes(self.file.data)
            .read_error("Invalid COFF section offset or size")
    }
}

impl<'data, 'file> read::private::Sealed for CoffSection<'data, 'file> {}

impl<'data, 'file> ObjectSection<'data> for CoffSection<'data, 'file> {
    type RelocationIterator = CoffRelocationIterator<'data, 'file>;

    #[inline]
    fn index(&self) -> SectionIndex {
        self.index
    }

    #[inline]
    fn address(&self) -> u64 {
        u64::from(self.section.virtual_address.get(LE))
    }

    #[inline]
    fn size(&self) -> u64 {
        // TODO: This may need to be the length from the auxiliary symbol for this section.
        u64::from(self.section.size_of_raw_data.get(LE))
    }

    #[inline]
    fn align(&self) -> u64 {
        self.section.coff_alignment()
    }

    #[inline]
    fn file_range(&self) -> Option<(u64, u64)> {
        let (offset, size) = self.section.coff_file_range()?;
        Some((u64::from(offset), u64::from(size)))
    }

    fn data(&self) -> Result<&'data [u8]> {
        Ok(self.bytes()?.0)
    }

    fn data_range(&self, address: u64, size: u64) -> Result<Option<&'data [u8]>> {
        Ok(read::data_range(
            self.bytes()?,
            self.address(),
            address,
            size,
        ))
    }

    #[cfg(feature = "compression")]
    #[inline]
    fn uncompressed_data(&self) -> Result<Cow<'data, [u8]>> {
        Ok(Cow::from(self.data()?))
    }

    #[inline]
    fn name(&self) -> Result<&str> {
        let name = self.section.name(self.file.symbols.strings)?;
        str::from_utf8(name)
            .ok()
            .read_error("Non UTF-8 COFF section name")
    }

    #[inline]
    fn segment_name(&self) -> Result<Option<&str>> {
        Ok(None)
    }

    #[inline]
    fn kind(&self) -> SectionKind {
        self.section.kind()
    }

    fn relocations(&self) -> CoffRelocationIterator<'data, 'file> {
        let pointer = self.section.pointer_to_relocations.get(LE) as usize;
        let number = self.section.number_of_relocations.get(LE) as usize;
        let relocations = self.file.data.read_slice_at(pointer, number).unwrap_or(&[]);
        CoffRelocationIterator {
            file: self.file,
            iter: relocations.iter(),
        }
    }

    fn flags(&self) -> SectionFlags {
        SectionFlags::Coff {
            characteristics: self.section.characteristics.get(LE),
        }
    }
}

impl pe::ImageSectionHeader {
    /// Return the offset and size of the section in the file.
    ///
    /// Returns `None` for sections that have no data in the file.
    fn coff_file_range(&self) -> Option<(u32, u32)> {
        if self.characteristics.get(LE) & pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
            None
        } else {
            let offset = self.pointer_to_raw_data.get(LE);
            // Note: virtual size is not used for COFF.
            let size = self.size_of_raw_data.get(LE);
            Some((offset, size))
        }
    }

    /// Return the section data.
    ///
    /// Returns `Ok(&[])` if the section has no data.
    /// Returns `Err` for invalid values.
    fn coff_bytes<'data>(&self, data: Bytes<'data>) -> result::Result<Bytes<'data>, ()> {
        if let Some((offset, size)) = self.coff_file_range() {
            data.read_bytes_at(offset as usize, size as usize)
        } else {
            Ok(Bytes(&[]))
        }
    }

    pub(crate) fn name<'data>(&'data self, strings: StringTable<'data>) -> Result<&'data [u8]> {
        let bytes = &self.name;
        Ok(if bytes[0] == b'/' {
            let mut offset = 0;
            if bytes[1] == b'/' {
                for byte in bytes[2..].iter() {
                    let digit = match byte {
                        b'A'..=b'Z' => byte - b'A',
                        b'a'..=b'z' => byte - b'a' + 26,
                        b'0'..=b'9' => byte - b'0' + 52,
                        b'+' => 62,
                        b'/' => 63,
                        _ => return Err(Error("Invalid COFF section name base-64 offset")),
                    };
                    offset = offset * 64 + digit as u32;
                }
            } else {
                for byte in bytes[1..].iter() {
                    let digit = match byte {
                        b'0'..=b'9' => byte - b'0',
                        0 => break,
                        _ => return Err(Error("Invalid COFF section name base-10 offset")),
                    };
                    offset = offset * 10 + digit as u32;
                }
            };
            strings
                .get(offset)
                .read_error("Invalid COFF section name offset")?
        } else {
            match bytes.iter().position(|&x| x == 0) {
                Some(end) => &bytes[..end],
                None => &bytes[..],
            }
        })
    }

    pub(crate) fn kind(&self) -> SectionKind {
        let characteristics = self.characteristics.get(LE);
        if characteristics & (pe::IMAGE_SCN_CNT_CODE | pe::IMAGE_SCN_MEM_EXECUTE) != 0 {
            SectionKind::Text
        } else if characteristics & pe::IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
            if characteristics & pe::IMAGE_SCN_MEM_DISCARDABLE != 0 {
                SectionKind::Other
            } else if characteristics & pe::IMAGE_SCN_MEM_WRITE != 0 {
                SectionKind::Data
            } else {
                SectionKind::ReadOnlyData
            }
        } else if characteristics & pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
            SectionKind::UninitializedData
        } else if characteristics & pe::IMAGE_SCN_LNK_INFO != 0 {
            SectionKind::Linker
        } else {
            SectionKind::Unknown
        }
    }

    fn coff_alignment(&self) -> u64 {
        match self.characteristics.get(LE) & pe::IMAGE_SCN_ALIGN_MASK {
            pe::IMAGE_SCN_ALIGN_1BYTES => 1,
            pe::IMAGE_SCN_ALIGN_2BYTES => 2,
            pe::IMAGE_SCN_ALIGN_4BYTES => 4,
            pe::IMAGE_SCN_ALIGN_8BYTES => 8,
            pe::IMAGE_SCN_ALIGN_16BYTES => 16,
            pe::IMAGE_SCN_ALIGN_32BYTES => 32,
            pe::IMAGE_SCN_ALIGN_64BYTES => 64,
            pe::IMAGE_SCN_ALIGN_128BYTES => 128,
            pe::IMAGE_SCN_ALIGN_256BYTES => 256,
            pe::IMAGE_SCN_ALIGN_512BYTES => 512,
            pe::IMAGE_SCN_ALIGN_1024BYTES => 1024,
            pe::IMAGE_SCN_ALIGN_2048BYTES => 2048,
            pe::IMAGE_SCN_ALIGN_4096BYTES => 4096,
            pe::IMAGE_SCN_ALIGN_8192BYTES => 8192,
            _ => 16,
        }
    }
}
