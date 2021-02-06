use core::marker::PhantomData;
use core::{cmp, iter, result, slice, str};

use crate::endian::LittleEndian as LE;
use crate::pe;
use crate::pod::Bytes;
use crate::read::{
    self, CompressedData, ObjectSection, ObjectSegment, ReadError, ReadRef, Relocation, Result,
    SectionFlags, SectionIndex, SectionKind,
};

use super::{ImageNtHeaders, PeFile, SectionTable};

/// An iterator over the loadable sections of a `PeFile32`.
pub type PeSegmentIterator32<'data, 'file, R> =
    PeSegmentIterator<'data, 'file, pe::ImageNtHeaders32, R>;
/// An iterator over the loadable sections of a `PeFile64`.
pub type PeSegmentIterator64<'data, 'file, R> =
    PeSegmentIterator<'data, 'file, pe::ImageNtHeaders64, R>;

/// An iterator over the loadable sections of a `PeFile`.
#[derive(Debug)]
pub struct PeSegmentIterator<'data, 'file, Pe, R>
where
    'data: 'file,
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
    pub(super) file: &'file PeFile<'data, Pe, R>,
    pub(super) iter: slice::Iter<'file, pe::ImageSectionHeader>,
}

impl<'data, 'file, Pe: ImageNtHeaders, R: ReadRef<'data>> Iterator
    for PeSegmentIterator<'data, 'file, Pe, R>
{
    type Item = PeSegment<'data, 'file, Pe, R>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|section| PeSegment {
            file: self.file,
            section,
        })
    }
}

/// A loadable section of a `PeFile32`.
pub type PeSegment32<'data, 'file, R> = PeSegment<'data, 'file, pe::ImageNtHeaders32, R>;
/// A loadable section of a `PeFile64`.
pub type PeSegment64<'data, 'file, R> = PeSegment<'data, 'file, pe::ImageNtHeaders64, R>;

/// A loadable section of a `PeFile`.
#[derive(Debug)]
pub struct PeSegment<'data, 'file, Pe, R>
where
    'data: 'file,
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
    file: &'file PeFile<'data, Pe, R>,
    section: &'file pe::ImageSectionHeader,
}

impl<'data, 'file, Pe: ImageNtHeaders, R: ReadRef<'data>> PeSegment<'data, 'file, Pe, R> {
    fn bytes(&self) -> Result<Bytes<'data>> {
        self.section
            .pe_data(self.file.data)
            .read_error("Invalid PE section offset or size")
    }
}

impl<'data, 'file, Pe: ImageNtHeaders, R: ReadRef<'data>> read::private::Sealed
    for PeSegment<'data, 'file, Pe, R>
{
}

impl<'data, 'file, Pe: ImageNtHeaders, R: ReadRef<'data>> ObjectSegment<'data>
    for PeSegment<'data, 'file, Pe, R>
{
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
        self.file.section_alignment()
    }

    #[inline]
    fn file_range(&self) -> (u64, u64) {
        let (offset, size) = self.section.pe_file_range();
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
        let name = self.section.name(self.file.common.symbols.strings())?;
        Ok(Some(
            str::from_utf8(name)
                .ok()
                .read_error("Non UTF-8 PE section name")?,
        ))
    }
}

/// An iterator over the sections of a `PeFile32`.
pub type PeSectionIterator32<'data, 'file, R> =
    PeSectionIterator<'data, 'file, pe::ImageNtHeaders32, R>;
/// An iterator over the sections of a `PeFile64`.
pub type PeSectionIterator64<'data, 'file, R> =
    PeSectionIterator<'data, 'file, pe::ImageNtHeaders64, R>;

/// An iterator over the sections of a `PeFile`.
#[derive(Debug)]
pub struct PeSectionIterator<'data, 'file, Pe, R>
where
    'data: 'file,
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
    pub(super) file: &'file PeFile<'data, Pe, R>,
    pub(super) iter: iter::Enumerate<slice::Iter<'file, pe::ImageSectionHeader>>,
}

impl<'data, 'file, Pe: ImageNtHeaders, R: ReadRef<'data>> Iterator
    for PeSectionIterator<'data, 'file, Pe, R>
{
    type Item = PeSection<'data, 'file, Pe, R>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|(index, section)| PeSection {
            file: self.file,
            index: SectionIndex(index + 1),
            section,
        })
    }
}

/// A section of a `PeFile32`.
pub type PeSection32<'data, 'file, R> = PeSection<'data, 'file, pe::ImageNtHeaders32, R>;
/// A section of a `PeFile64`.
pub type PeSection64<'data, 'file, R> = PeSection<'data, 'file, pe::ImageNtHeaders64, R>;

/// A section of a `PeFile`.
#[derive(Debug)]
pub struct PeSection<'data, 'file, Pe, R>
where
    'data: 'file,
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
    pub(super) file: &'file PeFile<'data, Pe, R>,
    pub(super) index: SectionIndex,
    pub(super) section: &'file pe::ImageSectionHeader,
}

impl<'data, 'file, Pe: ImageNtHeaders, R: ReadRef<'data>> PeSection<'data, 'file, Pe, R> {
    fn bytes(&self) -> Result<Bytes<'data>> {
        self.section
            .pe_data(self.file.data)
            .read_error("Invalid PE section offset or size")
    }
}

impl<'data, 'file, Pe: ImageNtHeaders, R: ReadRef<'data>> read::private::Sealed
    for PeSection<'data, 'file, Pe, R>
{
}

impl<'data, 'file, Pe: ImageNtHeaders, R: ReadRef<'data>> ObjectSection<'data>
    for PeSection<'data, 'file, Pe, R>
{
    type RelocationIterator = PeRelocationIterator<'data, 'file>;

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
        u64::from(self.section.virtual_size.get(LE))
    }

    #[inline]
    fn align(&self) -> u64 {
        self.file.section_alignment()
    }

    #[inline]
    fn file_range(&self) -> Option<(u64, u64)> {
        let (offset, size) = self.section.pe_file_range();
        if size == 0 {
            None
        } else {
            Some((u64::from(offset), u64::from(size)))
        }
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
    fn compressed_data(&self) -> Result<CompressedData<'data>> {
        self.data().map(CompressedData::none)
    }

    #[inline]
    fn name(&self) -> Result<&str> {
        let name = self.section.name(self.file.common.symbols.strings())?;
        str::from_utf8(name)
            .ok()
            .read_error("Non UTF-8 PE section name")
    }

    #[inline]
    fn segment_name(&self) -> Result<Option<&str>> {
        Ok(None)
    }

    #[inline]
    fn kind(&self) -> SectionKind {
        self.section.kind()
    }

    fn relocations(&self) -> PeRelocationIterator<'data, 'file> {
        PeRelocationIterator::default()
    }

    fn flags(&self) -> SectionFlags {
        SectionFlags::Coff {
            characteristics: self.section.characteristics.get(LE),
        }
    }
}

impl<'data> SectionTable<'data> {
    /// Return the data at the given virtual address in a PE file.
    pub fn pe_data_at<R: ReadRef<'data>>(&self, data: R, va: u32) -> Option<Bytes<'data>> {
        self.iter()
            .filter_map(|section| section.pe_data_at(data, va))
            .next()
    }
}

impl pe::ImageSectionHeader {
    /// Return the offset and size of the section in a PE file.
    ///
    /// Returns `None` for sections that have no data in the file.
    pub fn pe_file_range(&self) -> (u32, u32) {
        // Pointer and size will be zero for uninitialized data; we don't need to validate this.
        let offset = self.pointer_to_raw_data.get(LE);
        let size = cmp::min(self.virtual_size.get(LE), self.size_of_raw_data.get(LE));
        (offset, size)
    }

    /// Return the section data in a PE file.
    pub fn pe_data<'data, R: ReadRef<'data>>(&self, data: R) -> result::Result<Bytes<'data>, ()> {
        let (offset, size) = self.pe_file_range();
        data.read_bytes_at(offset as usize, size as usize)
            .map(Bytes)
    }

    /// Return the data at the given virtual address if this section contains it.
    pub fn pe_data_at<'data, R: ReadRef<'data>>(&self, data: R, va: u32) -> Option<Bytes<'data>> {
        let section_va = self.virtual_address.get(LE);
        let offset = va.checked_sub(section_va)?;
        let mut section_data = self.pe_data(data).ok()?;
        section_data.skip(offset as usize).ok()?;
        Some(section_data)
    }
}

/// An iterator over the relocations in an `PeSection`.
#[derive(Debug, Default)]
pub struct PeRelocationIterator<'data, 'file>(PhantomData<(&'data (), &'file ())>);

impl<'data, 'file> Iterator for PeRelocationIterator<'data, 'file> {
    type Item = (u64, Relocation);

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}
