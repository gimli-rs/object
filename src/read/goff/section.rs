use alloc::borrow::Cow;
use core::{fmt, iter, slice, str};

use crate::read::{self, Error, ObjectSection, ReadRef, RelocationMap, Result, SectionIndex};
use crate::{CompressedData, CompressedFileRange, SectionFlags, SectionKind};
use crate::{ebcdic, goff};

use super::{GoffFile, GoffRelocationIterator, GoffSymbolIndex, GoffSymbolInternal};

/// An iterator for the sections in an [`GoffFile`].
#[derive(Debug)]
pub struct GoffSectionIterator<'data, 'file, R = &'data [u8]>
where
    R: ReadRef<'data>,
{
    pub(super) file: &'file GoffFile<'data, R>,
    pub(super) iter: iter::Enumerate<slice::Iter<'file, GoffSymbolIndex>>,
}

impl<'data, 'file, R> Iterator for GoffSectionIterator<'data, 'file, R>
where
    R: ReadRef<'data>,
{
    type Item = GoffSection<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        let (index, symbol_index) = self.iter.next()?;
        Some(GoffSection::new(
            self.file,
            SectionIndex(index),
            *symbol_index,
        ))
    }
}

/// A section in an [`GoffFile`].
///
/// Most functionality is provided by the [`ObjectSection`] trait implementation.
pub struct GoffSection<'data, 'file, R = &'data [u8]>
where
    R: ReadRef<'data>,
{
    file: &'file GoffFile<'data, R>,
    symbol: &'file GoffSymbolInternal<'data>,
    index: SectionIndex,
}

impl<'data, 'file, R> fmt::Debug for GoffSection<'data, 'file, R>
where
    R: ReadRef<'data>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoffSection")
            .field("esdid", &self.symbol.esdid())
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl<'data, 'file, R: ReadRef<'data>> GoffSection<'data, 'file, R> {
    pub(super) fn new(
        file: &'file GoffFile<'data, R>,
        index: SectionIndex,
        symbol_index: GoffSymbolIndex,
    ) -> Self {
        GoffSection {
            file,
            index,
            symbol: file.symbols.get_by_index(symbol_index),
        }
    }

    /// Returns GOFF section data by collecting TXT record payloads for this section
    /// and any descendant elements.
    pub fn data_parts(&self) -> Result<alloc::vec::Vec<u8>> {
        let mut data = alloc::vec::Vec::new();
        for txt in self.symbol.text() {
            for part in txt.txt_data_parts()? {
                data.extend_from_slice(part);
            }
        }
        Ok(data)
    }

    /// Returns GOFF section name bytes from the flattened symbol name.
    pub fn goff_name_bytes(&self) -> Result<&'file [u8]> {
        let name = self.symbol.name_bytes();
        if name.is_empty() {
            Err(Error("Invalid GOFF section, empty section name"))
        } else {
            Ok(name)
        }
    }
}

impl<'data, 'file, R> read::private::Sealed for GoffSection<'data, 'file, R> where R: ReadRef<'data> {}

// DC: ObjectSection trait at read/traits.rs
impl<'data, 'file, R> ObjectSection<'data> for GoffSection<'data, 'file, R>
where
    R: ReadRef<'data>,
{
    type RelocationIterator = GoffRelocationIterator<'data, 'file, R>;

    fn index(&self) -> SectionIndex {
        self.index
    }

    fn address(&self) -> u64 {
        0
    }

    fn size(&self) -> u64 {
        u64::from(self.symbol.length())
    }

    fn align(&self) -> u64 {
        match self.symbol.record().behavioral_attributes.alignment() {
            goff::ALIGN_BYTE => 1,
            goff::ALIGN_HALFWORD => 2,
            goff::ALIGN_FULLWORD => 4,
            goff::ALIGN_DOUBLEWORD => 8,
            goff::ALIGN_QUADWORD => 16,
            goff::ALIGN_32BYTE => 32,
            goff::ALIGN_64BYTE => 64,
            goff::ALIGN_128BYTE => 128,
            goff::ALIGN_256BYTE => 256,
            goff::ALIGN_512BYTE => 512,
            goff::ALIGN_1024BYTE => 1024,
            goff::ALIGN_2KB => 2048,
            goff::ALIGN_4KB => 4096,
            _ => 1, // Default to byte alignment
        }
    }

    fn file_range(&self) -> Option<(u64, u64)> {
        None
    }

    fn data(&self) -> Result<&'data [u8]> {
        Err(Error(
            "GOFF section data is non-contiguous, use uncompressed_data() instead",
        ))
    }

    fn data_range(&self, _address: u64, _size: u64) -> Result<Option<&'data [u8]>> {
        // GOFF sections do not have an address
        Ok(None)
    }

    fn compressed_file_range(&self) -> Result<CompressedFileRange> {
        Ok(CompressedFileRange::none(self.file_range()))
    }

    fn compressed_data(&self) -> Result<CompressedData<'data>> {
        // GOFF doesn't support compression
        // Return a special marker that will cause decompress() to fail with a helpful message
        // This ensures that if someone calls the default uncompressed_data() implementation,
        // they get a clear error message
        Err(Error(
            "GOFF section data is non-contiguous, use uncompressed_data() instead",
        ))
    }

    // Override the default uncompressed_data() implementation
    // This is the correct way to get GOFF section data
    fn uncompressed_data(&self) -> Result<Cow<'data, [u8]>> {
        let data = self.data_parts()?;

        if data.is_empty() {
            Ok(alloc::borrow::Cow::Borrowed(&[]))
        } else {
            Ok(alloc::borrow::Cow::Owned(data))
        }
    }

    fn name_bytes(&self) -> read::Result<&'data [u8]> {
        Err(Error(
            "GOFF section names are non-contiguous EBCDIC. Use name_utf8() instead",
        ))
    }

    fn name(&self) -> read::Result<&'data str> {
        Err(Error(
            "GOFF section names are non-contiguous EBCDIC. Use name_utf8() instead",
        ))
    }

    fn name_utf8(&self) -> read::Result<Cow<'data, str>> {
        let name = self.goff_name_bytes()?;
        Ok(Cow::Owned(ebcdic::to_string(name)))
    }

    fn segment_name_bytes(&self) -> Result<Option<&[u8]>> {
        Ok(None)
    }

    fn segment_name(&self) -> Result<Option<&str>> {
        Ok(None)
    }

    fn kind(&self) -> SectionKind {
        let flags = self.symbol.record().behavioral_attributes;
        if flags.executable() == goff::EXEC_CODE {
            SectionKind::Text
        } else if flags.is_read_only() {
            SectionKind::ReadOnlyData
        } else {
            SectionKind::Data
        }
    }

    fn relocations(&self) -> Self::RelocationIterator {
        GoffRelocationIterator {
            file: self.file,
            relocations: self.symbol.relocations().iter(),
        }
    }

    fn relocation_map(&self) -> read::Result<RelocationMap> {
        unimplemented!(); // GOFF: not needed
    }

    fn flags(&self) -> SectionFlags {
        SectionFlags::Goff {
            flags: self.symbol.record().behavioral_attributes,
        }
    }
}
