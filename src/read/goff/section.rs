use alloc::borrow::Cow;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
use alloc::collections::btree_map as hash_map;
use core::fmt::Debug;
use core::str;
#[cfg(feature = "std")]
#[allow(unused_imports)]
use std::collections::hash_map;
//FIXME_GOFF
use crate::{CompressedData, CompressedFileRange, SectionFlags, SectionKind, goff};

use crate::read::{
    self, Error, ObjectSection, ReadRef, RelocationMap, Result, SectionIndex, SymbolIndex,
};

use super::{GoffFile, GoffRelocationIterator};

use alloc::vec::Vec;

/// An iterator for the sections in an [`GoffFile64`](super::GoffFile64).
pub type GoffSectionIterator64<'data, 'file, R = &'data [u8]> =
    GoffSectionIterator<'data, 'file, R>;

/// An iterator for the sections in an [`GoffFile`].
#[derive(Debug)]
pub struct GoffSectionIterator<'data, 'file, R = &'data [u8]>
where
    R: ReadRef<'data>,
{
    pub(super) file: &'file GoffFile<'data, R>,
    pub(super) iter: std::slice::Iter<'file, SymbolIndex>,
    pub(super) index: usize,
}

impl<'data, 'file, R> Iterator for GoffSectionIterator<'data, 'file, R>
where
    R: ReadRef<'data>,
{
    type Item = GoffSection<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        let next_item = self.iter.next();
        if next_item.is_none() {
            None
        } else {
            let current_index = self.index;
            self.index += 1;
            Some(GoffSection {
                esdid: *next_item.unwrap(),
                file: self.file,
                index: SectionIndex(current_index),
            })
        }
    }
}

/// A section in an [`GoffFile64`](super::GoffFile64).
pub type GoffSection64<'data, 'file, R = &'data [u8]> = GoffSection<'data, 'file, R>;

/// A section in an [`GoffFile`].
///
/// Most functionality is provided by the [`ObjectSection`] trait implementation.
pub struct GoffSection<'data, 'file, R = &'data [u8]>
where
    R: ReadRef<'data>,
{
    pub(super) file: &'file GoffFile<'data, R>,
    pub(super) esdid: SymbolIndex,
    pub(super) index: SectionIndex,
}

impl<'data, 'file, R> core::fmt::Debug for GoffSection<'data, 'file, R>
where
    R: ReadRef<'data>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GoffSection")
            .field("esdid", &self.esdid)
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl<'data, 'file, R: ReadRef<'data>> GoffSection<'data, 'file, R> {
    /// Check if an ESDID is a descendant (child, grandchild, etc.) of a parent ESDID
    fn is_descendant_of(&self, esdid: &SymbolIndex, parent_esdid: &SymbolIndex) -> bool {
        if let Some(symbol) = self.file.symbols.get(esdid) {
            if symbol.parentesdid == *parent_esdid {
                return true;
            }
            // Recursively check if this symbol's parent is a descendant
            if symbol.parentesdid != *esdid {
                return self.is_descendant_of(&symbol.parentesdid, parent_esdid);
            }
        }
        false
    }

    /// Returns GOFF section data by collecting TXT record payloads for this section
    /// and any descendant elements.
    pub fn data_parts(&self) -> alloc::vec::Vec<u8> {
        let mut data = alloc::vec::Vec::new();
        for (segment_esdid, segment) in &self.file.segments {
            if *segment_esdid == self.esdid || self.is_descendant_of(segment_esdid, &self.esdid) {
                for txt in &segment.text_refs {
                    for part in &txt.text_data {
                        data.extend_from_slice(part);
                    }
                }
            }
        }
        data
    }

    /// Returns GOFF section name bytes by collecting the symbol name parts for this section.
    pub fn name_bytes_parts(&self) -> Result<Cow<'data, [u8]>> {
        let symbol = self
            .file
            .symbols
            .get(&self.esdid)
            .ok_or(Error("Invalid GOFF section ESDID"))?;

        match symbol.name_parts() {
            [] => Err(Error("Invalid GOFF section, empty section name")),
            [single_chunk] => Ok(Cow::Borrowed(single_chunk)),
            parts => {
                let total_len = parts.iter().map(|part| part.len()).sum();
                let mut name = Vec::with_capacity(total_len);
                for part in parts {
                    name.extend_from_slice(part);
                }
                Ok(Cow::Owned(name))
            }
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
        self.file
            .symbols
            .get(&self.esdid)
            .map(|symbol| symbol.length as u64)
            .unwrap_or(0)
    }

    fn align(&self) -> u64 {
        self.file
            .symbols
            .get(&self.esdid)
            .map(|symbol| {
                // Extract alignment from byte 6 (index 5) bits 3-7 of behavioral attributes
                let align_flags = goff::AlignmentFlags(symbol.behavioralattributes[5] & 0xF8);
                match align_flags {
                    goff::GOFF_ALIGN_BYTE => 1,
                    goff::GOFF_ALIGN_HALFWORD => 2,
                    goff::GOFF_ALIGN_FULLWORD => 4,
                    goff::GOFF_ALIGN_DOUBLEWORD => 8,
                    goff::GOFF_ALIGN_QUADWORD => 16,
                    goff::GOFF_ALIGN_32BYTE => 32,
                    goff::GOFF_ALIGN_64BYTE => 64,
                    goff::GOFF_ALIGN_128BYTE => 128,
                    goff::GOFF_ALIGN_256BYTE => 256,
                    goff::GOFF_ALIGN_512BYTE => 512,
                    goff::GOFF_ALIGN_1024BYTE => 1024,
                    goff::GOFF_ALIGN_2KB => 2048,
                    goff::GOFF_ALIGN_4KB => 4096,
                    _ => 1, // Default to byte alignment
                }
            })
            .unwrap_or(1)
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
        let data = self.data_parts();

        if data.is_empty() {
            Ok(alloc::borrow::Cow::Borrowed(&[]))
        } else {
            Ok(alloc::borrow::Cow::Owned(data))
        }
    }

    fn name_bytes(&self) -> read::Result<&'data [u8]> {
        Err(Error(
            "Section name data in GOFF in non-contiguous, use GoffSection::name_bytes_parts instead",
        ))
    }

    fn name(&self) -> read::Result<&'data str> {
        Err(Error(
            "Section name data in GOFF in non-contiguous and encoded in ebcidic, use GoffSection::name_bytes_parts instead",
        ))
    }

    fn segment_name_bytes(&self) -> Result<Option<&[u8]>> {
        Err(Error(
            "Segment name data in GOFF in non-contiguous, look up segments by their ESDID",
        ))
    }

    fn segment_name(&self) -> Result<Option<&str>> {
        Err(Error(
            "Segment name data in GOFF in non-contiguous, look up segments by their ESDID",
        ))
    }

    fn kind(&self) -> SectionKind {
        let SectionFlags::Goff { flags } = self.flags() else {
            return SectionKind::Unknown;
        };

        match flags.executable() {
            goff::GOFF_EXEC_CODE => SectionKind::Text,
            _ if flags.is_read_only() => SectionKind::ReadOnlyData,
            _ => SectionKind::Data,
        }
    }

    fn relocations(&self) -> Self::RelocationIterator {
        GoffRelocationIterator {
            file: self.file,
            section_esdid: self.esdid,
            index: 0,
        }
    }

    fn relocation_map(&self) -> read::Result<RelocationMap> {
        unimplemented!(); // GOFF: not needed
    }

    fn flags(&self) -> SectionFlags {
        self.file
            .symbols
            .get(&self.esdid)
            .map(|symbol| {
                let attrs = &symbol.behavioralattributes;
                SectionFlags::Goff {
                    flags: goff::SectionFlags {
                        amode: goff::AmodeFlags(attrs[0]),
                        rmode: goff::RmodeFlags(attrs[1]),
                        text_and_binding: attrs[2],
                        tasking_and_exec: attrs[3],
                        dup_and_strength: attrs[4],
                        loading_and_scope: attrs[5],
                        linkage_and_align: attrs[6],
                        reserved: [attrs[7], attrs[8], attrs[9]],
                    },
                }
            })
            .unwrap_or(SectionFlags::None)
    }
}
