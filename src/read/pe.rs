//! Support for reading ELF files.
//!
//! Defines traits to abstract over the difference between PE32/PE32+,
//! and implements read functionality in terms of these traits.
//!
//! Also provides `PeFile` and related types which implement the `Object` trait.

use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::{cmp, iter, mem, slice, str};
use target_lexicon::Architecture;

use crate::endian::LittleEndian as LE;
use crate::pe;
use crate::pod::{self, Pod};
use crate::read::coff::{
    parse_symbol, section_kind, section_name, CoffSymbolIterator, SymbolTable,
};
use crate::read::{
    self, FileFlags, Object, ObjectSection, ObjectSegment, Relocation, SectionFlags, SectionIndex,
    SectionKind, Symbol, SymbolIndex, SymbolMap,
};

/// A PE32 (32-bit) image file.
pub type PeFile32<'data> = PeFile<'data, pe::ImageNtHeaders32>;
/// A PE32+ (64-bit) image file.
pub type PeFile64<'data> = PeFile<'data, pe::ImageNtHeaders64>;

/// A PE object file.
#[derive(Debug)]
pub struct PeFile<'data, Pe: ImageNtHeaders> {
    dos_header: &'data pe::ImageDosHeader,
    nt_headers: &'data Pe,
    data_directories: &'data [pe::ImageDataDirectory],
    sections: &'data [pe::ImageSectionHeader],
    symbols: SymbolTable<'data>,
    data: &'data [u8],
}

impl<'data, Pe: ImageNtHeaders> PeFile<'data, Pe> {
    /// Find the optional header and read the `optional_header.magic`.
    pub fn optional_header_magic(data: &'data [u8]) -> Option<u16> {
        // DOS header comes first.
        let (dos_header, _) = pod::from_bytes::<pe::ImageDosHeader>(data)?;
        if dos_header.e_magic.get(LE) != pe::IMAGE_DOS_SIGNATURE {
            return None;
        }
        // NT headers are at an offset specified in the DOS header.
        let nt_data = data.get(dos_header.e_lfanew.get(LE) as usize..)?;
        let (nt_headers, _) = pod::from_bytes::<Pe>(nt_data)?;
        if nt_headers.signature() != pe::IMAGE_NT_SIGNATURE {
            return None;
        }
        return Some(nt_headers.optional_header().magic());
    }

    /// Parse the raw PE file data.
    pub fn parse(data: &'data [u8]) -> Result<Self, &'static str> {
        // DOS header comes first.
        let (dos_header, _) = pod::from_bytes::<pe::ImageDosHeader>(data)
            .ok_or("Invalid DOS header size or alignment")?;
        if dos_header.e_magic.get(LE) != pe::IMAGE_DOS_SIGNATURE {
            return Err("Invalid DOS magic");
        }

        // NT headers are at an offset specified in the DOS header.
        let nt_data = data
            .get(dos_header.e_lfanew.get(LE) as usize..)
            .ok_or("Invalid NT headers offset")?;
        // Note that the optional header may overflow into nt_tail.
        let (nt_headers, nt_tail) =
            pod::from_bytes::<Pe>(nt_data).ok_or("Invalid NT headers size or alignment")?;
        if nt_headers.signature() != pe::IMAGE_NT_SIGNATURE {
            return Err("Invalid PE magic");
        }
        if !nt_headers.is_valid_optional_magic() {
            return Err("Invalid optional header magic");
        }

        // The optional header is allowed to be larger than we expected.
        let optional_data_size = (nt_headers.file_header().size_of_optional_header.get(LE)
            as usize)
            .checked_sub(mem::size_of::<Pe::ImageOptionalHeader>())
            .ok_or("Size of optional header is too small")?;
        let optional_data = nt_tail
            .get(..optional_data_size)
            .ok_or("Invalid size of optional header")?;

        // Data directories are at the end the optional header, and are included in its size.
        let (data_directories, _) = pod::slice_from_bytes(
            optional_data,
            0,
            nt_headers.optional_header().number_of_rva_and_sizes() as usize,
        )
        .ok_or("Invalid number of RVA and sizes")?;

        // Section headers are after the optional header.
        let (sections, _) = pod::slice_from_bytes(
            nt_tail,
            optional_data_size,
            nt_headers.file_header().number_of_sections.get(LE) as usize,
        )
        .ok_or("Invalid section headers")?;

        let symbols = SymbolTable::parse(&nt_headers.file_header(), data)?;

        Ok(PeFile {
            dos_header,
            nt_headers,
            data_directories,
            sections,
            symbols,
            data,
        })
    }

    fn section_alignment(&self) -> u64 {
        u64::from(self.nt_headers.optional_header().section_alignment())
    }
}

impl<'data, 'file, Pe> Object<'data, 'file> for PeFile<'data, Pe>
where
    'data: 'file,
    Pe: ImageNtHeaders,
{
    type Segment = PeSegment<'data, 'file, Pe>;
    type SegmentIterator = PeSegmentIterator<'data, 'file, Pe>;
    type Section = PeSection<'data, 'file, Pe>;
    type SectionIterator = PeSectionIterator<'data, 'file, Pe>;
    type SymbolIterator = CoffSymbolIterator<'data, 'file>;

    fn architecture(&self) -> Architecture {
        match self.nt_headers.file_header().machine.get(LE) {
            // TODO: Arm/Arm64
            pe::IMAGE_FILE_MACHINE_I386 => Architecture::I386,
            pe::IMAGE_FILE_MACHINE_AMD64 => Architecture::X86_64,
            _ => Architecture::Unknown,
        }
    }

    #[inline]
    fn is_little_endian(&self) -> bool {
        // Only little endian is supported.
        true
    }

    #[inline]
    fn is_64(&self) -> bool {
        self.nt_headers.is_type_64()
    }

    fn segments(&'file self) -> PeSegmentIterator<'data, 'file, Pe> {
        PeSegmentIterator {
            file: self,
            iter: self.sections.iter(),
        }
    }

    fn section_by_name(&'file self, section_name: &str) -> Option<PeSection<'data, 'file, Pe>> {
        self.sections()
            .find(|section| section.name() == Some(section_name))
    }

    fn section_by_index(&'file self, index: SectionIndex) -> Option<PeSection<'data, 'file, Pe>> {
        self.sections().find(|section| section.index() == index)
    }

    fn sections(&'file self) -> PeSectionIterator<'data, 'file, Pe> {
        PeSectionIterator {
            file: self,
            iter: self.sections.iter().enumerate(),
        }
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> Option<Symbol<'data>> {
        Some(parse_symbol(
            &self.symbols,
            index.0,
            self.symbols.get(index.0)?,
        ))
    }

    fn symbols(&'file self) -> CoffSymbolIterator<'data, 'file> {
        CoffSymbolIterator {
            symbols: &self.symbols,
            index: 0,
        }
    }

    fn dynamic_symbols(&'file self) -> CoffSymbolIterator<'data, 'file> {
        // TODO: return exports/imports
        CoffSymbolIterator {
            symbols: &self.symbols,
            // Hack: don't return any.
            index: self.symbols.symbols.len(),
        }
    }

    fn symbol_map(&self) -> SymbolMap<'data> {
        // TODO: untested
        let mut symbols: Vec<_> = self
            .symbols()
            .map(|(_, s)| s)
            .filter(SymbolMap::filter)
            .collect();
        symbols.sort_by_key(|x| x.address);
        SymbolMap { symbols }
    }

    fn has_debug_symbols(&self) -> bool {
        for section in self.sections {
            if section_name(&section.name, self.symbols.strings) == Some(".debug_info") {
                return true;
            }
        }
        false
    }

    fn entry(&self) -> u64 {
        u64::from(self.nt_headers.optional_header().address_of_entry_point())
    }

    fn flags(&self) -> FileFlags {
        FileFlags::Coff {
            characteristics: self.nt_headers.file_header().characteristics.get(LE),
        }
    }
}

/// An iterator over the loadable sections of a `PeFile32`.
pub type PeSegmentIterator32<'data, 'file> = PeSegmentIterator<'data, 'file, pe::ImageNtHeaders32>;
/// An iterator over the loadable sections of a `PeFile64`.
pub type PeSegmentIterator64<'data, 'file> = PeSegmentIterator<'data, 'file, pe::ImageNtHeaders64>;

/// An iterator over the loadable sections of a `PeFile`.
#[derive(Debug)]
pub struct PeSegmentIterator<'data, 'file, Pe>
where
    'data: 'file,
    Pe: ImageNtHeaders,
{
    file: &'file PeFile<'data, Pe>,
    iter: slice::Iter<'file, pe::ImageSectionHeader>,
}

impl<'data, 'file, Pe: ImageNtHeaders> Iterator for PeSegmentIterator<'data, 'file, Pe> {
    type Item = PeSegment<'data, 'file, Pe>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|section| PeSegment {
            file: self.file,
            section,
        })
    }
}

/// A loadable section of a `PeFile32`.
pub type PeSegment32<'data, 'file> = PeSegment<'data, 'file, pe::ImageNtHeaders32>;
/// A loadable section of a `PeFile64`.
pub type PeSegment64<'data, 'file> = PeSegment<'data, 'file, pe::ImageNtHeaders64>;

/// A loadable section of a `PeFile`.
#[derive(Debug)]
pub struct PeSegment<'data, 'file, Pe>
where
    'data: 'file,
    Pe: ImageNtHeaders,
{
    file: &'file PeFile<'data, Pe>,
    section: &'file pe::ImageSectionHeader,
}

impl<'data, 'file, Pe: ImageNtHeaders> ObjectSegment<'data> for PeSegment<'data, 'file, Pe> {
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
        (
            self.section.pointer_to_raw_data.get(LE) as u64,
            self.section.size_of_raw_data.get(LE) as u64,
        )
    }

    fn data(&self) -> &'data [u8] {
        let offset = self.section.pointer_to_raw_data.get(LE) as usize;
        let size = cmp::min(
            self.section.virtual_size.get(LE),
            self.section.size_of_raw_data.get(LE),
        ) as usize;
        &self.file.data[offset..][..size]
    }

    fn data_range(&self, address: u64, size: u64) -> Option<&'data [u8]> {
        read::data_range(self.data(), self.address(), address, size)
    }

    #[inline]
    fn name(&self) -> Option<&str> {
        section_name(&self.section.name, self.file.symbols.strings)
    }
}

/// An iterator over the sections of a `PeFile32`.
pub type PeSectionIterator32<'data, 'file> = PeSectionIterator<'data, 'file, pe::ImageNtHeaders32>;
/// An iterator over the sections of a `PeFile64`.
pub type PeSectionIterator64<'data, 'file> = PeSectionIterator<'data, 'file, pe::ImageNtHeaders64>;

/// An iterator over the sections of a `PeFile`.
#[derive(Debug)]
pub struct PeSectionIterator<'data, 'file, Pe>
where
    'data: 'file,
    Pe: ImageNtHeaders,
{
    file: &'file PeFile<'data, Pe>,
    iter: iter::Enumerate<slice::Iter<'file, pe::ImageSectionHeader>>,
}

impl<'data, 'file, Pe: ImageNtHeaders> Iterator for PeSectionIterator<'data, 'file, Pe> {
    type Item = PeSection<'data, 'file, Pe>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|(index, section)| PeSection {
            file: self.file,
            index: SectionIndex(index),
            section,
        })
    }
}

/// A section of a `PeFile32`.
pub type PeSection32<'data, 'file> = PeSection<'data, 'file, pe::ImageNtHeaders32>;
/// A section of a `PeFile64`.
pub type PeSection64<'data, 'file> = PeSection<'data, 'file, pe::ImageNtHeaders64>;

/// A section of a `PeFile`.
#[derive(Debug)]
pub struct PeSection<'data, 'file, Pe>
where
    'data: 'file,
    Pe: ImageNtHeaders,
{
    file: &'file PeFile<'data, Pe>,
    index: SectionIndex,
    section: &'file pe::ImageSectionHeader,
}

impl<'data, 'file, Pe: ImageNtHeaders> PeSection<'data, 'file, Pe> {
    fn raw_data(&self) -> &'data [u8] {
        let offset = self.section.pointer_to_raw_data.get(LE) as usize;
        let size = cmp::min(
            self.section.virtual_size.get(LE),
            self.section.size_of_raw_data.get(LE),
        ) as usize;
        &self.file.data[offset..][..size]
    }
}

impl<'data, 'file, Pe: ImageNtHeaders> ObjectSection<'data> for PeSection<'data, 'file, Pe> {
    type RelocationIterator = PeRelocationIterator;

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
        Some((
            u64::from(self.section.pointer_to_raw_data.get(LE)),
            u64::from(self.section.size_of_raw_data.get(LE)),
        ))
    }

    fn data(&self) -> &'data [u8] {
        self.raw_data()
    }

    fn data_range(&self, address: u64, size: u64) -> Option<&'data [u8]> {
        read::data_range(self.raw_data(), self.address(), address, size)
    }

    #[inline]
    fn uncompressed_data(&self) -> Cow<'data, [u8]> {
        Cow::from(self.data())
    }

    #[inline]
    fn name(&self) -> Option<&str> {
        section_name(&self.section.name, self.file.symbols.strings)
    }

    #[inline]
    fn segment_name(&self) -> Option<&str> {
        None
    }

    #[inline]
    fn kind(&self) -> SectionKind {
        section_kind(self.section.characteristics.get(LE))
    }

    fn relocations(&self) -> PeRelocationIterator {
        PeRelocationIterator
    }

    fn flags(&self) -> SectionFlags {
        SectionFlags::Coff {
            characteristics: self.section.characteristics.get(LE),
        }
    }
}

/// An iterator over the relocations in an `PeSection`.
#[derive(Debug)]
pub struct PeRelocationIterator;

impl Iterator for PeRelocationIterator {
    type Item = (u64, Relocation);

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

/// A trait for generic access to `ImageNtHeaders32` and `ImageNtHeaders64`.
#[allow(missing_docs)]
pub trait ImageNtHeaders: Debug + Pod {
    type ImageOptionalHeader: ImageOptionalHeader;

    /// Return true if this type is a 64-bit header.
    ///
    /// This is a property of the type, not a value in the header data.
    fn is_type_64(&self) -> bool;

    /// Return true if the magic field in the optional header is valid.
    fn is_valid_optional_magic(&self) -> bool;

    /// Return the signature
    fn signature(&self) -> u32;

    /// Return the file header.
    fn file_header(&self) -> &pe::ImageFileHeader;

    /// Return the optional header.
    fn optional_header(&self) -> &Self::ImageOptionalHeader;
}

/// A trait for generic access to `ImageOptionalHeader32` and `ImageOptionalHeader64`.
#[allow(missing_docs)]
pub trait ImageOptionalHeader: Debug + Pod {
    fn magic(&self) -> u16;
    fn address_of_entry_point(&self) -> u32;
    fn section_alignment(&self) -> u32;
    fn number_of_rva_and_sizes(&self) -> u32;
}

impl ImageNtHeaders for pe::ImageNtHeaders32 {
    type ImageOptionalHeader = pe::ImageOptionalHeader32;

    #[inline]
    fn is_type_64(&self) -> bool {
        false
    }

    #[inline]
    fn is_valid_optional_magic(&self) -> bool {
        self.optional_header.magic.get(LE) == pe::IMAGE_NT_OPTIONAL_HDR32_MAGIC
    }

    #[inline]
    fn signature(&self) -> u32 {
        self.signature.get(LE)
    }

    #[inline]
    fn file_header(&self) -> &pe::ImageFileHeader {
        &self.file_header
    }

    #[inline]
    fn optional_header(&self) -> &Self::ImageOptionalHeader {
        &self.optional_header
    }
}

impl ImageOptionalHeader for pe::ImageOptionalHeader32 {
    #[inline]
    fn magic(&self) -> u16 {
        self.magic.get(LE)
    }

    #[inline]
    fn address_of_entry_point(&self) -> u32 {
        self.address_of_entry_point.get(LE)
    }

    #[inline]
    fn section_alignment(&self) -> u32 {
        self.section_alignment.get(LE)
    }

    #[inline]
    fn number_of_rva_and_sizes(&self) -> u32 {
        self.number_of_rva_and_sizes.get(LE)
    }
}

impl ImageNtHeaders for pe::ImageNtHeaders64 {
    type ImageOptionalHeader = pe::ImageOptionalHeader64;

    #[inline]
    fn is_type_64(&self) -> bool {
        true
    }

    #[inline]
    fn is_valid_optional_magic(&self) -> bool {
        self.optional_header.magic.get(LE) == pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC
    }

    #[inline]
    fn signature(&self) -> u32 {
        self.signature.get(LE)
    }

    #[inline]
    fn file_header(&self) -> &pe::ImageFileHeader {
        &self.file_header
    }

    #[inline]
    fn optional_header(&self) -> &Self::ImageOptionalHeader {
        &self.optional_header
    }
}

impl ImageOptionalHeader for pe::ImageOptionalHeader64 {
    #[inline]
    fn magic(&self) -> u16 {
        self.magic.get(LE)
    }

    #[inline]
    fn address_of_entry_point(&self) -> u32 {
        self.address_of_entry_point.get(LE)
    }

    #[inline]
    fn section_alignment(&self) -> u32 {
        self.section_alignment.get(LE)
    }

    #[inline]
    fn number_of_rva_and_sizes(&self) -> u32 {
        self.number_of_rva_and_sizes.get(LE)
    }
}
