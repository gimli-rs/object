use alloc::vec::Vec;
use core::fmt::Debug;
use core::{mem, str};
use target_lexicon::Architecture;

use crate::endian::LittleEndian as LE;
use crate::pe;
use crate::pod::{Bytes, Pod};
use crate::read::coff::{parse_symbol, CoffSymbolIterator, SymbolTable};
use crate::read::{
    self, Error, FileFlags, Object, ObjectSection, ReadError, Result, SectionIndex, Symbol,
    SymbolIndex, SymbolMap,
};

use super::{PeSection, PeSectionIterator, PeSegment, PeSegmentIterator};

/// A PE32 (32-bit) image file.
pub type PeFile32<'data> = PeFile<'data, pe::ImageNtHeaders32>;
/// A PE32+ (64-bit) image file.
pub type PeFile64<'data> = PeFile<'data, pe::ImageNtHeaders64>;

/// A PE object file.
#[derive(Debug)]
pub struct PeFile<'data, Pe: ImageNtHeaders> {
    pub(super) dos_header: &'data pe::ImageDosHeader,
    pub(super) nt_headers: &'data Pe,
    pub(super) data_directories: &'data [pe::ImageDataDirectory],
    pub(super) sections: &'data [pe::ImageSectionHeader],
    pub(super) symbols: SymbolTable<'data>,
    pub(super) data: Bytes<'data>,
}

impl<'data, Pe: ImageNtHeaders> PeFile<'data, Pe> {
    /// Find the optional header and read the `optional_header.magic`.
    pub fn optional_header_magic(data: &'data [u8]) -> Result<u16> {
        let data = Bytes(data);
        // DOS header comes first.
        let dos_header = data
            .read_at::<pe::ImageDosHeader>(0)
            .read_error("Invalid DOS header size or alignment")?;
        if dos_header.e_magic.get(LE) != pe::IMAGE_DOS_SIGNATURE {
            return Err(Error("Invalid DOS magic"));
        }
        // NT headers are at an offset specified in the DOS header.
        let nt_headers = data
            .read_at::<Pe>(dos_header.e_lfanew.get(LE) as usize)
            .read_error("Invalid NT headers offset, size, or alignment")?;
        if nt_headers.signature() != pe::IMAGE_NT_SIGNATURE {
            return Err(Error("Invalid PE magic"));
        }
        Ok(nt_headers.optional_header().magic())
    }

    /// Parse the raw PE file data.
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        let data = Bytes(data);
        // DOS header comes first.
        let dos_header = data
            .read_at::<pe::ImageDosHeader>(0)
            .read_error("Invalid DOS header size or alignment")?;
        if dos_header.e_magic.get(LE) != pe::IMAGE_DOS_SIGNATURE {
            return Err(Error("Invalid DOS magic"));
        }

        // NT headers are at an offset specified in the DOS header.
        let mut nt_tail = data;
        nt_tail
            .skip(dos_header.e_lfanew.get(LE) as usize)
            .read_error("Invalid PE headers offset")?;
        // Note that this does not include the data directories in the optional header.
        let nt_headers = nt_tail
            .read::<Pe>()
            .read_error("Invalid PE headers size or alignment")?;
        if nt_headers.signature() != pe::IMAGE_NT_SIGNATURE {
            return Err(Error("Invalid PE magic"));
        }
        if !nt_headers.is_valid_optional_magic() {
            return Err(Error("Invalid PE optional header magic"));
        }

        // Read the rest of the optional header, and then read the data directories from that.
        let optional_data_size = (nt_headers.file_header().size_of_optional_header.get(LE)
            as usize)
            .checked_sub(mem::size_of::<Pe::ImageOptionalHeader>())
            .read_error("PE optional header size is too small")?;
        let mut optional_data = nt_tail
            .read_bytes(optional_data_size)
            .read_error("Invalid PE optional header size")?;
        let data_directories = optional_data
            .read_slice(nt_headers.optional_header().number_of_rva_and_sizes() as usize)
            .read_error("Invalid PE number of RVA and sizes")?;

        // Section headers are after the optional header.
        let sections = nt_tail
            .read_slice(nt_headers.file_header().number_of_sections.get(LE) as usize)
            .read_error("Invalid PE section headers")?;

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

    pub(super) fn section_alignment(&self) -> u64 {
        u64::from(self.nt_headers.optional_header().section_alignment())
    }
}

impl<'data, Pe: ImageNtHeaders> read::private::Sealed for PeFile<'data, Pe> {}

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
            .find(|section| section.name() == Ok(section_name))
    }

    fn section_by_index(&'file self, index: SectionIndex) -> Result<PeSection<'data, 'file, Pe>> {
        let section = self
            .sections
            .get(index.0)
            .read_error("Invalid PE section index")?;
        Ok(PeSection {
            file: self,
            index,
            section,
        })
    }

    fn sections(&'file self) -> PeSectionIterator<'data, 'file, Pe> {
        PeSectionIterator {
            file: self,
            iter: self.sections.iter().enumerate(),
        }
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> Result<Symbol<'data>> {
        let symbol = self
            .symbols
            .get(index.0)
            .read_error("Invalid PE symbol index")?;
        Ok(parse_symbol(&self.symbols, index.0, symbol))
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
        self.section_by_name(".debug_info").is_some()
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
