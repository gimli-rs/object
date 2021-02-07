use core::fmt::Debug;
use core::{iter, mem, slice, str};

use crate::elf;
use crate::endian::{self, Endianness, U32Bytes};
use crate::pod::{Bytes, Pod};
use crate::read::{
    self, CompressedData, CompressionFormat, Error, ObjectSection, ReadError, ReadRef,
    SectionFlags, SectionIndex, SectionKind, StringTable,
};

use super::{
    CompressionHeader, ElfFile, ElfSectionRelocationIterator, FileHeader, NoteIterator,
    RelocationSections, SymbolTable,
};

/// The table of section headers in an ELF file.
///
/// Also includes the string table used for the section names.
#[derive(Debug, Default, Clone, Copy)]
pub struct SectionTable<'data, Elf: FileHeader> {
    sections: &'data [Elf::SectionHeader],
    strings: StringTable<'data>,
}

impl<'data, Elf: FileHeader> SectionTable<'data, Elf> {
    /// Create a new section table.
    #[inline]
    pub fn new(sections: &'data [Elf::SectionHeader], strings: StringTable<'data>) -> Self {
        SectionTable { sections, strings }
    }

    /// Iterate over the section headers.
    #[inline]
    pub fn iter(&self) -> slice::Iter<'data, Elf::SectionHeader> {
        self.sections.iter()
    }

    /// Return true if the section table is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.sections.is_empty()
    }

    /// The number of section headers.
    #[inline]
    pub fn len(&self) -> usize {
        self.sections.len()
    }

    /// Return the section header at the given index.
    pub fn section(&self, index: usize) -> read::Result<&'data Elf::SectionHeader> {
        self.sections
            .get(index)
            .read_error("Invalid ELF section index")
    }

    /// Return the section header with the given name.
    ///
    /// Ignores sections with invalid names.
    pub fn section_by_name(
        &self,
        endian: Elf::Endian,
        name: &[u8],
    ) -> Option<(usize, &'data Elf::SectionHeader)> {
        self.sections
            .iter()
            .enumerate()
            .find(|(_, section)| self.section_name(endian, section) == Ok(name))
    }

    /// Return the section name for the given section header.
    pub fn section_name(
        &self,
        endian: Elf::Endian,
        section: &'data Elf::SectionHeader,
    ) -> read::Result<&'data [u8]> {
        section.name(endian, self.strings)
    }

    /// Return the symbol table of the given section type.
    ///
    /// Returns an empty symbol table if the symbol table does not exist.
    #[inline]
    pub fn symbols<R: ReadRef<'data>>(
        &self,
        endian: Elf::Endian,
        data: R,
        sh_type: u32,
    ) -> read::Result<SymbolTable<'data, Elf>> {
        debug_assert!(sh_type == elf::SHT_DYNSYM || sh_type == elf::SHT_SYMTAB);

        let (index, section) = match self
            .iter()
            .enumerate()
            .find(|s| s.1.sh_type(endian) == sh_type)
        {
            Some(s) => s,
            None => return Ok(SymbolTable::default()),
        };

        SymbolTable::parse(endian, data, self, index, section)
    }

    /// Return the symbol table at the given section index.
    ///
    /// Returns an error if the section is not a symbol table.
    #[inline]
    pub fn symbol_table_by_index<R: ReadRef<'data>>(
        &self,
        endian: Elf::Endian,
        data: R,
        index: usize,
    ) -> read::Result<SymbolTable<'data, Elf>> {
        let section = self.section(index)?;
        match section.sh_type(endian) {
            elf::SHT_DYNSYM | elf::SHT_SYMTAB => {}
            _ => return Err(Error("Invalid ELF symbol table section type.")),
        }
        SymbolTable::parse(endian, data, self, index, section)
    }

    /// Create a mapping from section index to associated relocation sections.
    #[inline]
    pub fn relocation_sections(
        &self,
        endian: Elf::Endian,
        symbol_section: usize,
    ) -> read::Result<RelocationSections> {
        RelocationSections::parse(endian, self, symbol_section)
    }
}

/// An iterator over the sections of an `ElfFile32`.
pub type ElfSectionIterator32<'data, 'file, R, Endian = Endianness> =
    ElfSectionIterator<'data, 'file, elf::FileHeader32<Endian>, R>;
/// An iterator over the sections of an `ElfFile64`.
pub type ElfSectionIterator64<'data, 'file, R, Endian = Endianness> =
    ElfSectionIterator<'data, 'file, elf::FileHeader64<Endian>, R>;

/// An iterator over the sections of an `ElfFile`.
#[derive(Debug)]
pub struct ElfSectionIterator<'data, 'file, Elf, R>
where
    'data: 'file,
    Elf: FileHeader,
    R: ReadRef<'data>,
{
    pub(super) file: &'file ElfFile<'data, Elf, R>,
    pub(super) iter: iter::Enumerate<slice::Iter<'data, Elf::SectionHeader>>,
}

impl<'data, 'file, Elf: FileHeader, R: ReadRef<'data>> Iterator
    for ElfSectionIterator<'data, 'file, Elf, R>
{
    type Item = ElfSection<'data, 'file, Elf, R>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|(index, section)| ElfSection {
            index: SectionIndex(index),
            file: self.file,
            section,
        })
    }
}

/// A section of an `ElfFile32`.
pub type ElfSection32<'data, 'file, R, Endian = Endianness> =
    ElfSection<'data, 'file, elf::FileHeader32<Endian>, R>;
/// A section of an `ElfFile64`.
pub type ElfSection64<'data, 'file, R, Endian = Endianness> =
    ElfSection<'data, 'file, elf::FileHeader64<Endian>, R>;

/// A section of an `ElfFile`.
#[derive(Debug)]
pub struct ElfSection<'data, 'file, Elf, R>
where
    'data: 'file,
    Elf: FileHeader,
    R: ReadRef<'data>,
{
    pub(super) file: &'file ElfFile<'data, Elf, R>,
    pub(super) index: SectionIndex,
    pub(super) section: &'data Elf::SectionHeader,
}

impl<'data, 'file, Elf: FileHeader, R: ReadRef<'data>> ElfSection<'data, 'file, Elf, R> {
    fn bytes(&self) -> read::Result<Bytes<'data>> {
        self.section
            .data(self.file.endian, self.file.data)
            .read_error("Invalid ELF section size or offset")
    }

    fn maybe_compressed_data(&self) -> read::Result<Option<CompressedData<'data>>> {
        let endian = self.file.endian;
        if (self.section.sh_flags(endian).into() & u64::from(elf::SHF_COMPRESSED)) == 0 {
            return Ok(None);
        }

        let mut data = self
            .section
            .data(endian, self.file.data)
            .read_error("Invalid ELF compressed section offset or size")?;
        let header = data
            .read::<Elf::CompressionHeader>()
            .read_error("Invalid ELF compression header size or alignment")?;
        if header.ch_type(endian) != elf::ELFCOMPRESS_ZLIB {
            return Err(Error("Unsupported ELF compression type"));
        }
        let uncompressed_size: u64 = header.ch_size(endian).into();
        Ok(Some(CompressedData {
            format: CompressionFormat::Zlib,
            data: data.0,
            uncompressed_size: uncompressed_size as usize,
        }))
    }

    /// Try GNU-style "ZLIB" header decompression.
    fn maybe_compressed_data_gnu(&self) -> read::Result<Option<CompressedData<'data>>> {
        let name = match self.name() {
            Ok(name) => name,
            // I think it's ok to ignore this error?
            Err(_) => return Ok(None),
        };
        if !name.starts_with(".zdebug_") {
            return Ok(None);
        }
        let mut data = self.bytes()?;
        // Assume ZLIB-style uncompressed data is no more than 4GB to avoid accidentally
        // huge allocations. This also reduces the chance of accidentally matching on a
        // .debug_str that happens to start with "ZLIB".
        if data
            .read_bytes(8)
            .read_error("ELF GNU compressed section is too short")?
            .0
            != b"ZLIB\0\0\0\0"
        {
            return Err(Error("Invalid ELF GNU compressed section header"));
        }
        let uncompressed_size = data
            .read::<U32Bytes<_>>()
            .read_error("ELF GNU compressed section is too short")?
            .get(endian::BigEndian);
        Ok(Some(CompressedData {
            format: CompressionFormat::Zlib,
            data: data.0,
            uncompressed_size: uncompressed_size as usize,
        }))
    }
}

impl<'data, 'file, Elf: FileHeader, R: ReadRef<'data>> read::private::Sealed
    for ElfSection<'data, 'file, Elf, R>
{
}

impl<'data, 'file, Elf: FileHeader, R: ReadRef<'data>> ObjectSection<'data>
    for ElfSection<'data, 'file, Elf, R>
{
    type RelocationIterator = ElfSectionRelocationIterator<'data, 'file, Elf, R>;

    #[inline]
    fn index(&self) -> SectionIndex {
        self.index
    }

    #[inline]
    fn address(&self) -> u64 {
        self.section.sh_addr(self.file.endian).into()
    }

    #[inline]
    fn size(&self) -> u64 {
        self.section.sh_size(self.file.endian).into()
    }

    #[inline]
    fn align(&self) -> u64 {
        self.section.sh_addralign(self.file.endian).into()
    }

    #[inline]
    fn file_range(&self) -> Option<(u64, u64)> {
        self.section.file_range(self.file.endian)
    }

    #[inline]
    fn data(&self) -> read::Result<&'data [u8]> {
        Ok(self.bytes()?.0)
    }

    fn data_range(&self, address: u64, size: u64) -> read::Result<Option<&'data [u8]>> {
        Ok(read::data_range(
            self.bytes()?,
            self.address(),
            address,
            size,
        ))
    }

    fn compressed_data(&self) -> read::Result<CompressedData<'data>> {
        Ok(if let Some(data) = self.maybe_compressed_data()? {
            data
        } else if let Some(data) = self.maybe_compressed_data_gnu()? {
            data
        } else {
            CompressedData::none(self.data()?)
        })
    }

    fn name(&self) -> read::Result<&str> {
        let name = self
            .file
            .sections
            .section_name(self.file.endian, self.section)?;
        str::from_utf8(name)
            .ok()
            .read_error("Non UTF-8 ELF section name")
    }

    #[inline]
    fn segment_name(&self) -> read::Result<Option<&str>> {
        Ok(None)
    }

    fn kind(&self) -> SectionKind {
        let flags = self.section.sh_flags(self.file.endian).into();
        let sh_type = self.section.sh_type(self.file.endian);
        match sh_type {
            elf::SHT_PROGBITS => {
                if flags & u64::from(elf::SHF_ALLOC) != 0 {
                    if flags & u64::from(elf::SHF_EXECINSTR) != 0 {
                        SectionKind::Text
                    } else if flags & u64::from(elf::SHF_TLS) != 0 {
                        SectionKind::Tls
                    } else if flags & u64::from(elf::SHF_WRITE) != 0 {
                        SectionKind::Data
                    } else if flags & u64::from(elf::SHF_STRINGS) != 0 {
                        SectionKind::ReadOnlyString
                    } else {
                        SectionKind::ReadOnlyData
                    }
                } else if flags & u64::from(elf::SHF_STRINGS) != 0 {
                    SectionKind::OtherString
                } else {
                    SectionKind::Other
                }
            }
            elf::SHT_NOBITS => {
                if flags & u64::from(elf::SHF_TLS) != 0 {
                    SectionKind::UninitializedTls
                } else {
                    SectionKind::UninitializedData
                }
            }
            elf::SHT_NOTE => SectionKind::Note,
            elf::SHT_NULL
            | elf::SHT_SYMTAB
            | elf::SHT_STRTAB
            | elf::SHT_RELA
            | elf::SHT_HASH
            | elf::SHT_DYNAMIC
            | elf::SHT_REL
            | elf::SHT_DYNSYM
            | elf::SHT_GROUP => SectionKind::Metadata,
            _ => SectionKind::Elf(sh_type),
        }
    }

    fn relocations(&self) -> ElfSectionRelocationIterator<'data, 'file, Elf, R> {
        ElfSectionRelocationIterator {
            section_index: self.index.0,
            file: self.file,
            relocations: None,
        }
    }

    fn flags(&self) -> SectionFlags {
        SectionFlags::Elf {
            sh_flags: self.section.sh_flags(self.file.endian).into(),
        }
    }
}

/// A trait for generic access to `SectionHeader32` and `SectionHeader64`.
#[allow(missing_docs)]
pub trait SectionHeader: Debug + Pod {
    type Elf: FileHeader<SectionHeader = Self, Endian = Self::Endian, Word = Self::Word>;
    type Word: Into<u64>;
    type Endian: endian::Endian;

    fn sh_name(&self, endian: Self::Endian) -> u32;
    fn sh_type(&self, endian: Self::Endian) -> u32;
    fn sh_flags(&self, endian: Self::Endian) -> Self::Word;
    fn sh_addr(&self, endian: Self::Endian) -> Self::Word;
    fn sh_offset(&self, endian: Self::Endian) -> Self::Word;
    fn sh_size(&self, endian: Self::Endian) -> Self::Word;
    fn sh_link(&self, endian: Self::Endian) -> u32;
    fn sh_info(&self, endian: Self::Endian) -> u32;
    fn sh_addralign(&self, endian: Self::Endian) -> Self::Word;
    fn sh_entsize(&self, endian: Self::Endian) -> Self::Word;

    /// Parse the section name from the string table.
    fn name<'data>(
        &self,
        endian: Self::Endian,
        strings: StringTable<'data>,
    ) -> read::Result<&'data [u8]> {
        strings
            .get(self.sh_name(endian))
            .read_error("Invalid ELF section name offset")
    }

    /// Return the offset and size of the section in the file.
    ///
    /// Returns `None` for sections that have no data in the file.
    fn file_range(&self, endian: Self::Endian) -> Option<(u64, u64)> {
        if self.sh_type(endian) == elf::SHT_NOBITS {
            None
        } else {
            Some((self.sh_offset(endian).into(), self.sh_size(endian).into()))
        }
    }

    /// Return the section data.
    ///
    /// Returns `Ok(&[])` if the section has no data.
    /// Returns `Err` for invalid values.
    fn data<'data, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        data: R,
    ) -> Result<Bytes<'data>, ()> {
        if let Some((offset, size)) = self.file_range(endian) {
            data.read_bytes_at(offset as usize, size as usize)
                .map(Bytes)
        } else {
            Ok(Bytes(&[]))
        }
    }

    /// Return the section data as a slice of the given type.
    ///
    /// Allows padding at the end of the data.
    /// Returns `Ok(&[])` if the section has no data.
    /// Returns `Err` for invalid values, including bad alignment.
    fn data_as_array<'data, T: Pod, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        data: R,
    ) -> Result<&'data [T], ()> {
        let mut data = self.data(endian, data)?;
        data.read_slice(data.len() / mem::size_of::<T>())
    }

    /// Return the symbols in the section.
    ///
    /// Also finds the corresponding string table in `sections`.
    ///
    /// `section_index` must be the 0-based index of this section, and is used
    /// to find the corresponding extended section index table in `sections`.
    ///
    /// Returns `Ok(None)` if the section does not contain symbols.
    /// Returns `Err` for invalid values.
    fn symbols<'data, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        data: R,
        sections: &SectionTable<Self::Elf>,
        section_index: usize,
    ) -> read::Result<Option<SymbolTable<'data, Self::Elf>>> {
        let sh_type = self.sh_type(endian);
        if sh_type != elf::SHT_SYMTAB && sh_type != elf::SHT_DYNSYM {
            return Ok(None);
        }
        SymbolTable::parse(endian, data, sections, section_index, self).map(Some)
    }

    /// Return the `Elf::Rel` entries in the section.
    ///
    /// Returns `Ok(None)` if the section does not contain relocations.
    /// Returns `Err` for invalid values.
    fn rel<'data, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        data: R,
    ) -> read::Result<Option<&'data [<Self::Elf as FileHeader>::Rel]>> {
        if self.sh_type(endian) != elf::SHT_REL {
            return Ok(None);
        }
        self.data_as_array(endian, data)
            .map(Some)
            .read_error("Invalid ELF relocation section offset or size")
    }

    /// Return the `Elf::Rela` entries in the section.
    ///
    /// Returns `Ok(None)` if the section does not contain relocations.
    /// Returns `Err` for invalid values.
    fn rela<'data, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        data: R,
    ) -> read::Result<Option<&'data [<Self::Elf as FileHeader>::Rela]>> {
        if self.sh_type(endian) != elf::SHT_RELA {
            return Ok(None);
        }
        self.data_as_array(endian, data)
            .map(Some)
            .read_error("Invalid ELF relocation section offset or size")
    }

    /// Return the symbol table for a relocation section.
    ///
    /// Returns `Err` for invalid values, including if the section does not contain
    /// relocations.
    fn relocation_symbols<'data, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        data: R,
        sections: &SectionTable<'data, Self::Elf>,
    ) -> read::Result<SymbolTable<'data, Self::Elf>> {
        let sh_type = self.sh_type(endian);
        if sh_type != elf::SHT_REL && sh_type != elf::SHT_RELA {
            return Err(Error("Invalid ELF relocation section type"));
        }
        sections.symbol_table_by_index(endian, data, self.sh_link(endian) as usize)
    }

    /// Return a note iterator for the section data.
    ///
    /// Returns `Ok(None)` if the section does not contain notes.
    /// Returns `Err` for invalid values.
    fn notes<'data, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        data: R,
    ) -> read::Result<Option<NoteIterator<'data, Self::Elf>>> {
        if self.sh_type(endian) != elf::SHT_NOTE {
            return Ok(None);
        }
        let data = self
            .data(endian, data)
            .read_error("Invalid ELF note section offset or size")?;
        let notes = NoteIterator::new(endian, self.sh_addralign(endian), data)?;
        Ok(Some(notes))
    }

    /// Return the contents of a group section.
    ///
    /// The first value is a `GRP_*` value, and the remaining values
    /// are section indices.
    ///
    /// Returns `Ok(None)` if the section does not define a group.
    /// Returns `Err` for invalid values.
    fn group<'data, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        data: R,
    ) -> read::Result<Option<(u32, &'data [U32Bytes<Self::Endian>])>> {
        if self.sh_type(endian) != elf::SHT_GROUP {
            return Ok(None);
        }
        let mut data = self
            .data(endian, data)
            .read_error("Invalid ELF group section offset or size")?;
        let flag = data
            .read::<U32Bytes<_>>()
            .read_error("Invalid ELF group section offset or size")?
            .get(endian);
        let count = data.len() / mem::size_of::<U32Bytes<Self::Endian>>();
        let sections = data
            .read_slice(count)
            .read_error("Invalid ELF group section offset or size")?;
        Ok(Some((flag, sections)))
    }
}

impl<Endian: endian::Endian> SectionHeader for elf::SectionHeader32<Endian> {
    type Elf = elf::FileHeader32<Endian>;
    type Word = u32;
    type Endian = Endian;

    #[inline]
    fn sh_name(&self, endian: Self::Endian) -> u32 {
        self.sh_name.get(endian)
    }

    #[inline]
    fn sh_type(&self, endian: Self::Endian) -> u32 {
        self.sh_type.get(endian)
    }

    #[inline]
    fn sh_flags(&self, endian: Self::Endian) -> Self::Word {
        self.sh_flags.get(endian)
    }

    #[inline]
    fn sh_addr(&self, endian: Self::Endian) -> Self::Word {
        self.sh_addr.get(endian)
    }

    #[inline]
    fn sh_offset(&self, endian: Self::Endian) -> Self::Word {
        self.sh_offset.get(endian)
    }

    #[inline]
    fn sh_size(&self, endian: Self::Endian) -> Self::Word {
        self.sh_size.get(endian)
    }

    #[inline]
    fn sh_link(&self, endian: Self::Endian) -> u32 {
        self.sh_link.get(endian)
    }

    #[inline]
    fn sh_info(&self, endian: Self::Endian) -> u32 {
        self.sh_info.get(endian)
    }

    #[inline]
    fn sh_addralign(&self, endian: Self::Endian) -> Self::Word {
        self.sh_addralign.get(endian)
    }

    #[inline]
    fn sh_entsize(&self, endian: Self::Endian) -> Self::Word {
        self.sh_entsize.get(endian)
    }
}

impl<Endian: endian::Endian> SectionHeader for elf::SectionHeader64<Endian> {
    type Word = u64;
    type Endian = Endian;
    type Elf = elf::FileHeader64<Endian>;

    #[inline]
    fn sh_name(&self, endian: Self::Endian) -> u32 {
        self.sh_name.get(endian)
    }

    #[inline]
    fn sh_type(&self, endian: Self::Endian) -> u32 {
        self.sh_type.get(endian)
    }

    #[inline]
    fn sh_flags(&self, endian: Self::Endian) -> Self::Word {
        self.sh_flags.get(endian)
    }

    #[inline]
    fn sh_addr(&self, endian: Self::Endian) -> Self::Word {
        self.sh_addr.get(endian)
    }

    #[inline]
    fn sh_offset(&self, endian: Self::Endian) -> Self::Word {
        self.sh_offset.get(endian)
    }

    #[inline]
    fn sh_size(&self, endian: Self::Endian) -> Self::Word {
        self.sh_size.get(endian)
    }

    #[inline]
    fn sh_link(&self, endian: Self::Endian) -> u32 {
        self.sh_link.get(endian)
    }

    #[inline]
    fn sh_info(&self, endian: Self::Endian) -> u32 {
        self.sh_info.get(endian)
    }

    #[inline]
    fn sh_addralign(&self, endian: Self::Endian) -> Self::Word {
        self.sh_addralign.get(endian)
    }

    #[inline]
    fn sh_entsize(&self, endian: Self::Endian) -> Self::Word {
        self.sh_entsize.get(endian)
    }
}
