use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::{mem, str};

use target_lexicon::{Aarch64Architecture, Architecture, ArmArchitecture};

use crate::elf;
use crate::endian::{self, Endian, RunTimeEndian, U32};
use crate::pod::{Bytes, Pod};
use crate::read::util::{self, StringTable};
use crate::read::{
    self, Error, FileFlags, Object, ReadError, SectionIndex, Symbol, SymbolIndex, SymbolMap,
};

use super::{
    parse_symbol, CompressionHeader, ElfSection, ElfSectionIterator, ElfSegment,
    ElfSegmentIterator, ElfSymbolIterator, NoteHeader, ProgramHeader, Rela, SectionHeader, Sym,
    SymbolTable,
};

/// A 32-bit ELF object file.
pub type ElfFile32<'data, Endian = RunTimeEndian> = ElfFile<'data, elf::FileHeader32<Endian>>;
/// A 64-bit ELF object file.
pub type ElfFile64<'data, Endian = RunTimeEndian> = ElfFile<'data, elf::FileHeader64<Endian>>;

/// A partially parsed ELF file.
///
/// Most of the functionality of this type is provided by the `Object` trait implementation.
#[derive(Debug)]
pub struct ElfFile<'data, Elf: FileHeader> {
    pub(super) endian: Elf::Endian,
    pub(super) data: Bytes<'data>,
    pub(super) header: &'data Elf,
    pub(super) segments: &'data [Elf::ProgramHeader],
    pub(super) sections: &'data [Elf::SectionHeader],
    pub(super) section_strings: StringTable<'data>,
    pub(super) relocations: Vec<usize>,
    pub(super) symbols: SymbolTable<'data, Elf>,
    pub(super) dynamic_symbols: SymbolTable<'data, Elf>,
}

impl<'data, Elf: FileHeader> ElfFile<'data, Elf> {
    /// Parse the raw ELF file data.
    pub fn parse(data: &'data [u8]) -> read::Result<Self> {
        let data = Bytes(data);
        let header = data
            .read_at::<Elf>(0)
            .read_error("Invalid ELF header size or alignment")?;
        if !header.is_supported() {
            return Err(Error("Unsupported ELF header"));
        }

        // TODO: Check self.e_ehsize?

        let endian = header.endian()?;
        let segments = header.program_headers(endian, data)?;
        let sections = header.section_headers(endian, data)?;

        let section_string_data = if !sections.is_empty() {
            let index = header.shstrndx(endian, data)?;
            let shstrtab_section = sections
                .get(index as usize)
                .read_error("Invalid ELF section header strtab index")?;
            shstrtab_section
                .data(endian, data)
                .read_error("Invalid ELF section header strtab data")?
        } else {
            Bytes(&[])
        };
        let section_strings = StringTable {
            data: section_string_data,
        };

        let mut symbol_section = None;
        let mut symbols = &[][..];
        let mut symbol_string_data = Bytes(&[]);
        let mut symbol_shndx = &[][..];
        let mut dynamic_symbols = &[][..];
        let mut dynamic_symbol_string_data = Bytes(&[]);
        // TODO: only do this if the user requires it.
        for (index, section) in sections.iter().enumerate() {
            match section.sh_type(endian) {
                elf::SHT_DYNSYM => {
                    if dynamic_symbols.is_empty() {
                        dynamic_symbols = section
                            .data_as_array(endian, data)
                            .read_error("Invalid ELF dynsym data")?;
                        let strtab_section = sections
                            .get(section.sh_link(endian) as usize)
                            .read_error("Invalid ELF dynstr section index")?;
                        dynamic_symbol_string_data = strtab_section
                            .data(endian, data)
                            .read_error("Invalid ELF dynstr data")?;
                    }
                }
                elf::SHT_SYMTAB => {
                    if symbols.is_empty() {
                        symbol_section = Some(index);
                        symbols = section
                            .data_as_array(endian, data)
                            .read_error("Invalid ELF symtab data")?;
                        let strtab_section = sections
                            .get(section.sh_link(endian) as usize)
                            .read_error("Invalid ELF strtab section index")?;
                        symbol_string_data = strtab_section
                            .data(endian, data)
                            .read_error("Invalid ELF strtab data")?;
                    }
                }
                elf::SHT_SYMTAB_SHNDX => {
                    if symbol_shndx.is_empty() {
                        symbol_shndx = section
                            .data_as_array(endian, data)
                            .read_error("Invalid ELF symtab_shndx data")?;
                    }
                }
                _ => {}
            }
        }
        let symbol_strings = StringTable {
            data: symbol_string_data,
        };
        let symbols = SymbolTable {
            symbols,
            strings: symbol_strings,
            shndx: symbol_shndx,
        };
        let dynamic_symbol_strings = StringTable {
            data: dynamic_symbol_string_data,
        };
        let dynamic_symbols = SymbolTable {
            symbols: dynamic_symbols,
            strings: dynamic_symbol_strings,
            shndx: &[],
        };

        // The API we provide requires a mapping from section to relocations, so build it now.
        // TODO: only do this if the user requires it (and then we can return an error
        // for invalid sh_link values).
        let mut relocations = vec![0; sections.len()];
        for (index, section) in sections.iter().enumerate().rev() {
            let sh_type = section.sh_type(endian);
            if sh_type == elf::SHT_REL || sh_type == elf::SHT_RELA {
                let sh_info = section.sh_info(endian) as usize;
                let sh_link = section.sh_link(endian) as usize;
                // Skip dynamic relocations (sh_info = 0), invalid sh_info, and section
                // relocations with the wrong symbol table (sh_link).
                if sh_info != 0 && sh_info < relocations.len() && Some(sh_link) == symbol_section {
                    // Handle multiple relocation sections by chaining them.
                    let next = relocations[sh_info];
                    relocations[sh_info] = index;
                    relocations[index] = next;
                }
            }
        }

        Ok(ElfFile {
            endian,
            header,
            segments,
            sections,
            section_strings,
            relocations,
            symbols,
            dynamic_symbols,
            data,
        })
    }

    fn raw_section_by_name<'file>(
        &'file self,
        section_name: &str,
    ) -> Option<ElfSection<'data, 'file, Elf>> {
        for (index, section) in self.sections.iter().enumerate() {
            if let Ok(name) = self.section_strings.get(section.sh_name(self.endian)) {
                if name == section_name.as_bytes() {
                    return Some(ElfSection {
                        file: self,
                        index: SectionIndex(index),
                        section,
                    });
                }
            }
        }
        None
    }

    #[cfg(feature = "compression")]
    fn zdebug_section_by_name<'file>(
        &'file self,
        section_name: &str,
    ) -> Option<ElfSection<'data, 'file, Elf>> {
        if !section_name.starts_with(".debug_") {
            return None;
        }
        self.raw_section_by_name(&format!(".zdebug_{}", &section_name[7..]))
    }

    #[cfg(not(feature = "compression"))]
    fn zdebug_section_by_name<'file>(
        &'file self,
        _section_name: &str,
    ) -> Option<ElfSection<'data, 'file, Elf>> {
        None
    }
}

impl<'data, Elf: FileHeader> read::private::Sealed for ElfFile<'data, Elf> {}

impl<'data, 'file, Elf> Object<'data, 'file> for ElfFile<'data, Elf>
where
    'data: 'file,
    Elf: FileHeader,
{
    type Segment = ElfSegment<'data, 'file, Elf>;
    type SegmentIterator = ElfSegmentIterator<'data, 'file, Elf>;
    type Section = ElfSection<'data, 'file, Elf>;
    type SectionIterator = ElfSectionIterator<'data, 'file, Elf>;
    type SymbolIterator = ElfSymbolIterator<'data, 'file, Elf>;

    fn architecture(&self) -> Architecture {
        match self.header.e_machine(self.endian) {
            elf::EM_ARM => Architecture::Arm(ArmArchitecture::Arm),
            elf::EM_AARCH64 => Architecture::Aarch64(Aarch64Architecture::Aarch64),
            elf::EM_386 => Architecture::I386,
            elf::EM_X86_64 => Architecture::X86_64,
            elf::EM_MIPS => Architecture::Mips,
            _ => Architecture::Unknown,
        }
    }

    #[inline]
    fn is_little_endian(&self) -> bool {
        self.header.is_little_endian()
    }

    #[inline]
    fn is_64(&self) -> bool {
        self.header.is_class_64()
    }

    fn segments(&'file self) -> ElfSegmentIterator<'data, 'file, Elf> {
        ElfSegmentIterator {
            file: self,
            iter: self.segments.iter(),
        }
    }

    fn section_by_name(&'file self, section_name: &str) -> Option<ElfSection<'data, 'file, Elf>> {
        self.raw_section_by_name(section_name)
            .or_else(|| self.zdebug_section_by_name(section_name))
    }

    fn section_by_index(
        &'file self,
        index: SectionIndex,
    ) -> read::Result<ElfSection<'data, 'file, Elf>> {
        let section = self
            .sections
            .get(index.0)
            .read_error("Invalid ELF section index")?;
        Ok(ElfSection {
            file: self,
            index,
            section,
        })
    }

    fn sections(&'file self) -> ElfSectionIterator<'data, 'file, Elf> {
        ElfSectionIterator {
            file: self,
            iter: self.sections.iter().enumerate(),
        }
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> read::Result<Symbol<'data>> {
        let symbol = self
            .symbols
            .symbols
            .get(index.0)
            .read_error("Invalid ELF symbol index")?;
        let shndx = self.symbols.shndx.get(index.0).cloned();
        Ok(parse_symbol::<Elf>(
            self.endian,
            index.0,
            symbol,
            self.symbols.strings,
            shndx,
        ))
    }

    fn symbols(&'file self) -> ElfSymbolIterator<'data, 'file, Elf> {
        ElfSymbolIterator {
            file: self,
            symbols: self.symbols,
            index: 0,
        }
    }

    fn dynamic_symbols(&'file self) -> ElfSymbolIterator<'data, 'file, Elf> {
        ElfSymbolIterator {
            file: self,
            symbols: self.dynamic_symbols,
            index: 0,
        }
    }

    fn symbol_map(&self) -> SymbolMap<'data> {
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
            if let Ok(name) = self.section_strings.get(section.sh_name(self.endian)) {
                if name == b".debug_info" || name == b".zdebug_info" {
                    return true;
                }
            }
        }
        false
    }

    fn build_id(&self) -> read::Result<Option<&'data [u8]>> {
        let endian = self.endian;
        // Use section headers if present, otherwise use program headers.
        if !self.sections.is_empty() {
            for section in self.sections {
                if let Some(mut notes) = section.notes(endian, self.data)? {
                    while let Some(note) = notes.next()? {
                        if note.name() == elf::ELF_NOTE_GNU
                            && note.n_type(endian) == elf::NT_GNU_BUILD_ID
                        {
                            return Ok(Some(note.desc()));
                        }
                    }
                }
            }
        } else {
            for segment in self.segments {
                if let Some(mut notes) = segment.notes(endian, self.data)? {
                    while let Some(note) = notes.next()? {
                        if note.name() == elf::ELF_NOTE_GNU
                            && note.n_type(endian) == elf::NT_GNU_BUILD_ID
                        {
                            return Ok(Some(note.desc()));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    fn gnu_debuglink(&self) -> read::Result<Option<(&'data [u8], u32)>> {
        let section = match self.raw_section_by_name(".gnu_debuglink") {
            Some(section) => section,
            None => return Ok(None),
        };
        let data = section
            .section
            .data(self.endian, self.data)
            .read_error("Invalid ELF .gnu_debuglink section offset or size")?;
        let filename = data
            .read_string_at(0)
            .read_error("Missing ELF .gnu_debuglink filename")?;
        let crc_offset = util::align(filename.len() + 1, 4);
        let crc = data
            .read_at::<U32<_>>(crc_offset)
            .read_error("Missing ELF .gnu_debuglink crc")?
            .get(self.endian);
        Ok(Some((filename, crc)))
    }

    fn entry(&self) -> u64 {
        self.header.e_entry(self.endian).into()
    }

    fn flags(&self) -> FileFlags {
        FileFlags::Elf {
            e_flags: self.header.e_flags(self.endian),
        }
    }
}

/// A trait for generic access to `FileHeader32` and `FileHeader64`.
#[allow(missing_docs)]
pub trait FileHeader: Debug + Pod {
    // Ideally this would be a `u64: From<Word>`, but can't express that.
    type Word: Into<u64>;
    type Sword: Into<i64>;
    type Endian: endian::Endian;
    type ProgramHeader: ProgramHeader<Endian = Self::Endian>;
    type SectionHeader: SectionHeader<Endian = Self::Endian>;
    type CompressionHeader: CompressionHeader<Endian = Self::Endian>;
    type NoteHeader: NoteHeader<Endian = Self::Endian>;
    type Sym: Sym<Endian = Self::Endian>;
    type Rel: Clone + Pod;
    type Rela: Rela<Endian = Self::Endian> + From<Self::Rel>;

    /// Return true if this type is a 64-bit header.
    ///
    /// This is a property of the type, not a value in the header data.
    fn is_type_64(&self) -> bool;

    fn e_ident(&self) -> &elf::Ident;
    fn e_type(&self, endian: Self::Endian) -> u16;
    fn e_machine(&self, endian: Self::Endian) -> u16;
    fn e_version(&self, endian: Self::Endian) -> u32;
    fn e_entry(&self, endian: Self::Endian) -> Self::Word;
    fn e_phoff(&self, endian: Self::Endian) -> Self::Word;
    fn e_shoff(&self, endian: Self::Endian) -> Self::Word;
    fn e_flags(&self, endian: Self::Endian) -> u32;
    fn e_ehsize(&self, endian: Self::Endian) -> u16;
    fn e_phentsize(&self, endian: Self::Endian) -> u16;
    fn e_phnum(&self, endian: Self::Endian) -> u16;
    fn e_shentsize(&self, endian: Self::Endian) -> u16;
    fn e_shnum(&self, endian: Self::Endian) -> u16;
    fn e_shstrndx(&self, endian: Self::Endian) -> u16;

    // Provided methods.

    fn is_supported(&self) -> bool {
        let ident = self.e_ident();
        // TODO: Check self.e_version too? Requires endian though.
        ident.magic == elf::ELFMAG
            && (self.is_type_64() || self.is_class_32())
            && (!self.is_type_64() || self.is_class_64())
            && (self.is_little_endian() || self.is_big_endian())
            && ident.version == elf::EV_CURRENT
    }

    fn is_class_32(&self) -> bool {
        self.e_ident().class == elf::ELFCLASS32
    }

    fn is_class_64(&self) -> bool {
        self.e_ident().class == elf::ELFCLASS64
    }

    fn is_little_endian(&self) -> bool {
        self.e_ident().data == elf::ELFDATA2LSB
    }

    fn is_big_endian(&self) -> bool {
        self.e_ident().data == elf::ELFDATA2MSB
    }

    fn endian(&self) -> read::Result<Self::Endian> {
        Self::Endian::from_big_endian(self.is_big_endian()).read_error("Unsupported ELF endian")
    }

    /// Return the first section header, if present.
    ///
    /// Section 0 is a special case because getting the section headers normally
    /// requires `shnum`, but `shnum` may be in the first section header.
    fn section_0<'data>(
        &self,
        endian: Self::Endian,
        data: Bytes<'data>,
    ) -> read::Result<Option<&'data Self::SectionHeader>> {
        let shoff: u64 = self.e_shoff(endian).into();
        if shoff == 0 {
            // No section headers is ok.
            return Ok(None);
        }
        let shentsize = self.e_shentsize(endian) as usize;
        if shentsize != mem::size_of::<Self::SectionHeader>() {
            // Section header size must match.
            return Err(Error("Invalid ELF section header entry size"));
        }
        data.read_at(shoff as usize)
            .map(Some)
            .read_error("Invalid ELF section header offset or size")
    }

    /// Return the `e_phnum` field of the header. Handles extended values.
    ///
    /// Returns `Err` for invalid values.
    fn phnum<'data>(&self, endian: Self::Endian, data: Bytes<'data>) -> read::Result<usize> {
        let e_phnum = self.e_phnum(endian);
        if e_phnum < elf::PN_XNUM {
            Ok(e_phnum as usize)
        } else if let Some(section_0) = self.section_0(endian, data)? {
            Ok(section_0.sh_info(endian) as usize)
        } else {
            // Section 0 must exist if e_phnum overflows.
            Err(Error("Missing ELF section headers for e_phnum overflow"))
        }
    }

    /// Return the `e_shnum` field of the header. Handles extended values.
    ///
    /// Returns `Err` for invalid values.
    fn shnum<'data>(&self, endian: Self::Endian, data: Bytes<'data>) -> read::Result<usize> {
        let e_shnum = self.e_shnum(endian);
        if e_shnum > 0 {
            Ok(e_shnum as usize)
        } else if let Some(section_0) = self.section_0(endian, data)? {
            let size: u64 = section_0.sh_size(endian).into();
            Ok(size as usize)
        } else {
            // No section headers is ok.
            Ok(0)
        }
    }

    /// Return the `e_shstrndx` field of the header. Handles extended values.
    ///
    /// Returns `Err` for invalid values (including if the index is 0).
    fn shstrndx<'data>(&self, endian: Self::Endian, data: Bytes<'data>) -> read::Result<u32> {
        let e_shstrndx = self.e_shstrndx(endian);
        let index = if e_shstrndx != elf::SHN_XINDEX {
            e_shstrndx.into()
        } else if let Some(section_0) = self.section_0(endian, data)? {
            section_0.sh_link(endian)
        } else {
            // Section 0 must exist if we're trying to read e_shstrndx.
            return Err(Error("Missing ELF section headers for e_shstrndx overflow"));
        };
        if index == 0 {
            return Err(Error("Missing ELF e_shstrndx"));
        }
        Ok(index)
    }

    /// Return the slice of program headers.
    ///
    /// Returns `Ok(&[])` if there are no program headers.
    /// Returns `Err` for invalid values.
    fn program_headers<'data>(
        &self,
        endian: Self::Endian,
        data: Bytes<'data>,
    ) -> read::Result<&'data [Self::ProgramHeader]> {
        let phoff: u64 = self.e_phoff(endian).into();
        if phoff == 0 {
            // No program headers is ok.
            return Ok(&[]);
        }
        let phnum = self.phnum(endian, data)?;
        if phnum == 0 {
            // No program headers is ok.
            return Ok(&[]);
        }
        let phentsize = self.e_phentsize(endian) as usize;
        if phentsize != mem::size_of::<Self::ProgramHeader>() {
            // Program header size must match.
            return Err(Error("Invalid ELF program header entry size"));
        }
        data.read_slice_at(phoff as usize, phnum)
            .read_error("Invalid ELF program header size or alignment")
    }

    /// Return the slice of section headers.
    ///
    /// Returns `Ok(&[])` if there are no section headers.
    /// Returns `Err` for invalid values.
    fn section_headers<'data>(
        &self,
        endian: Self::Endian,
        data: Bytes<'data>,
    ) -> read::Result<&'data [Self::SectionHeader]> {
        let shoff: u64 = self.e_shoff(endian).into();
        if shoff == 0 {
            // No section headers is ok.
            return Ok(&[]);
        }
        let shnum = self.shnum(endian, data)?;
        if shnum == 0 {
            // No section headers is ok.
            return Ok(&[]);
        }
        let shentsize = self.e_shentsize(endian) as usize;
        if shentsize != mem::size_of::<Self::SectionHeader>() {
            // Section header size must match.
            return Err(Error("Invalid ELF section header entry size"));
        }
        data.read_slice_at(shoff as usize, shnum)
            .read_error("Invalid ELF section header offset/size/alignment")
    }
}

impl<Endian: endian::Endian> FileHeader for elf::FileHeader32<Endian> {
    type Word = u32;
    type Sword = i32;
    type Endian = Endian;
    type ProgramHeader = elf::ProgramHeader32<Endian>;
    type SectionHeader = elf::SectionHeader32<Endian>;
    type CompressionHeader = elf::CompressionHeader32<Endian>;
    type NoteHeader = elf::NoteHeader32<Endian>;
    type Sym = elf::Sym32<Endian>;
    type Rel = elf::Rel32<Endian>;
    type Rela = elf::Rela32<Endian>;

    #[inline]
    fn is_type_64(&self) -> bool {
        false
    }

    #[inline]
    fn e_ident(&self) -> &elf::Ident {
        &self.e_ident
    }

    #[inline]
    fn e_type(&self, endian: Self::Endian) -> u16 {
        self.e_type.get(endian)
    }

    #[inline]
    fn e_machine(&self, endian: Self::Endian) -> u16 {
        self.e_machine.get(endian)
    }

    #[inline]
    fn e_version(&self, endian: Self::Endian) -> u32 {
        self.e_version.get(endian)
    }

    #[inline]
    fn e_entry(&self, endian: Self::Endian) -> Self::Word {
        self.e_entry.get(endian)
    }

    #[inline]
    fn e_phoff(&self, endian: Self::Endian) -> Self::Word {
        self.e_phoff.get(endian)
    }

    #[inline]
    fn e_shoff(&self, endian: Self::Endian) -> Self::Word {
        self.e_shoff.get(endian)
    }

    #[inline]
    fn e_flags(&self, endian: Self::Endian) -> u32 {
        self.e_flags.get(endian)
    }

    #[inline]
    fn e_ehsize(&self, endian: Self::Endian) -> u16 {
        self.e_ehsize.get(endian)
    }

    #[inline]
    fn e_phentsize(&self, endian: Self::Endian) -> u16 {
        self.e_phentsize.get(endian)
    }

    #[inline]
    fn e_phnum(&self, endian: Self::Endian) -> u16 {
        self.e_phnum.get(endian)
    }

    #[inline]
    fn e_shentsize(&self, endian: Self::Endian) -> u16 {
        self.e_shentsize.get(endian)
    }

    #[inline]
    fn e_shnum(&self, endian: Self::Endian) -> u16 {
        self.e_shnum.get(endian)
    }

    #[inline]
    fn e_shstrndx(&self, endian: Self::Endian) -> u16 {
        self.e_shstrndx.get(endian)
    }
}

impl<Endian: endian::Endian> FileHeader for elf::FileHeader64<Endian> {
    type Word = u64;
    type Sword = i64;
    type Endian = Endian;
    type ProgramHeader = elf::ProgramHeader64<Endian>;
    type SectionHeader = elf::SectionHeader64<Endian>;
    type CompressionHeader = elf::CompressionHeader64<Endian>;
    type NoteHeader = elf::NoteHeader32<Endian>;
    type Sym = elf::Sym64<Endian>;
    type Rel = elf::Rel64<Endian>;
    type Rela = elf::Rela64<Endian>;

    #[inline]
    fn is_type_64(&self) -> bool {
        true
    }

    #[inline]
    fn e_ident(&self) -> &elf::Ident {
        &self.e_ident
    }

    #[inline]
    fn e_type(&self, endian: Self::Endian) -> u16 {
        self.e_type.get(endian)
    }

    #[inline]
    fn e_machine(&self, endian: Self::Endian) -> u16 {
        self.e_machine.get(endian)
    }

    #[inline]
    fn e_version(&self, endian: Self::Endian) -> u32 {
        self.e_version.get(endian)
    }

    #[inline]
    fn e_entry(&self, endian: Self::Endian) -> Self::Word {
        self.e_entry.get(endian)
    }

    #[inline]
    fn e_phoff(&self, endian: Self::Endian) -> Self::Word {
        self.e_phoff.get(endian)
    }

    #[inline]
    fn e_shoff(&self, endian: Self::Endian) -> Self::Word {
        self.e_shoff.get(endian)
    }

    #[inline]
    fn e_flags(&self, endian: Self::Endian) -> u32 {
        self.e_flags.get(endian)
    }

    #[inline]
    fn e_ehsize(&self, endian: Self::Endian) -> u16 {
        self.e_ehsize.get(endian)
    }

    #[inline]
    fn e_phentsize(&self, endian: Self::Endian) -> u16 {
        self.e_phentsize.get(endian)
    }

    #[inline]
    fn e_phnum(&self, endian: Self::Endian) -> u16 {
        self.e_phnum.get(endian)
    }

    #[inline]
    fn e_shentsize(&self, endian: Self::Endian) -> u16 {
        self.e_shentsize.get(endian)
    }

    #[inline]
    fn e_shnum(&self, endian: Self::Endian) -> u16 {
        self.e_shnum.get(endian)
    }

    #[inline]
    fn e_shstrndx(&self, endian: Self::Endian) -> u16 {
        self.e_shstrndx.get(endian)
    }
}
