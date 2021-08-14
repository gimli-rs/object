use alloc::vec::Vec;
use core::convert::TryInto;
use core::fmt::Debug;
use core::mem;

use crate::read::{
    self, util, Architecture, ByteString, Bytes, Error, Export, FileFlags, Import, Object,
    ObjectKind, ReadError, ReadRef, SectionIndex, StringTable, SymbolIndex,
};
use crate::{elf, endian, Endian, Endianness, Pod, U32};

use super::{
    CompressionHeader, Dyn, ElfComdat, ElfComdatIterator, ElfDynamicRelocationIterator, ElfSection,
    ElfSectionIterator, ElfSegment, ElfSegmentIterator, ElfSymbol, ElfSymbolIterator,
    ElfSymbolTable, NoteHeader, ProgramHeader, Rel, Rela, RelocationSections, SectionHeader,
    SectionTable, Sym, SymbolTable,
};

/// A 32-bit ELF object file.
pub type ElfFile32<'data, Endian = Endianness, R = &'data [u8]> =
    ElfFile<'data, elf::FileHeader32<Endian>, R>;
/// A 64-bit ELF object file.
pub type ElfFile64<'data, Endian = Endianness, R = &'data [u8]> =
    ElfFile<'data, elf::FileHeader64<Endian>, R>;

/// A partially parsed ELF file.
///
/// Most of the functionality of this type is provided by the `Object` trait implementation.
#[derive(Debug)]
pub struct ElfFile<'data, Elf, R = &'data [u8]>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
{
    pub(super) endian: Elf::Endian,
    pub(super) data: R,
    pub(super) header: &'data Elf,
    pub(super) segments: &'data [Elf::ProgramHeader],
    pub(super) sections: SectionTable<'data, Elf, R>,
    pub(super) relocations: RelocationSections,
    pub(super) symbols: SymbolTable<'data, Elf, R>,
    pub(super) dynamic_symbols: SymbolTable<'data, Elf, R>,
}

impl<'data, Elf, R> ElfFile<'data, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
{
    /// Parse the raw ELF file data.
    pub fn parse(data: R) -> read::Result<Self> {
        let header = Elf::parse(data)?;
        let endian = header.endian()?;
        let segments = header.program_headers(endian, data)?;
        let sections = header.sections(endian, data)?;
        let symbols = sections.symbols(endian, data, elf::SHT_SYMTAB)?;
        // TODO: get dynamic symbols from DT_SYMTAB if there are no sections
        let dynamic_symbols = sections.symbols(endian, data, elf::SHT_DYNSYM)?;
        // The API we provide requires a mapping from section to relocations, so build it now.
        let relocations = sections.relocation_sections(endian, symbols.section())?;

        Ok(ElfFile {
            endian,
            data,
            header,
            segments,
            sections,
            relocations,
            symbols,
            dynamic_symbols,
        })
    }

    /// Returns the endianness.
    pub fn endian(&self) -> Elf::Endian {
        self.endian
    }

    /// Returns the raw data.
    pub fn data(&self) -> R {
        self.data
    }

    /// Returns the raw ELF file header.
    pub fn raw_header(&self) -> &'data Elf {
        self.header
    }

    /// Returns the raw ELF segments.
    pub fn raw_segments(&self) -> &'data [Elf::ProgramHeader] {
        self.segments
    }

    fn raw_section_by_name<'file>(
        &'file self,
        section_name: &[u8],
    ) -> Option<ElfSection<'data, 'file, Elf, R>> {
        self.sections
            .section_by_name(self.endian, section_name)
            .map(|(index, section)| ElfSection {
                file: self,
                index: SectionIndex(index),
                section,
            })
    }

    #[cfg(feature = "compression")]
    fn zdebug_section_by_name<'file>(
        &'file self,
        section_name: &[u8],
    ) -> Option<ElfSection<'data, 'file, Elf, R>> {
        if !section_name.starts_with(b".debug_") {
            return None;
        }
        let mut name = Vec::with_capacity(section_name.len() + 1);
        name.extend_from_slice(b".zdebug_");
        name.extend_from_slice(&section_name[7..]);
        self.raw_section_by_name(&name)
    }

    #[cfg(not(feature = "compression"))]
    fn zdebug_section_by_name<'file>(
        &'file self,
        _section_name: &[u8],
    ) -> Option<ElfSection<'data, 'file, Elf, R>> {
        None
    }
}

impl<'data, Elf, R> read::private::Sealed for ElfFile<'data, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
{
}

impl<'data, 'file, Elf, R> Object<'data, 'file> for ElfFile<'data, Elf, R>
where
    'data: 'file,
    Elf: FileHeader,
    R: 'file + ReadRef<'data>,
{
    type Segment = ElfSegment<'data, 'file, Elf, R>;
    type SegmentIterator = ElfSegmentIterator<'data, 'file, Elf, R>;
    type Section = ElfSection<'data, 'file, Elf, R>;
    type SectionIterator = ElfSectionIterator<'data, 'file, Elf, R>;
    type Comdat = ElfComdat<'data, 'file, Elf, R>;
    type ComdatIterator = ElfComdatIterator<'data, 'file, Elf, R>;
    type Symbol = ElfSymbol<'data, 'file, Elf, R>;
    type SymbolIterator = ElfSymbolIterator<'data, 'file, Elf, R>;
    type SymbolTable = ElfSymbolTable<'data, 'file, Elf, R>;
    type DynamicRelocationIterator = ElfDynamicRelocationIterator<'data, 'file, Elf, R>;

    fn architecture(&self) -> Architecture {
        match (
            self.header.e_machine(self.endian),
            self.header.is_class_64(),
        ) {
            (elf::EM_AARCH64, _) => Architecture::Aarch64,
            (elf::EM_ARM, _) => Architecture::Arm,
            (elf::EM_AVR, _) => Architecture::Avr,
            (elf::EM_BPF, _) => Architecture::Bpf,
            (elf::EM_386, _) => Architecture::I386,
            (elf::EM_X86_64, false) => Architecture::X86_64_X32,
            (elf::EM_X86_64, true) => Architecture::X86_64,
            (elf::EM_HEXAGON, _) => Architecture::Hexagon,
            (elf::EM_MIPS, false) => Architecture::Mips,
            (elf::EM_MIPS, true) => Architecture::Mips64,
            (elf::EM_MSP430, _) => Architecture::Msp430,
            (elf::EM_PPC, _) => Architecture::PowerPc,
            (elf::EM_PPC64, _) => Architecture::PowerPc64,
            (elf::EM_RISCV, false) => Architecture::Riscv32,
            (elf::EM_RISCV, true) => Architecture::Riscv64,
            // This is either s390 or s390x, depending on the ELF class.
            // We only support the 64-bit variant s390x here.
            (elf::EM_S390, true) => Architecture::S390x,
            (elf::EM_SPARCV9, true) => Architecture::Sparc64,
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

    fn kind(&self) -> ObjectKind {
        match self.header.e_type(self.endian) {
            elf::ET_REL => ObjectKind::Relocatable,
            elf::ET_EXEC => ObjectKind::Executable,
            // TODO: check for `DF_1_PIE`?
            elf::ET_DYN => ObjectKind::Dynamic,
            elf::ET_CORE => ObjectKind::Core,
            _ => ObjectKind::Unknown,
        }
    }

    fn segments(&'file self) -> ElfSegmentIterator<'data, 'file, Elf, R> {
        ElfSegmentIterator {
            file: self,
            iter: self.segments.iter(),
        }
    }

    fn section_by_name_bytes(
        &'file self,
        section_name: &[u8],
    ) -> Option<ElfSection<'data, 'file, Elf, R>> {
        self.raw_section_by_name(section_name)
            .or_else(|| self.zdebug_section_by_name(section_name))
    }

    fn section_by_index(
        &'file self,
        index: SectionIndex,
    ) -> read::Result<ElfSection<'data, 'file, Elf, R>> {
        let section = self.sections.section(index)?;
        Ok(ElfSection {
            file: self,
            index,
            section,
        })
    }

    fn sections(&'file self) -> ElfSectionIterator<'data, 'file, Elf, R> {
        ElfSectionIterator {
            file: self,
            iter: self.sections.iter().enumerate(),
        }
    }

    fn comdats(&'file self) -> ElfComdatIterator<'data, 'file, Elf, R> {
        ElfComdatIterator {
            file: self,
            iter: self.sections.iter().enumerate(),
        }
    }

    fn symbol_by_index(
        &'file self,
        index: SymbolIndex,
    ) -> read::Result<ElfSymbol<'data, 'file, Elf, R>> {
        let symbol = self.symbols.symbol(index.0)?;
        Ok(ElfSymbol {
            endian: self.endian,
            symbols: &self.symbols,
            index,
            symbol,
        })
    }

    fn symbols(&'file self) -> ElfSymbolIterator<'data, 'file, Elf, R> {
        ElfSymbolIterator {
            endian: self.endian,
            symbols: &self.symbols,
            index: 0,
        }
    }

    fn symbol_table(&'file self) -> Option<ElfSymbolTable<'data, 'file, Elf, R>> {
        Some(ElfSymbolTable {
            endian: self.endian,
            symbols: &self.symbols,
        })
    }

    fn dynamic_symbols(&'file self) -> ElfSymbolIterator<'data, 'file, Elf, R> {
        ElfSymbolIterator {
            endian: self.endian,
            symbols: &self.dynamic_symbols,
            index: 0,
        }
    }

    fn dynamic_symbol_table(&'file self) -> Option<ElfSymbolTable<'data, 'file, Elf, R>> {
        Some(ElfSymbolTable {
            endian: self.endian,
            symbols: &self.dynamic_symbols,
        })
    }

    fn dynamic_relocations(
        &'file self,
    ) -> Option<ElfDynamicRelocationIterator<'data, 'file, Elf, R>> {
        Some(ElfDynamicRelocationIterator {
            section_index: SectionIndex(1),
            file: self,
            relocations: None,
        })
    }

    /// Get the imported symbols.
    fn imports(&self) -> read::Result<Vec<Import<'data>>> {
        let mut imports = Vec::new();
        for symbol in self.dynamic_symbols.iter() {
            if symbol.is_undefined(self.endian) {
                let name = symbol.name(self.endian, self.dynamic_symbols.strings())?;
                if !name.is_empty() {
                    // TODO: use symbol versioning to determine library
                    imports.push(Import {
                        name: ByteString(name),
                        library: ByteString(&[]),
                    });
                }
            }
        }
        Ok(imports)
    }

    /// Get the exported symbols.
    fn exports(&self) -> read::Result<Vec<Export<'data>>> {
        let mut exports = Vec::new();
        for symbol in self.dynamic_symbols.iter() {
            if symbol.is_definition(self.endian) {
                let name = symbol.name(self.endian, self.dynamic_symbols.strings())?;
                let address = symbol.st_value(self.endian).into();
                exports.push(Export {
                    name: ByteString(name),
                    address,
                });
            }
        }
        Ok(exports)
    }

    fn has_debug_symbols(&self) -> bool {
        for section in self.sections.iter() {
            if let Ok(name) = self.sections.section_name(self.endian, section) {
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
            for section in self.sections.iter() {
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
        let section = match self.raw_section_by_name(b".gnu_debuglink") {
            Some(section) => section,
            None => return Ok(None),
        };
        let data = section
            .section
            .data(self.endian, self.data)
            .read_error("Invalid ELF .gnu_debuglink section offset or size")
            .map(Bytes)?;
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

    fn gnu_debugaltlink(&self) -> read::Result<Option<(&'data [u8], &'data [u8])>> {
        let section = match self.raw_section_by_name(b".gnu_debugaltlink") {
            Some(section) => section,
            None => return Ok(None),
        };
        let mut data = section
            .section
            .data(self.endian, self.data)
            .read_error("Invalid ELF .gnu_debugaltlink section offset or size")
            .map(Bytes)?;
        let filename = data
            .read_string()
            .read_error("Missing ELF .gnu_debugaltlink filename")?;
        let build_id = data.0;
        Ok(Some((filename, build_id)))
    }

    fn relative_address_base(&self) -> u64 {
        0
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
    type ProgramHeader: ProgramHeader<Elf = Self, Endian = Self::Endian, Word = Self::Word>;
    type SectionHeader: SectionHeader<Elf = Self, Endian = Self::Endian, Word = Self::Word>;
    type CompressionHeader: CompressionHeader<Endian = Self::Endian, Word = Self::Word>;
    type NoteHeader: NoteHeader<Endian = Self::Endian>;
    type Dyn: Dyn<Endian = Self::Endian, Word = Self::Word>;
    type Sym: Sym<Endian = Self::Endian, Word = Self::Word>;
    type Rel: Rel<Endian = Self::Endian, Word = Self::Word>;
    type Rela: Rela<Endian = Self::Endian, Word = Self::Word> + From<Self::Rel>;

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

    /// Read the file header.
    ///
    /// Also checks that the ident field in the file header is a supported format.
    fn parse<'data, R: ReadRef<'data>>(data: R) -> read::Result<&'data Self> {
        let header = data
            .read_at::<Self>(0)
            .read_error("Invalid ELF header size or alignment")?;
        if !header.is_supported() {
            return Err(Error("Unsupported ELF header"));
        }
        // TODO: Check self.e_ehsize?
        Ok(header)
    }

    /// Check that the ident field in the file header is a supported format.
    ///
    /// This checks the magic number, version, class, and endianness.
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
    fn section_0<'data, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        data: R,
    ) -> read::Result<Option<&'data Self::SectionHeader>> {
        let shoff: u64 = self.e_shoff(endian).into();
        if shoff == 0 {
            // No section headers is ok.
            return Ok(None);
        }
        let shentsize = usize::from(self.e_shentsize(endian));
        if shentsize != mem::size_of::<Self::SectionHeader>() {
            // Section header size must match.
            return Err(Error("Invalid ELF section header entry size"));
        }
        data.read_at(shoff)
            .map(Some)
            .read_error("Invalid ELF section header offset or size")
    }

    /// Return the `e_phnum` field of the header. Handles extended values.
    ///
    /// Returns `Err` for invalid values.
    fn phnum<'data, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        data: R,
    ) -> read::Result<usize> {
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
    fn shnum<'data, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        data: R,
    ) -> read::Result<usize> {
        let e_shnum = self.e_shnum(endian);
        if e_shnum > 0 {
            Ok(e_shnum as usize)
        } else if let Some(section_0) = self.section_0(endian, data)? {
            section_0
                .sh_size(endian)
                .into()
                .try_into()
                .ok()
                .read_error("Invalid ELF extended e_shnum")
        } else {
            // No section headers is ok.
            Ok(0)
        }
    }

    /// Return the `e_shstrndx` field of the header. Handles extended values.
    ///
    /// Returns `Err` for invalid values (including if the index is 0).
    fn shstrndx<'data, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        data: R,
    ) -> read::Result<u32> {
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
    fn program_headers<'data, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        data: R,
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
        data.read_slice_at(phoff, phnum)
            .read_error("Invalid ELF program header size or alignment")
    }

    /// Return the slice of section headers.
    ///
    /// Returns `Ok(&[])` if there are no section headers.
    /// Returns `Err` for invalid values.
    fn section_headers<'data, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        data: R,
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
        let shentsize = usize::from(self.e_shentsize(endian));
        if shentsize != mem::size_of::<Self::SectionHeader>() {
            // Section header size must match.
            return Err(Error("Invalid ELF section header entry size"));
        }
        data.read_slice_at(shoff, shnum)
            .read_error("Invalid ELF section header offset/size/alignment")
    }

    /// Return the string table for the section headers.
    fn section_strings<'data, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        data: R,
        sections: &[Self::SectionHeader],
    ) -> read::Result<StringTable<'data, R>> {
        if sections.is_empty() {
            return Ok(StringTable::default());
        }
        let index = self.shstrndx(endian, data)? as usize;
        let shstrtab = sections.get(index).read_error("Invalid ELF e_shstrndx")?;
        let strings = if let Some((shstrtab_offset, shstrtab_size)) = shstrtab.file_range(endian) {
            let shstrtab_end = shstrtab_offset
                .checked_add(shstrtab_size)
                .read_error("Invalid ELF shstrtab size")?;
            StringTable::new(data, shstrtab_offset, shstrtab_end)
        } else {
            StringTable::default()
        };
        Ok(strings)
    }

    /// Return the section table.
    fn sections<'data, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        data: R,
    ) -> read::Result<SectionTable<'data, Self, R>> {
        let sections = self.section_headers(endian, data)?;
        let strings = self.section_strings(endian, data, sections)?;
        Ok(SectionTable::new(sections, strings))
    }

    /// Returns whether this is a mips64el elf file.
    fn is_mips64el(&self, endian: Self::Endian) -> bool {
        self.is_class_64() && self.is_little_endian() && self.e_machine(endian) == elf::EM_MIPS
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
    type Dyn = elf::Dyn32<Endian>;
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
    type Dyn = elf::Dyn64<Endian>;
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
