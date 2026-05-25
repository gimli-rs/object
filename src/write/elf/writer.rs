//! Helper for writing ELF files.
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryInto;
use core::mem;

use crate::elf;
use crate::endian::*;
use crate::pod;
use crate::write::string::{StringId, StringTable};
use crate::write::util;
use crate::write::{Error, GrowableBuffer, Result, WritableBuffer};

const ALIGN_SYMTAB_SHNDX: usize = 4;
const ALIGN_HASH: usize = 4;
const ALIGN_GNU_VERSYM: usize = 2;
const ALIGN_GNU_VERDEF: usize = 4;
const ALIGN_GNU_VERNEED: usize = 4;

/// The index of an ELF section.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SectionIndex(pub u32);

/// The index of an ELF symbol.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolIndex(pub u32);

/// The writing mode of a [`Writer`].
///
/// This is a sealed trait with two implementors:
/// - [`TwoPhase`]: reserve all file ranges, then write.
/// - [`SinglePhase`]: write directly, discovering file offsets as you go.
pub trait Mode: ModeSealed {}

use private::ModeSealed;
mod private {
    use super::*;

    #[allow(private_interfaces)]
    pub trait ModeSealed {
        fn reserve(&self, buffer: &mut dyn WritableBuffer) -> Result<()>;
        fn need_offset(offset: u64) -> bool;
        fn set_offset(dest: &mut u64, offset: u64);
        fn set_size(dest: &mut u64, size: u64);
        fn set_section_index(dest: &mut SectionIndex, index: SectionIndex);
        fn set_section_name(
            dest: &mut Option<StringId>,
            shstrtab: &mut StringTable<'_>,
            name: &'static [u8],
        );
        fn set_count<T: Copy + PartialOrd>(dest: &mut T, count: T);
    }
}

/// A helper for writing ELF files.
///
/// The writer supports two modes: [`TwoPhase`] or [`SinglePhase`].
/// See the mode documentation for a description of the use of the writer.
///
/// The default mode is two-phase. Use [`Writer::new_single_phase`] to construct
/// a single-phase writer; the [`SinglePhaseWriter`] type alias is also provided.
#[allow(missing_debug_implementations)]
pub struct Writer<'a, M: Mode = TwoPhase> {
    mode: M,
    endian: Endianness,
    is_64: bool,
    is_mips64el: bool,
    elf_align: usize,

    buffer: &'a mut dyn WritableBuffer,

    header: FileHeader,
    layout: FileHeaderLayout,
    written_segment_num: u32,
    written_section_num: u32,

    shstrtab: StringTable<'a>,
    shstrtab_str_id: Option<StringId>,
    shstrtab_offset: u64,
    shstrtab_size: u32,

    need_strtab: bool,
    strtab: StringTable<'a>,
    strtab_str_id: Option<StringId>,
    strtab_index: SectionIndex,
    strtab_offset: u64,
    strtab_size: u32,

    symtab_str_id: Option<StringId>,
    symtab_index: SectionIndex,
    symtab_offset: u64,
    symtab_num: u32,
    written_symtab_num: u32,

    need_symtab_shndx: bool,
    symtab_shndx_str_id: Option<StringId>,
    symtab_shndx_offset: u64,
    symtab_shndx_data: Vec<u8>,

    need_dynstr: bool,
    dynstr: StringTable<'a>,
    dynstr_str_id: Option<StringId>,
    dynstr_index: SectionIndex,
    dynstr_offset: u64,
    dynstr_size: u32,

    dynsym_str_id: Option<StringId>,
    dynsym_index: SectionIndex,
    dynsym_offset: u64,
    dynsym_num: u32,
    written_dynsym_num: u32,

    dynamic_str_id: Option<StringId>,
    dynamic_offset: u64,
    dynamic_num: usize,
    written_dynamic_num: usize,

    hash_str_id: Option<StringId>,
    hash_offset: u64,
    hash_size: u64,

    gnu_hash_str_id: Option<StringId>,
    gnu_hash_offset: u64,
    gnu_hash_size: u64,

    gnu_versym_str_id: Option<StringId>,
    gnu_versym_offset: u64,

    gnu_verdef_str_id: Option<StringId>,
    gnu_verdef_offset: u64,
    gnu_verdef_count: u16,
    gnu_verdaux_count: usize,
    written_verdaux_count: usize,
    gnu_verdef_remaining: u16,
    gnu_verdaux_remaining: u16,

    gnu_verneed_str_id: Option<StringId>,
    gnu_verneed_offset: u64,
    gnu_verneed_count: u16,
    gnu_vernaux_count: usize,
    written_vernaux_count: usize,
    gnu_verneed_remaining: u16,
    gnu_vernaux_remaining: u16,

    gnu_attributes_str_id: Option<StringId>,
    gnu_attributes_offset: u64,
    gnu_attributes_size: u64,
}

impl<'a, M: Mode> Writer<'a, M> {
    /// Create a new `Writer` for the given endianness and ELF class.
    fn new_with_mode(
        endian: Endianness,
        is_64: bool,
        buffer: &'a mut dyn WritableBuffer,
        mode: M,
    ) -> Self {
        let elf_align = if is_64 { 8 } else { 4 };
        Writer {
            mode,
            endian,
            is_64,
            // Determined later.
            is_mips64el: false,
            elf_align,

            buffer,

            header: FileHeader::default(),
            layout: FileHeaderLayout::default(),
            written_segment_num: 0,
            written_section_num: 0,

            shstrtab: StringTable::default(),
            shstrtab_str_id: None,
            shstrtab_offset: 0,
            shstrtab_size: 0,

            need_strtab: false,
            strtab: StringTable::default(),
            strtab_str_id: None,
            strtab_index: SectionIndex(0),
            strtab_offset: 0,
            strtab_size: 0,

            symtab_str_id: None,
            symtab_index: SectionIndex(0),
            symtab_offset: 0,
            symtab_num: 0,
            written_symtab_num: 0,

            need_symtab_shndx: false,
            symtab_shndx_str_id: None,
            symtab_shndx_offset: 0,
            symtab_shndx_data: Vec::new(),

            need_dynstr: false,
            dynstr: StringTable::default(),
            dynstr_str_id: None,
            dynstr_index: SectionIndex(0),
            dynstr_offset: 0,
            dynstr_size: 0,

            dynsym_str_id: None,
            dynsym_index: SectionIndex(0),
            dynsym_offset: 0,
            dynsym_num: 0,
            written_dynsym_num: 0,

            dynamic_str_id: None,
            dynamic_offset: 0,
            dynamic_num: 0,
            written_dynamic_num: 0,

            hash_str_id: None,
            hash_offset: 0,
            hash_size: 0,

            gnu_hash_str_id: None,
            gnu_hash_offset: 0,
            gnu_hash_size: 0,

            gnu_versym_str_id: None,
            gnu_versym_offset: 0,

            gnu_verdef_str_id: None,
            gnu_verdef_offset: 0,
            gnu_verdef_count: 0,
            gnu_verdaux_count: 0,
            written_verdaux_count: 0,
            gnu_verdef_remaining: 0,
            gnu_verdaux_remaining: 0,

            gnu_verneed_str_id: None,
            gnu_verneed_offset: 0,
            gnu_verneed_count: 0,
            gnu_vernaux_count: 0,
            written_vernaux_count: 0,
            gnu_verneed_remaining: 0,
            gnu_vernaux_remaining: 0,

            gnu_attributes_str_id: None,
            gnu_attributes_offset: 0,
            gnu_attributes_size: 0,
        }
    }

    /// Get the file class that will be written.
    fn class(&self) -> Class {
        Class { is_64: self.is_64 }
    }

    /// Return the current file length that has been written.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Return the file offset of the next write.
    pub fn offset(&self) -> u64 {
        self.buffer.len() as u64
    }

    /// Write alignment padding bytes.
    ///
    /// Returns the file offset after the padding.
    pub fn write_align(&mut self, align_start: usize) -> u64 {
        if align_start > 1 {
            util::write_align(self.buffer, align_start);
        }
        self.offset()
    }

    /// Write data.
    ///
    /// This is typically used to write section data.
    pub fn write(&mut self, data: &[u8]) {
        self.buffer.write_bytes(data);
    }

    /// Write padding up to the given file offset.
    pub fn pad_until(&mut self, offset: u64) {
        debug_assert!(self.offset() <= offset);
        debug_assert!(offset <= usize::MAX as u64);
        self.buffer.resize(offset as usize);
    }

    /// Write the file header.
    ///
    /// This must be at the start of the file.
    ///
    /// Fields that can be derived from known information are automatically set by this function.
    pub fn write_file_header(&mut self, header: &FileHeader) -> Result<()> {
        debug_assert_eq!(self.buffer.len(), 0);

        self.is_mips64el =
            self.is_64 && self.endian.is_little_endian() && header.e_machine == elf::EM_MIPS;

        self.mode.reserve(self.buffer)?;
        self.header = header.clone();
        Self::write_file_header_impl(
            self.buffer,
            self.endian,
            self.is_64,
            &self.header,
            &self.layout,
        )
    }

    fn write_file_header_impl(
        buffer: &mut dyn WritableBuffer,
        endian: Endianness,
        is_64: bool,
        header: &FileHeader,
        layout: &FileHeaderLayout,
    ) -> Result<()> {
        let class = Class { is_64 };
        let e_ident = elf::Ident {
            magic: elf::ELFMAG,
            class: if class.is_64 {
                elf::ELFCLASS64
            } else {
                elf::ELFCLASS32
            },
            data: if endian.is_little_endian() {
                elf::ELFDATA2LSB
            } else {
                elf::ELFDATA2MSB
            },
            version: elf::EV_CURRENT,
            os_abi: header.os_abi,
            abi_version: header.abi_version,
            padding: [0; 7],
        };

        let e_ehsize = class.file_header_size() as u16;

        let e_phoff = layout.segment_offset;
        let e_phentsize = if layout.segment_num == 0 {
            0
        } else {
            class.program_header_size() as u16
        };
        let e_phnum = if layout.segment_num >= elf::PN_XNUM.into() {
            if layout.section_num == 0 {
                return Err(Error(String::from(
                    "e_phnum overflow requires section headers",
                )));
            }
            elf::PN_XNUM
        } else {
            layout.segment_num as u16
        };

        let e_shoff = layout.section_offset;
        let e_shentsize = if layout.section_num == 0 {
            0
        } else {
            class.section_header_size() as u16
        };
        let e_shnum = if layout.section_num >= elf::SHN_LORESERVE.into() {
            0
        } else {
            layout.section_num as u16
        };
        let e_shstrndx = elf::SymbolSection::new(layout.shstrtab_index.0);

        if class.is_64 {
            let file = elf::FileHeader64 {
                e_ident,
                e_type: U16::new(endian, header.e_type),
                e_machine: U16::new(endian, header.e_machine),
                e_version: U32::new(endian, elf::EV_CURRENT.0.into()),
                e_entry: U64::new(endian, header.e_entry),
                e_phoff: U64::new(endian, e_phoff),
                e_shoff: U64::new(endian, e_shoff),
                e_flags: U32::new(endian, header.e_flags),
                e_ehsize: U16::new(endian, e_ehsize),
                e_phentsize: U16::new(endian, e_phentsize),
                e_phnum: U16::new(endian, e_phnum),
                e_shentsize: U16::new(endian, e_shentsize),
                e_shnum: U16::new(endian, e_shnum),
                e_shstrndx: U16::new(endian, e_shstrndx),
            };
            buffer.write(&file)
        } else {
            let file = elf::FileHeader32 {
                e_ident,
                e_type: U16::new(endian, header.e_type),
                e_machine: U16::new(endian, header.e_machine),
                e_version: U32::new(endian, elf::EV_CURRENT.0.into()),
                e_entry: U32::new(endian, header.e_entry as u32),
                e_phoff: U32::new(endian, e_phoff as u32),
                e_shoff: U32::new(endian, e_shoff as u32),
                e_flags: U32::new(endian, header.e_flags),
                e_ehsize: U16::new(endian, e_ehsize),
                e_phentsize: U16::new(endian, e_phentsize),
                e_phnum: U16::new(endian, e_phnum),
                e_shentsize: U16::new(endian, e_shentsize),
                e_shnum: U16::new(endian, e_shnum),
                e_shstrndx: U16::new(endian, e_shstrndx),
            };
            buffer.write(&file);
        }

        Ok(())
    }

    /// Write alignment padding bytes prior to the program headers.
    ///
    /// Returns the file offset after the padding.
    /// In two-phase mode, returns 0 without writing if no program headers were reserved.
    pub fn write_align_program_headers(&mut self) -> u64 {
        if !M::need_offset(self.layout.segment_offset) {
            return 0;
        }
        let offset = self.write_align(self.elf_align);
        M::set_offset(&mut self.layout.segment_offset, offset);
        offset
    }

    /// Write a program header.
    ///
    /// Must be called after [`Self::write_align_program_headers`].
    pub fn write_program_header(&mut self, header: &ProgramHeader) {
        Self::write_program_header_impl(self.buffer, self.endian, self.is_64, header);
        self.written_segment_num += 1;
        M::set_count(&mut self.layout.segment_num, self.written_segment_num);
    }

    fn write_program_header_impl(
        buffer: &mut dyn WritableBuffer,
        endian: Endianness,
        is_64: bool,
        header: &ProgramHeader,
    ) {
        if is_64 {
            let header = elf::ProgramHeader64 {
                p_type: U32::new(endian, header.p_type),
                p_flags: U32::new(endian, header.p_flags),
                p_offset: U64::new(endian, header.p_offset),
                p_vaddr: U64::new(endian, header.p_vaddr),
                p_paddr: U64::new(endian, header.p_paddr),
                p_filesz: U64::new(endian, header.p_filesz),
                p_memsz: U64::new(endian, header.p_memsz),
                p_align: U64::new(endian, header.p_align),
            };
            buffer.write(&header);
        } else {
            let header = elf::ProgramHeader32 {
                p_type: U32::new(endian, header.p_type),
                p_offset: U32::new(endian, header.p_offset as u32),
                p_vaddr: U32::new(endian, header.p_vaddr as u32),
                p_paddr: U32::new(endian, header.p_paddr as u32),
                p_filesz: U32::new(endian, header.p_filesz as u32),
                p_memsz: U32::new(endian, header.p_memsz as u32),
                p_flags: U32::new(endian, header.p_flags),
                p_align: U32::new(endian, header.p_align as u32),
            };
            buffer.write(&header);
        }
    }

    /// Write the null section header.
    ///
    /// This must be the first section header that is written.
    ///
    /// Returns the file offset of the header.
    /// In two-phase mode, returns 0 without writing if no sections were reserved.
    pub fn write_null_section_header(&mut self) -> u64 {
        if !M::need_offset(self.layout.section_offset) {
            return 0;
        }
        let offset = self.write_align(self.elf_align);
        M::set_offset(&mut self.layout.section_offset, offset);
        self.write_section_header(&SectionHeader {
            name: None,
            sh_type: elf::SHT_NULL,
            sh_flags: elf::SectionFlags(0),
            sh_addr: 0,
            sh_offset: 0,
            sh_size: if self.layout.section_num >= elf::SHN_LORESERVE.into() {
                self.layout.section_num.into()
            } else {
                0
            },
            sh_link: if self.layout.shstrtab_index.0 >= elf::SHN_LORESERVE.into() {
                self.layout.shstrtab_index.0
            } else {
                0
            },
            sh_info: if self.layout.segment_num >= elf::PN_XNUM.into() {
                self.layout.segment_num
            } else {
                0
            },
            sh_addralign: 0,
            sh_entsize: 0,
        });
        offset
    }

    /// Write a section header.
    ///
    /// Must be called after [`Self::write_null_section_header`].
    pub fn write_section_header(&mut self, section: &SectionHeader) -> SectionIndex {
        let sh_name = if let Some(name) = section.name {
            self.shstrtab.get_offset(name)
        } else {
            0
        };
        let endian = self.endian;
        if self.is_64 {
            let section = elf::SectionHeader64 {
                sh_name: U32::new(endian, sh_name),
                sh_type: U32::new(endian, section.sh_type),
                sh_flags: U64::new(endian, section.sh_flags),
                sh_addr: U64::new(endian, section.sh_addr),
                sh_offset: U64::new(endian, section.sh_offset),
                sh_size: U64::new(endian, section.sh_size),
                sh_link: U32::new(endian, section.sh_link),
                sh_info: U32::new(endian, section.sh_info),
                sh_addralign: U64::new(endian, section.sh_addralign),
                sh_entsize: U64::new(endian, section.sh_entsize),
            };
            self.buffer.write(&section);
        } else {
            let section = elf::SectionHeader32 {
                sh_name: U32::new(endian, sh_name),
                sh_type: U32::new(endian, section.sh_type),
                sh_flags: U32::new_u64_truncate(endian, section.sh_flags),
                sh_addr: U32::new(endian, section.sh_addr as u32),
                sh_offset: U32::new(endian, section.sh_offset as u32),
                sh_size: U32::new(endian, section.sh_size as u32),
                sh_link: U32::new(endian, section.sh_link),
                sh_info: U32::new(endian, section.sh_info),
                sh_addralign: U32::new(endian, section.sh_addralign as u32),
                sh_entsize: U32::new(endian, section.sh_entsize as u32),
            };
            self.buffer.write(&section);
        }
        let index = SectionIndex(self.written_section_num);
        self.written_section_num += 1;
        M::set_count(&mut self.layout.section_num, self.written_section_num);
        index
    }

    /// Add a section name to the section header string table.
    ///
    /// This will be stored in the `.shstrtab` section.
    ///
    /// Must be called before [`Self::reserve_shstrtab`] in two-phase mode,
    /// or before [`Self::write_shstrtab`] in single-phase mode.
    pub fn add_section_name(&mut self, name: &'a [u8]) -> StringId {
        debug_assert_eq!(self.shstrtab_offset, 0);
        self.shstrtab.add(name)
    }

    /// Write the section header for the section header string table.
    ///
    /// The header is only written if the section index was reserved in two-phase
    /// mode, or [`Self::write_shstrtab`] was called in single-phase mode.
    pub fn write_shstrtab_section_header(&mut self) {
        if self.shstrtab_str_id.is_none() {
            return;
        }
        debug_assert_ne!(self.shstrtab_offset, 0);
        let index = self.write_section_header(&SectionHeader {
            name: self.shstrtab_str_id,
            sh_type: elf::SHT_STRTAB,
            sh_flags: elf::SectionFlags(0),
            sh_addr: 0,
            sh_offset: self.shstrtab_offset,
            sh_size: self.shstrtab_size.into(),
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 0,
        });
        M::set_section_index(&mut self.layout.shstrtab_index, index);
    }

    /// Add a string to the string table.
    ///
    /// This will be stored in the `.strtab` section.
    ///
    /// Must be called before [`Self::reserve_strtab`] in two-phase mode,
    /// or before [`Self::write_strtab`] in single-phase mode.
    pub fn add_string(&mut self, name: &'a [u8]) -> StringId {
        debug_assert_eq!(self.strtab_offset, 0);
        self.strtab.add(name)
    }

    /// Write the section header for the string table.
    ///
    /// Only writes the header if the section index was reserved in two-phase mode,
    /// or [`Self::write_strtab`] wrote the string table in single-phase mode.
    pub fn write_strtab_section_header(&mut self) {
        if self.strtab_str_id.is_none() {
            return;
        }
        let index = self.write_section_header(&SectionHeader {
            name: self.strtab_str_id,
            sh_type: elf::SHT_STRTAB,
            sh_flags: elf::SectionFlags(0),
            sh_addr: 0,
            sh_offset: self.strtab_offset,
            sh_size: self.strtab_size.into(),
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 0,
        });
        M::set_section_index(&mut self.strtab_index, index);
    }

    /// Write the null symbol.
    ///
    /// This must be the first symbol that is written.
    ///
    /// Returns the file offset of the symbol.
    /// In two-phase mode, returns 0 without writing if no symbols were reserved.
    pub fn write_null_symbol(&mut self) -> u64 {
        if !M::need_offset(self.symtab_offset) {
            return 0;
        }
        let offset = self.write_align(self.elf_align);
        M::set_offset(&mut self.symtab_offset, offset);
        M::set_section_name(&mut self.symtab_str_id, &mut self.shstrtab, b".symtab");
        if self.is_64 {
            self.buffer.write(&elf::Sym64::<Endianness>::default());
        } else {
            self.buffer.write(&elf::Sym32::<Endianness>::default());
        }

        if M::need_offset(self.symtab_shndx_offset) {
            self.symtab_shndx_data
                .write_pod(&U32::new(self.endian, 0u32));
        }

        self.written_symtab_num = 1;
        M::set_count(&mut self.symtab_num, self.written_symtab_num);
        // The symtab must link to a strtab.
        self.need_strtab = true;
        offset
    }

    /// Write a symbol.
    ///
    /// Must be called after [`Self::write_null_symbol`].
    pub fn write_symbol(&mut self, sym: &Sym) -> SymbolIndex {
        let st_name = if let Some(name) = sym.name {
            self.strtab.get_offset(name)
        } else {
            0
        };
        let st_shndx = if let Some(section) = sym.section {
            elf::SymbolSection::new(section.0)
        } else {
            sym.st_shndx
        };

        let endian = self.endian;
        if self.is_64 {
            let sym = elf::Sym64 {
                st_name: U32::new(endian, st_name),
                st_info: sym.st_info,
                st_other: sym.st_other,
                st_shndx: U16::new(endian, st_shndx),
                st_value: U64::new(endian, sym.st_value),
                st_size: U64::new(endian, sym.st_size),
            };
            self.buffer.write(&sym);
        } else {
            let sym = elf::Sym32 {
                st_name: U32::new(endian, st_name),
                st_info: sym.st_info,
                st_other: sym.st_other,
                st_shndx: U16::new(endian, st_shndx),
                st_value: U32::new(endian, sym.st_value as u32),
                st_size: U32::new(endian, sym.st_size as u32),
            };
            self.buffer.write(&sym);
        }

        if M::need_offset(self.symtab_shndx_offset) {
            let section_index = if st_shndx == elf::SHN_XINDEX {
                self.need_symtab_shndx = true;
                sym.section.map_or(0, |s| s.0)
            } else {
                0
            };
            self.symtab_shndx_data
                .write_pod(&U32::new(self.endian, section_index));
        }

        let index = SymbolIndex(self.written_symtab_num);
        self.written_symtab_num += 1;
        M::set_count(&mut self.symtab_num, self.written_symtab_num);
        index
    }

    /// Write the section header for the symbol table.
    ///
    /// Only writes the header if the section index was reserved in two-phase mode,
    /// or [`Self::write_null_symbol`] was called in single-phase mode.
    pub fn write_symtab_section_header(&mut self, num_local: u32) {
        if self.symtab_str_id.is_none() {
            return;
        }
        let index = self.write_section_header(&SectionHeader {
            name: self.symtab_str_id,
            sh_type: elf::SHT_SYMTAB,
            sh_flags: elf::SectionFlags(0),
            sh_addr: 0,
            sh_offset: self.symtab_offset,
            sh_size: self.symtab_num as u64 * self.class().sym_size() as u64,
            sh_link: self.strtab_index.0,
            sh_info: num_local,
            sh_addralign: self.elf_align as u64,
            sh_entsize: self.class().sym_size() as u64,
        });
        M::set_section_index(&mut self.symtab_index, index);
    }

    /// Write the extended section indices for the symbol table.
    ///
    /// Returns the file offset of the start of the data.
    /// Returns 0 without writing if extended section indices are not needed.
    pub fn write_symtab_shndx(&mut self) -> u64 {
        if !self.need_symtab_shndx {
            self.symtab_shndx_data = Vec::new();
            return 0;
        }
        let offset = self.write_align(ALIGN_SYMTAB_SHNDX);
        M::set_offset(&mut self.symtab_shndx_offset, offset);
        M::set_section_name(
            &mut self.symtab_shndx_str_id,
            &mut self.shstrtab,
            b".symtab_shndx",
        );
        self.buffer.write_bytes(&self.symtab_shndx_data);
        self.symtab_shndx_data = Vec::new();
        offset
    }

    /// Write the section header for the extended section indices for the symbol table.
    ///
    /// Only writes the header if the section index was reserved in two-phase mode,
    /// or [`Self::write_symtab_shndx`] was called in single-phase mode.
    pub fn write_symtab_shndx_section_header(&mut self) {
        if self.symtab_shndx_str_id.is_none() {
            return;
        }
        let sh_size = if self.symtab_shndx_offset == 0 {
            0
        } else {
            (self.symtab_num * 4) as u64
        };
        self.write_section_header(&SectionHeader {
            name: self.symtab_shndx_str_id,
            sh_type: elf::SHT_SYMTAB_SHNDX,
            sh_flags: elf::SectionFlags(0),
            sh_addr: 0,
            sh_offset: self.symtab_shndx_offset,
            sh_size,
            sh_link: self.symtab_index.0,
            sh_info: 0,
            sh_addralign: ALIGN_SYMTAB_SHNDX as u64,
            sh_entsize: 4,
        });
    }

    /// Add a string to the dynamic string table.
    ///
    /// This will be stored in the `.dynstr` section.
    ///
    /// Must be called before [`Self::reserve_dynstr`] in two-phase mode,
    /// or before [`Self::write_dynstr`] in single-phase mode.
    pub fn add_dynamic_string(&mut self, name: &'a [u8]) -> StringId {
        debug_assert_eq!(self.dynstr_offset, 0);
        self.dynstr.add(name)
    }

    /// Get a string that was previously added to the dynamic string table.
    ///
    /// Panics if the string was not added.
    pub fn get_dynamic_string(&self, name: &'a [u8]) -> StringId {
        self.dynstr.get_id(name)
    }

    /// Write the section header for the dynamic string table.
    ///
    /// Only writes the header if the section index was reserved in two-phase mode,
    /// or [`Self::write_dynstr`] wrote the string table in single-phase mode.
    pub fn write_dynstr_section_header(&mut self, sh_addr: u64) {
        if self.dynstr_str_id.is_none() {
            return;
        }
        let index = self.write_section_header(&SectionHeader {
            name: self.dynstr_str_id,
            sh_type: elf::SHT_STRTAB,
            sh_flags: elf::SHF_ALLOC,
            sh_addr,
            sh_offset: self.dynstr_offset,
            sh_size: self.dynstr_size.into(),
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 0,
        });
        M::set_section_index(&mut self.dynstr_index, index);
    }

    /// Write the null dynamic symbol.
    ///
    /// This must be the first dynamic symbol that is written.
    ///
    /// Returns the file offset of the symbol.
    /// In two-phase mode, returns 0 without writing if no dynamic symbols were reserved.
    pub fn write_null_dynamic_symbol(&mut self) -> u64 {
        if !M::need_offset(self.dynsym_offset) {
            return 0;
        }
        let offset = self.write_align(self.elf_align);
        M::set_offset(&mut self.dynsym_offset, offset);
        M::set_section_name(&mut self.dynsym_str_id, &mut self.shstrtab, b".dynsym");
        if self.is_64 {
            self.buffer.write(&elf::Sym64::<Endianness>::default());
        } else {
            self.buffer.write(&elf::Sym32::<Endianness>::default());
        }

        self.written_dynsym_num = 1;
        M::set_count(&mut self.dynsym_num, self.written_dynsym_num);
        // The symbol table must link to a string table.
        self.need_dynstr = true;
        offset
    }

    /// Write a dynamic symbol.
    ///
    /// Must be called after [`Self::write_null_dynamic_symbol`].
    pub fn write_dynamic_symbol(&mut self, sym: &Sym) -> SymbolIndex {
        let st_name = if let Some(name) = sym.name {
            self.dynstr.get_offset(name)
        } else {
            0
        };

        let st_shndx = if let Some(section) = sym.section {
            // TODO: we don't write out .dynsym_shndx yet.
            // This is unlikely to be needed though.
            elf::SymbolSection::new(section.0)
        } else {
            sym.st_shndx
        };

        let endian = self.endian;
        if self.is_64 {
            let sym = elf::Sym64 {
                st_name: U32::new(endian, st_name),
                st_info: sym.st_info,
                st_other: sym.st_other,
                st_shndx: U16::new(endian, st_shndx),
                st_value: U64::new(endian, sym.st_value),
                st_size: U64::new(endian, sym.st_size),
            };
            self.buffer.write(&sym);
        } else {
            let sym = elf::Sym32 {
                st_name: U32::new(endian, st_name),
                st_info: sym.st_info,
                st_other: sym.st_other,
                st_shndx: U16::new(endian, st_shndx),
                st_value: U32::new(endian, sym.st_value as u32),
                st_size: U32::new(endian, sym.st_size as u32),
            };
            self.buffer.write(&sym);
        }

        let index = SymbolIndex(self.written_dynsym_num);
        self.written_dynsym_num += 1;
        M::set_count(&mut self.dynsym_num, self.written_dynsym_num);
        index
    }

    /// Write the section header for the dynamic symbol table.
    ///
    /// Only writes the header if the section index was reserved in two-phase mode,
    /// or [`Self::write_null_dynamic_symbol`] was called in single-phase mode.
    pub fn write_dynsym_section_header(&mut self, sh_addr: u64, num_local: u32) {
        if self.dynsym_str_id.is_none() {
            return;
        }
        let index = self.write_section_header(&SectionHeader {
            name: self.dynsym_str_id,
            sh_type: elf::SHT_DYNSYM,
            sh_flags: elf::SHF_ALLOC,
            sh_addr,
            sh_offset: self.dynsym_offset,
            sh_size: self.dynsym_num as u64 * self.class().sym_size() as u64,
            sh_link: self.dynstr_index.0,
            sh_info: num_local,
            sh_addralign: self.elf_align as u64,
            sh_entsize: self.class().sym_size() as u64,
        });
        M::set_section_index(&mut self.dynsym_index, index);
    }

    /// Write alignment padding bytes prior to the `.dynamic` section.
    ///
    /// Returns the file offset after the padding.
    /// In two-phase mode, returns 0 without writing if the section was not reserved.
    pub fn write_align_dynamic(&mut self) -> u64 {
        if !M::need_offset(self.dynamic_offset) {
            return 0;
        }
        let offset = self.write_align(self.elf_align);
        M::set_offset(&mut self.dynamic_offset, offset);
        M::set_section_name(&mut self.dynamic_str_id, &mut self.shstrtab, b".dynamic");
        offset
    }

    /// Write a dynamic string entry.
    ///
    /// Must be called after [`Self::write_align_dynamic`].
    pub fn write_dynamic_string(&mut self, tag: elf::DynamicTag, id: StringId) -> Result<()> {
        self.write_dynamic(tag, self.dynstr.get_offset(id).into())
    }

    /// Write a dynamic value entry.
    ///
    /// Must be called after [`Self::write_align_dynamic`].
    pub fn write_dynamic(&mut self, d_tag: elf::DynamicTag, d_val: u64) -> Result<()> {
        let endian = self.endian;
        if self.is_64 {
            let d = elf::Dyn64 {
                d_tag: I64::new(endian, d_tag),
                d_val: U64::new(endian, d_val),
            };
            self.buffer.write(&d);
        } else {
            let d_tag = I32::new_i64(endian, d_tag)
                .map_err(|_| Error(format!("d_tag overflow: 0x{:x}", d_tag)))?;
            let d_val = d_val
                .try_into()
                .map_err(|_| Error(format!("d_val overflow: 0x{:x}", d_val)))?;
            let d = elf::Dyn32 {
                d_tag,
                d_val: U32::new(endian, d_val),
            };
            self.buffer.write(&d);
        }
        self.written_dynamic_num += 1;
        M::set_count(&mut self.dynamic_num, self.written_dynamic_num);
        Ok(())
    }

    /// Write the section header for the dynamic table.
    ///
    /// Only writes the header if the section index was reserved in two-phase mode,
    /// or [`Self::write_align_dynamic`] was called in single-phase mode.
    pub fn write_dynamic_section_header(&mut self, sh_addr: u64) {
        if self.dynamic_str_id.is_none() {
            return;
        }
        self.write_section_header(&SectionHeader {
            name: self.dynamic_str_id,
            sh_type: elf::SHT_DYNAMIC,
            sh_flags: elf::SHF_WRITE | elf::SHF_ALLOC,
            sh_addr,
            sh_offset: self.dynamic_offset,
            sh_size: (self.dynamic_num * self.class().dyn_size()) as u64,
            sh_link: self.dynstr_index.0,
            sh_info: 0,
            sh_addralign: self.elf_align as u64,
            sh_entsize: self.class().dyn_size() as u64,
        });
    }

    /// Write a SysV hash section.
    ///
    /// `chain_count` is the number of symbols in the hash.
    /// The argument to `hash` will be in the range `0..chain_count`.
    ///
    /// In two-phase mode, [`Self::reserve_hash`] must be called before this.
    ///
    /// Returns the file offset of the hash table data.
    pub fn write_hash<F>(&mut self, bucket_count: u32, chain_count: u32, hash: F) -> u64
    where
        F: Fn(u32) -> Option<u32>,
    {
        let mut buckets = vec![U32::new(self.endian, 0); bucket_count as usize];
        let mut chains = vec![U32::new(self.endian, 0); chain_count as usize];
        for i in 0..chain_count {
            if let Some(hash) = hash(i) {
                let bucket = hash % bucket_count;
                chains[i as usize] = buckets[bucket as usize];
                buckets[bucket as usize] = U32::new(self.endian, i);
            }
        }

        let offset = self.write_align(ALIGN_HASH);
        M::set_offset(&mut self.hash_offset, offset);
        M::set_section_name(&mut self.hash_str_id, &mut self.shstrtab, b".hash");
        self.buffer.write(&elf::HashHeader {
            bucket_count: U32::new(self.endian, bucket_count),
            chain_count: U32::new(self.endian, chain_count),
        });
        self.buffer.write_slice(&buckets);
        self.buffer.write_slice(&chains);
        let size = self.offset() - self.hash_offset;
        M::set_size(&mut self.hash_size, size);
        offset
    }

    /// Write the section header for the SysV hash table.
    ///
    /// Only writes the header if the section index was reserved in two-phase mode,
    /// or [`Self::write_hash`] was called in single-phase mode.
    pub fn write_hash_section_header(&mut self, sh_addr: u64) {
        if self.hash_str_id.is_none() {
            return;
        }
        self.write_section_header(&SectionHeader {
            name: self.hash_str_id,
            sh_type: elf::SHT_HASH,
            sh_flags: elf::SHF_ALLOC,
            sh_addr,
            sh_offset: self.hash_offset,
            sh_size: self.hash_size,
            sh_link: self.dynsym_index.0,
            sh_info: 0,
            sh_addralign: ALIGN_HASH as u64,
            sh_entsize: 4,
        });
    }

    /// Write a GNU hash section.
    ///
    /// `symbol_count` is the number of symbols in the hash.
    /// The argument to `hash` will be in the range `0..symbol_count`.
    ///
    /// This requires that symbols are already sorted by bucket.
    ///
    /// In two-phase mode, [`Self::reserve_gnu_hash`] must be called before this.
    ///
    /// Returns the file offset of the hash table data.
    pub fn write_gnu_hash<F>(
        &mut self,
        symbol_base: u32,
        bloom_shift: u32,
        bloom_count: u32,
        bucket_count: u32,
        symbol_count: u32,
        hash: F,
    ) -> u64
    where
        F: Fn(u32) -> u32,
    {
        let offset = self.write_align(self.elf_align);
        M::set_offset(&mut self.gnu_hash_offset, offset);
        M::set_section_name(&mut self.gnu_hash_str_id, &mut self.shstrtab, b".gnu.hash");
        self.buffer.write(&elf::GnuHashHeader {
            bucket_count: U32::new(self.endian, bucket_count),
            symbol_base: U32::new(self.endian, symbol_base),
            bloom_count: U32::new(self.endian, bloom_count),
            bloom_shift: U32::new(self.endian, bloom_shift),
        });

        // Calculate and write bloom filter.
        if self.is_64 {
            let mut bloom_filters = vec![0u64; bloom_count as usize];
            for i in 0..symbol_count {
                let h = hash(i);
                bloom_filters[((h / 64) & (bloom_count - 1)) as usize] |=
                    1 << (h % 64) | 1 << ((h >> bloom_shift) % 64);
            }
            for bloom_filter in bloom_filters {
                self.buffer.write(&U64::new(self.endian, bloom_filter));
            }
        } else {
            let mut bloom_filters = vec![0u32; bloom_count as usize];
            for i in 0..symbol_count {
                let h = hash(i);
                bloom_filters[((h / 32) & (bloom_count - 1)) as usize] |=
                    1 << (h % 32) | 1 << ((h >> bloom_shift) % 32);
            }
            for bloom_filter in bloom_filters {
                self.buffer.write(&U32::new(self.endian, bloom_filter));
            }
        }

        // Write buckets.
        //
        // This requires that symbols are already sorted by bucket.
        let mut bucket = 0;
        for i in 0..symbol_count {
            let symbol_bucket = hash(i) % bucket_count;
            while bucket < symbol_bucket {
                self.buffer.write(&U32::new(self.endian, 0u32));
                bucket += 1;
            }
            if bucket == symbol_bucket {
                self.buffer.write(&U32::new(self.endian, symbol_base + i));
                bucket += 1;
            }
        }
        while bucket < bucket_count {
            self.buffer.write(&U32::new(self.endian, 0u32));
            bucket += 1;
        }

        // Write hash values.
        for i in 0..symbol_count {
            let mut h = hash(i);
            if i == symbol_count - 1 || h % bucket_count != hash(i + 1) % bucket_count {
                h |= 1;
            } else {
                h &= !1;
            }
            self.buffer.write(&U32::new(self.endian, h));
        }

        let size = self.offset() - self.gnu_hash_offset;
        M::set_size(&mut self.gnu_hash_size, size);
        offset
    }

    /// Write the section header for the GNU hash table.
    ///
    /// Only writes the header if the section index was reserved in two-phase mode,
    /// or [`Self::write_gnu_hash`] was called in single-phase mode.
    pub fn write_gnu_hash_section_header(&mut self, sh_addr: u64) {
        if self.gnu_hash_str_id.is_none() {
            return;
        }
        self.write_section_header(&SectionHeader {
            name: self.gnu_hash_str_id,
            sh_type: elf::SHT_GNU_HASH,
            sh_flags: elf::SHF_ALLOC,
            sh_addr,
            sh_offset: self.gnu_hash_offset,
            sh_size: self.gnu_hash_size,
            sh_link: self.dynsym_index.0,
            sh_info: 0,
            sh_addralign: self.elf_align as u64,
            sh_entsize: if self.is_64 { 0 } else { 4 },
        });
    }

    /// Write the null symbol version entry.
    ///
    /// This must be the first symbol version that is written.
    ///
    /// Returns the file offset of the entry.
    /// In two-phase mode, returns 0 without writing if no dynamic symbols were reserved.
    pub fn write_null_gnu_versym(&mut self) -> u64 {
        if !M::need_offset(self.gnu_versym_offset) {
            return 0;
        }
        let offset = self.write_align(ALIGN_GNU_VERSYM);
        M::set_offset(&mut self.gnu_versym_offset, offset);
        M::set_section_name(
            &mut self.gnu_versym_str_id,
            &mut self.shstrtab,
            b".gnu.version",
        );
        self.write_gnu_versym(elf::VER_NDX_LOCAL.into());
        offset
    }

    /// Write a symbol version entry.
    ///
    /// Must be called after [`Self::write_null_gnu_versym`].
    pub fn write_gnu_versym(&mut self, versym: elf::VersymIndex) {
        self.buffer.write(&U16::new(self.endian, versym));
    }

    /// Write the section header for the `.gnu.version` section.
    ///
    /// Only writes the header if the section index was reserved in two-phase mode,
    /// or [`Self::write_null_gnu_versym`] was called in single-phase mode.
    pub fn write_gnu_versym_section_header(&mut self, sh_addr: u64) {
        if self.gnu_versym_str_id.is_none() {
            return;
        }
        self.write_section_header(&SectionHeader {
            name: self.gnu_versym_str_id,
            sh_type: elf::SHT_GNU_VERSYM,
            sh_flags: elf::SHF_ALLOC,
            sh_addr,
            sh_offset: self.gnu_versym_offset,
            sh_size: self.class().gnu_versym_size(self.dynsym_num as usize) as u64,
            sh_link: self.dynsym_index.0,
            sh_info: 0,
            sh_addralign: ALIGN_GNU_VERSYM as u64,
            sh_entsize: 2,
        });
    }

    /// Write alignment padding bytes prior to a `.gnu.version_d` section.
    ///
    /// Returns the file offset after the padding.
    /// In two-phase mode, returns 0 without writing if the section was not reserved.
    pub fn write_align_gnu_verdef(&mut self) -> u64 {
        if !M::need_offset(self.gnu_verdef_offset) {
            return 0;
        }
        let offset = self.write_align(ALIGN_GNU_VERDEF);
        M::set_offset(&mut self.gnu_verdef_offset, offset);
        M::set_section_name(
            &mut self.gnu_verdef_str_id,
            &mut self.shstrtab,
            b".gnu.version_d",
        );
        offset
    }

    /// Write a version definition entry.
    ///
    /// Must be called after [`Self::write_align_gnu_verdef`]. The number of entries
    /// must have been set via [`Self::reserve_gnu_verdef`] in two-phase mode, or
    /// [`Self::set_gnu_verdef_count`] in single-phase mode.
    pub fn write_gnu_verdef(&mut self, verdef: &Verdef) {
        debug_assert_ne!(self.gnu_verdef_remaining, 0);
        self.gnu_verdef_remaining -= 1;
        let vd_next = if self.gnu_verdef_remaining == 0 {
            0
        } else {
            mem::size_of::<elf::Verdef<Endianness>>() as u32
                + verdef.aux_count as u32 * mem::size_of::<elf::Verdaux<Endianness>>() as u32
        };

        debug_assert_ne!(verdef.aux_count, 0);
        self.gnu_verdaux_remaining = verdef.aux_count;
        self.written_verdaux_count += verdef.aux_count as usize;
        M::set_count(&mut self.gnu_verdaux_count, self.written_verdaux_count);
        let vd_aux = mem::size_of::<elf::Verdef<Endianness>>() as u32;

        self.buffer.write(&elf::Verdef {
            vd_version: U16::new(self.endian, verdef.version),
            vd_flags: U16::new(self.endian, verdef.flags),
            vd_ndx: U16::new(self.endian, verdef.index),
            vd_cnt: U16::new(self.endian, verdef.aux_count),
            vd_hash: U32::new(self.endian, elf::hash(self.dynstr.get_string(verdef.name))),
            vd_aux: U32::new(self.endian, vd_aux),
            vd_next: U32::new(self.endian, vd_next),
        });
        self.write_gnu_verdaux(verdef.name);
    }

    /// Write a version definition entry that shares the names of the next definition.
    ///
    /// This is typically useful when there are only two versions (including the base)
    /// and they have the same name.
    ///
    /// Must be called after [`Self::write_align_gnu_verdef`]. The number of entries
    /// must have been set via [`Self::reserve_gnu_verdef`] in two-phase mode, or
    /// [`Self::set_gnu_verdef_count`] in single-phase mode.
    pub fn write_gnu_verdef_shared(&mut self, verdef: &Verdef) {
        debug_assert_ne!(self.gnu_verdef_remaining, 0);
        self.gnu_verdef_remaining -= 1;
        debug_assert_ne!(self.gnu_verdef_remaining, 0);
        let vd_next = mem::size_of::<elf::Verdef<Endianness>>() as u32;

        debug_assert_ne!(verdef.aux_count, 0);
        self.gnu_verdaux_remaining = 0;
        let vd_aux = 2 * mem::size_of::<elf::Verdef<Endianness>>() as u32;

        self.buffer.write(&elf::Verdef {
            vd_version: U16::new(self.endian, verdef.version),
            vd_flags: U16::new(self.endian, verdef.flags),
            vd_ndx: U16::new(self.endian, verdef.index),
            vd_cnt: U16::new(self.endian, verdef.aux_count),
            vd_hash: U32::new(self.endian, elf::hash(self.dynstr.get_string(verdef.name))),
            vd_aux: U32::new(self.endian, vd_aux),
            vd_next: U32::new(self.endian, vd_next),
        });
    }

    /// Write a version definition auxiliary entry.
    ///
    /// Must be called inside a version definition started by [`Self::write_gnu_verdef`].
    pub fn write_gnu_verdaux(&mut self, name: StringId) {
        debug_assert_ne!(self.gnu_verdaux_remaining, 0);
        self.gnu_verdaux_remaining -= 1;
        let vda_next = if self.gnu_verdaux_remaining == 0 {
            0
        } else {
            mem::size_of::<elf::Verdaux<Endianness>>() as u32
        };
        self.buffer.write(&elf::Verdaux {
            vda_name: U32::new(self.endian, self.dynstr.get_offset(name)),
            vda_next: U32::new(self.endian, vda_next),
        });
    }

    /// Write the section header for the `.gnu.version_d` section.
    ///
    /// Only writes the header if the section index was reserved in two-phase mode,
    /// or [`Self::write_align_gnu_verdef`] was called in single-phase mode.
    pub fn write_gnu_verdef_section_header(&mut self, sh_addr: u64) {
        if self.gnu_verdef_str_id.is_none() {
            return;
        }
        let sh_size = self
            .class()
            .gnu_verdef_size(self.gnu_verdef_count as usize, self.gnu_verdaux_count)
            as u64;
        self.write_section_header(&SectionHeader {
            name: self.gnu_verdef_str_id,
            sh_type: elf::SHT_GNU_VERDEF,
            sh_flags: elf::SHF_ALLOC,
            sh_addr,
            sh_offset: self.gnu_verdef_offset,
            sh_size,
            sh_link: self.dynstr_index.0,
            sh_info: self.gnu_verdef_count.into(),
            sh_addralign: ALIGN_GNU_VERDEF as u64,
            sh_entsize: 0,
        });
    }

    /// Write alignment padding bytes prior to a `.gnu.version_r` section.
    ///
    /// Returns the file offset after the padding.
    /// In two-phase mode, returns 0 without writing if the section was not reserved.
    pub fn write_align_gnu_verneed(&mut self) -> u64 {
        if !M::need_offset(self.gnu_verneed_offset) {
            return 0;
        }
        let offset = self.write_align(ALIGN_GNU_VERNEED);
        M::set_offset(&mut self.gnu_verneed_offset, offset);
        M::set_section_name(
            &mut self.gnu_verneed_str_id,
            &mut self.shstrtab,
            b".gnu.version_r",
        );
        offset
    }

    /// Write a version need entry.
    ///
    /// Must be called after [`Self::write_align_gnu_verneed`]. The number of entries
    /// must have been set via [`Self::reserve_gnu_verneed`] in two-phase mode, or
    /// [`Self::set_gnu_verneed_count`] in single-phase mode.
    pub fn write_gnu_verneed(&mut self, verneed: &Verneed) {
        debug_assert_ne!(self.gnu_verneed_remaining, 0);
        self.gnu_verneed_remaining -= 1;
        let vn_next = if self.gnu_verneed_remaining == 0 {
            0
        } else {
            mem::size_of::<elf::Verneed<Endianness>>() as u32
                + verneed.aux_count as u32 * mem::size_of::<elf::Vernaux<Endianness>>() as u32
        };

        let vn_aux = if verneed.aux_count == 0 {
            0
        } else {
            self.gnu_vernaux_remaining = verneed.aux_count;
            self.written_vernaux_count += verneed.aux_count as usize;
            M::set_count(&mut self.gnu_vernaux_count, self.written_vernaux_count);
            mem::size_of::<elf::Verneed<Endianness>>() as u32
        };

        self.buffer.write(&elf::Verneed {
            vn_version: U16::new(self.endian, verneed.version),
            vn_cnt: U16::new(self.endian, verneed.aux_count),
            vn_file: U32::new(self.endian, self.dynstr.get_offset(verneed.file)),
            vn_aux: U32::new(self.endian, vn_aux),
            vn_next: U32::new(self.endian, vn_next),
        });
    }

    /// Write a version need auxiliary entry.
    ///
    /// Must be called inside a version need started by [`Self::write_gnu_verneed`].
    pub fn write_gnu_vernaux(&mut self, vernaux: &Vernaux) {
        debug_assert_ne!(self.gnu_vernaux_remaining, 0);
        self.gnu_vernaux_remaining -= 1;
        let vna_next = if self.gnu_vernaux_remaining == 0 {
            0
        } else {
            mem::size_of::<elf::Vernaux<Endianness>>() as u32
        };
        self.buffer.write(&elf::Vernaux {
            vna_hash: U32::new(self.endian, elf::hash(self.dynstr.get_string(vernaux.name))),
            vna_flags: U16::new(self.endian, vernaux.flags),
            vna_other: U16::new(self.endian, vernaux.index),
            vna_name: U32::new(self.endian, self.dynstr.get_offset(vernaux.name)),
            vna_next: U32::new(self.endian, vna_next),
        });
    }

    /// Write the section header for the `.gnu.version_r` section.
    ///
    /// Only writes the header if the section index was reserved in two-phase mode,
    /// or [`Self::write_align_gnu_verneed`] was called in single-phase mode.
    pub fn write_gnu_verneed_section_header(&mut self, sh_addr: u64) {
        if self.gnu_verneed_str_id.is_none() {
            return;
        }
        let sh_size = self
            .class()
            .gnu_verneed_size(self.gnu_verneed_count as usize, self.gnu_vernaux_count)
            as u64;
        self.write_section_header(&SectionHeader {
            name: self.gnu_verneed_str_id,
            sh_type: elf::SHT_GNU_VERNEED,
            sh_flags: elf::SHF_ALLOC,
            sh_addr,
            sh_offset: self.gnu_verneed_offset,
            sh_size,
            sh_link: self.dynstr_index.0,
            sh_info: self.gnu_verneed_count.into(),
            sh_addralign: ALIGN_GNU_VERNEED as u64,
            sh_entsize: 0,
        });
    }

    /// Write the section header for the `.gnu.attributes` section.
    ///
    /// Only writes the header if the section index was reserved in two-phase mode,
    /// or [`Self::write_gnu_attributes`] was called in single-phase mode.
    pub fn write_gnu_attributes_section_header(&mut self) {
        if self.gnu_attributes_str_id.is_none() {
            return;
        }
        self.write_section_header(&SectionHeader {
            name: self.gnu_attributes_str_id,
            sh_type: elf::SHT_GNU_ATTRIBUTES,
            sh_flags: elf::SectionFlags(0),
            sh_addr: 0,
            sh_offset: self.gnu_attributes_offset,
            sh_size: self.gnu_attributes_size,
            sh_link: self.dynstr_index.0,
            sh_info: 0, // TODO
            sh_addralign: self.elf_align as u64,
            sh_entsize: 0,
        });
    }

    /// Write the data for the `.gnu.attributes` section.
    ///
    /// Returns the file offset of the data.
    /// In two-phase mode, returns 0 without writing if the section was not reserved.
    pub fn write_gnu_attributes(&mut self, data: &[u8]) -> u64 {
        if !M::need_offset(self.gnu_attributes_offset) {
            return 0;
        }
        let offset = self.write_align(self.elf_align);
        M::set_offset(&mut self.gnu_attributes_offset, offset);
        M::set_section_name(
            &mut self.gnu_attributes_str_id,
            &mut self.shstrtab,
            b".gnu.attributes",
        );
        self.buffer.write_bytes(data);
        let size = self.offset() - self.gnu_attributes_offset;
        M::set_size(&mut self.gnu_attributes_size, size);
        offset
    }

    /// Write alignment padding bytes prior to a relocation section.
    ///
    /// Returns the file offset after the padding.
    pub fn write_align_relocation(&mut self) -> u64 {
        self.write_align(self.elf_align)
    }

    /// Write a relocation.
    ///
    /// [`Self::write_align_relocation`] should be called before the first relocation
    /// of a section. In two-phase mode, the file range must have been reserved with
    /// [`Self::reserve_relocations`].
    pub fn write_relocation(&mut self, is_rela: bool, rel: &Rel) {
        let endian = self.endian;
        if self.is_64 {
            if is_rela {
                let rel = elf::Rela64 {
                    r_offset: U64::new(endian, rel.r_offset),
                    r_info: elf::Rela64::r_info(endian, self.is_mips64el, rel.r_sym, rel.r_type),
                    r_addend: I64::new(endian, rel.r_addend),
                };
                self.buffer.write(&rel);
            } else {
                let rel = elf::Rel64 {
                    r_offset: U64::new(endian, rel.r_offset),
                    r_info: elf::Rel64::r_info(endian, rel.r_sym, rel.r_type),
                };
                self.buffer.write(&rel);
            }
        } else {
            if is_rela {
                let rel = elf::Rela32 {
                    r_offset: U32::new(endian, rel.r_offset as u32),
                    r_info: elf::Rel32::r_info(endian, rel.r_sym, rel.r_type as u8),
                    r_addend: I32::new(endian, rel.r_addend as i32),
                };
                self.buffer.write(&rel);
            } else {
                let rel = elf::Rel32 {
                    r_offset: U32::new(endian, rel.r_offset as u32),
                    r_info: elf::Rel32::r_info(endian, rel.r_sym, rel.r_type as u8),
                };
                self.buffer.write(&rel);
            }
        }
    }

    /// Write the section header for a relocation section.
    ///
    /// `section` is the index of the section the relocations apply to,
    /// or 0 if none.
    ///
    /// `symtab` is the index of the symbol table the relocations refer to,
    /// or 0 if none.
    ///
    /// `offset` is the file offset of the relocations.
    pub fn write_relocation_section_header(
        &mut self,
        name: StringId,
        section: SectionIndex,
        symtab: SectionIndex,
        offset: u64,
        count: usize,
        is_rela: bool,
    ) {
        self.write_section_header(&SectionHeader {
            name: Some(name),
            sh_type: if is_rela { elf::SHT_RELA } else { elf::SHT_REL },
            sh_flags: elf::SHF_INFO_LINK,
            sh_addr: 0,
            sh_offset: offset,
            sh_size: (count * self.class().rel_size(is_rela)) as u64,
            sh_link: symtab.0,
            sh_info: section.0,
            sh_addralign: self.elf_align as u64,
            sh_entsize: self.class().rel_size(is_rela) as u64,
        });
    }

    /// Write the section header for a relative relocation section.
    ///
    /// `offset` is the file offset of the relocations.
    /// `size` is the size of the section in bytes.
    pub fn write_relative_relocation_section_header(
        &mut self,
        name: StringId,
        offset: usize,
        size: usize,
    ) {
        self.write_section_header(&SectionHeader {
            name: Some(name),
            sh_type: elf::SHT_RELA,
            sh_flags: elf::SectionFlags(0),
            sh_addr: 0,
            sh_offset: offset as u64,
            sh_size: size as u64,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: self.elf_align as u64,
            sh_entsize: self.class().relr_size() as u64,
        });
    }

    /// Write `GRP_COMDAT` at the start of the COMDAT section.
    pub fn write_comdat_header(&mut self) {
        util::write_align(self.buffer, 4);
        self.buffer.write(&U32::new(self.endian, elf::GRP_COMDAT));
    }

    /// Write an entry in a COMDAT section.
    pub fn write_comdat_entry(&mut self, entry: SectionIndex) {
        self.buffer.write(&U32::new(self.endian, entry.0));
    }

    /// Write the section header for a COMDAT section.
    pub fn write_comdat_section_header(
        &mut self,
        name: StringId,
        symtab: SectionIndex,
        symbol: SymbolIndex,
        offset: u64,
        count: usize,
    ) {
        self.write_section_header(&SectionHeader {
            name: Some(name),
            sh_type: elf::SHT_GROUP,
            sh_flags: elf::SectionFlags(0),
            sh_addr: 0,
            sh_offset: offset,
            sh_size: ((count + 1) * 4) as u64,
            sh_link: symtab.0,
            sh_info: symbol.0,
            sh_addralign: 4,
            sh_entsize: 4,
        });
    }

    /// Return a helper for writing an attributes section.
    pub fn attributes_writer(&self) -> AttributesWriter {
        AttributesWriter::new(self.endian)
    }
}

/// Single-phase writer for ELF files.
///
/// See [`SinglePhase`].
pub type SinglePhaseWriter<'a> = Writer<'a, SinglePhase>;

/// Single-phase writing mode for [`Writer`].
///
/// Construct a writer with this mode using [`Writer::new_single_phase`].
///
/// There is no reservation phase: items are written directly and their file offsets are
/// discovered as they are written. The `reserve_*` methods are not available in this mode.
///
/// Items must be written before they are referenced:
/// - write section data before section headers
/// - write string tables before they are referenced
/// - write metadata section headers before they are referenced (e.g. `.strtab` before `.symtab`)
///
/// The one exception is the file header, which must be written first, but needs to
/// reference the program header table and section header table. To support this, you can
/// call [`Writer::write_file_header`] to write placeholders, then after everything
/// is written call [`Writer::write_file_header_to`] using a new buffer, and manually copy
/// the header to the start.
///
/// The `Writer` will assign section indices to metadata sections as the headers are
/// written. However, for text/data sections you will need to manually determine
/// the section indices ahead of time if you need to reference sections from
/// symbols. Similarly, for symbol indices if you need to reference symbols from
/// relocations.
#[derive(Debug)]
pub struct SinglePhase(());

impl Mode for SinglePhase {}
#[allow(private_interfaces)]
impl ModeSealed for SinglePhase {
    fn reserve(&self, _buffer: &mut dyn WritableBuffer) -> Result<()> {
        Ok(())
    }

    fn need_offset(offset: u64) -> bool {
        debug_assert_eq!(offset, 0);
        true
    }

    fn set_offset(dest: &mut u64, offset: u64) {
        debug_assert_eq!(*dest, 0);
        *dest = offset;
    }

    fn set_size(dest: &mut u64, size: u64) {
        debug_assert_eq!(*dest, 0);
        *dest = size;
    }

    fn set_section_index(dest: &mut SectionIndex, index: SectionIndex) {
        debug_assert_eq!(dest.0, 0);
        *dest = index;
    }

    fn set_section_name(
        dest: &mut Option<StringId>,
        shstrtab: &mut StringTable<'_>,
        name: &'static [u8],
    ) {
        debug_assert!(dest.is_none());
        *dest = Some(shstrtab.add(name));
    }

    fn set_count<T: Copy + PartialOrd>(dest: &mut T, count: T) {
        debug_assert!(*dest < count);
        *dest = count;
    }
}

impl<'a> Writer<'a, SinglePhase> {
    /// Create a new single-phase `Writer` for the given endianness and ELF class.
    pub fn new_single_phase(
        endian: Endianness,
        is_64: bool,
        buffer: &'a mut dyn GrowableBuffer,
    ) -> Self {
        Writer::new_with_mode(endian, is_64, buffer.as_writable(), SinglePhase(()))
    }

    /// Write the file header to the given buffer.
    ///
    /// This is needed to write fields such as the section header offset into the file
    /// header. You must manually copy the resulting `buffer` contents to the start of the
    /// original buffer after dropping the `Writer`.
    pub fn write_file_header_to(&mut self, buffer: &mut dyn WritableBuffer) -> Result<()> {
        if self.layout.section_num >= elf::SHN_LORESERVE.into() {
            // The null section header was written before section_num was known,
            // so it won't contain the overflow value.
            return Err(Error(String::from(
                "single phase write doesn't support e_shnum overflow",
            )));
        }
        Self::write_file_header_impl(buffer, self.endian, self.is_64, &self.header, &self.layout)
    }

    /// Write a placeholder for the program header table immediately after the file header.
    ///
    /// Must be called immediately after [`Self::write_file_header`] and before any
    /// other data is written. This pads the buffer by `count` program header entries.
    /// Use [`Self::write_headers_to`] to write the program headers once their contents
    /// are known.
    ///
    /// Returns the file offset and size of the program headers.
    /// Returns `(0, 0)` if `count` is zero.
    pub fn write_program_headers_placeholder(&mut self, count: u32) -> (u64, u64) {
        if count == 0 {
            return (0, 0);
        }
        // file_header_size is always a multiple of elf_align, so no alignment
        // padding is required.
        let offset = self.offset();
        debug_assert_eq!(offset, self.class().file_header_size() as u64);
        SinglePhase::set_offset(&mut self.layout.segment_offset, offset);
        SinglePhase::set_count(&mut self.layout.segment_num, count);
        self.written_segment_num = count;
        let size = count as usize * self.class().program_header_size();
        self.buffer.resize(self.buffer.len() + size);
        (offset, size as u64)
    }

    /// Write the file header and program headers to the given buffer.
    ///
    /// This serves the same purpose as [`Self::write_file_header_to`], but additionally
    /// writes the program headers immediately following the file header.  You must
    /// manually copy the resulting `buffer` contents to the start of the original buffer
    /// after dropping the `Writer`.
    ///
    /// The number of program headers must match the count passed to
    /// [`Self::write_program_headers_placeholder`].
    pub fn write_headers_to(
        &mut self,
        buffer: &mut dyn WritableBuffer,
        program_headers: &[ProgramHeader],
    ) -> Result<()> {
        debug_assert_eq!(program_headers.len() as u32, self.layout.segment_num);
        Self::write_file_header_impl(buffer, self.endian, self.is_64, &self.header, &self.layout)?;
        for header in program_headers {
            Self::write_program_header_impl(buffer, self.endian, self.is_64, header);
        }
        Ok(())
    }

    /// Write a program header to the given buffer.
    ///
    /// This serves the same purpose as [`Self::write_headers_to`], but allows you to use
    /// separate calls for writing the file header and each program header.
    pub fn write_program_header_to(
        &mut self,
        buffer: &mut dyn WritableBuffer,
        header: &ProgramHeader,
    ) {
        Self::write_program_header_impl(buffer, self.endian, self.is_64, header);
    }

    /// Write the section header string table.
    ///
    /// Always writes the string table, even if it is empty.
    ///
    /// Returns the file offset and size of the data.
    pub fn write_shstrtab(&mut self) -> Result<(u64, u32)> {
        // This must be written before the .shstrtab section header, so
        // we can't use write_null_section_header to determine if it is needed.
        // Thus we always write this if called.
        debug_assert_eq!(self.shstrtab_offset, 0);
        self.shstrtab_str_id = Some(self.add_section_name(b".shstrtab"));
        // Start with null section name.
        let mut data = vec![0];
        self.shstrtab_size = self.shstrtab.write(1, &mut data)?;
        self.shstrtab_offset = self.offset();
        self.write(&data);
        Ok((self.shstrtab_offset, self.shstrtab_size))
    }

    /// Write the string table.
    ///
    /// Returns the file offset and size of the data.
    /// Returns `(0, 0)` without writing anything if the string table is empty and
    /// there is no symbol table.
    pub fn write_strtab(&mut self) -> Result<(u64, u32)> {
        if !self.need_strtab && self.strtab.is_empty() {
            return Ok((0, 0));
        }
        debug_assert_eq!(self.strtab_offset, 0);
        self.strtab_str_id = Some(self.add_section_name(b".strtab"));
        // Start with null section name.
        let mut data = vec![0];
        self.strtab_size = self.strtab.write(1, &mut data)?;
        self.strtab_offset = self.offset();
        self.write(&data);
        Ok((self.strtab_offset, self.strtab_size))
    }

    /// Write the dynamic string table.
    ///
    /// Returns the file offset and size of the data.
    /// Returns `(0, 0)` without writing anything if the string table is empty and
    /// there is no dynamic symbol table.
    pub fn write_dynstr(&mut self) -> Result<(u64, u32)> {
        if !self.need_dynstr && self.dynstr.is_empty() {
            return Ok((0, 0));
        }
        debug_assert_eq!(self.dynstr_offset, 0);
        self.dynstr_str_id = Some(self.add_section_name(b".dynstr"));
        // Start with null section name.
        let mut data = vec![0];
        self.dynstr_size = self.dynstr.write(1, &mut data)?;
        self.dynstr_offset = self.offset();
        self.write(&data);
        Ok((self.dynstr_offset, self.dynstr_size))
    }

    /// Set the number of version definition entries that will be written.
    ///
    /// Must be called before [`Self::write_gnu_verdef`].
    pub fn set_gnu_verdef_count(&mut self, count: u16) {
        self.gnu_verdef_count = count;
        self.gnu_verdef_remaining = count;
    }

    /// Set the number of version needed entries that will be written.
    ///
    /// Must be called before [`Self::write_gnu_verneed`].
    pub fn set_gnu_verneed_count(&mut self, count: u16) {
        self.gnu_verneed_count = count;
        self.gnu_verneed_remaining = count;
    }
}

/// Two-phase writing mode for [`Writer`].
///
/// Construct a writer with this mode using [`Writer::new`].
///
/// File ranges and indices are reserved up front with the `reserve_*` methods,
/// then everything is written in the same order. This is the default mode.
///
/// The first phase uses the `reserve_*` methods to build up all of the information
/// that may need to be known ahead of time:
/// - string table offsets
/// - section indices
/// - symbol indices
/// - file ranges for headers and sections
///
/// Some of the information has ordering requirements. For example, strings must be added
/// to string tables before reserving the file range for the string table. Symbol indices
/// must be reserved after reserving the section indices they reference. There are debug
/// asserts to check some of these requirements.
///
/// The second phase writes everything out in order. Thus the caller must ensure writing
/// is in the same order that file ranges were reserved. There are debug asserts to assist
/// with checking this.
#[derive(Debug)]
pub struct TwoPhase {
    len: usize,
    shstrtab_data: Vec<u8>,
    strtab_data: Vec<u8>,
    dynstr_data: Vec<u8>,
}

impl Mode for TwoPhase {}
#[allow(private_interfaces)]
impl ModeSealed for TwoPhase {
    fn reserve(&self, buffer: &mut dyn WritableBuffer) -> Result<()> {
        buffer
            .reserve(self.len)
            .map_err(|_| Error(String::from("Cannot allocate buffer")))
    }

    fn need_offset(offset: u64) -> bool {
        offset != 0
    }

    fn set_offset(dest: &mut u64, offset: u64) {
        debug_assert_eq!(*dest, offset);
    }

    fn set_size(dest: &mut u64, size: u64) {
        debug_assert_eq!(*dest, size);
    }

    fn set_section_index(dest: &mut SectionIndex, index: SectionIndex) {
        debug_assert_eq!(*dest, index);
    }

    fn set_section_name(
        dest: &mut Option<StringId>,
        shstrtab: &mut StringTable<'_>,
        name: &'static [u8],
    ) {
        debug_assert_eq!(*dest, Some(shstrtab.get_id(name)));
    }

    fn set_count<T: Copy + PartialOrd>(dest: &mut T, count: T) {
        debug_assert!(*dest >= count);
    }
}

impl<'a> Writer<'a, TwoPhase> {
    /// Create a new two-phase `Writer` for the given endianness and ELF class.
    pub fn new(endian: Endianness, is_64: bool, buffer: &'a mut dyn WritableBuffer) -> Self {
        let mode = TwoPhase {
            len: 0,
            shstrtab_data: Vec::new(),
            strtab_data: Vec::new(),
            dynstr_data: Vec::new(),
        };
        Writer::new_with_mode(endian, is_64, buffer, mode)
    }

    /// Return the current file length that has been reserved.
    pub fn reserved_len(&self) -> usize {
        self.mode.len
    }

    /// Reserve a file range with the given size and starting alignment.
    ///
    /// Returns the aligned offset of the start of the range.
    ///
    /// `align_start` must be a power of two.
    pub fn reserve(&mut self, len: usize, align_start: usize) -> u64 {
        if align_start > 1 {
            self.mode.len = util::align(self.mode.len, align_start);
        }
        let offset = self.mode.len;
        self.mode.len += len;
        offset as u64
    }

    /// Reserve the file range up to the given file offset.
    pub fn reserve_until(&mut self, offset: usize) {
        debug_assert!(self.mode.len <= offset);
        self.mode.len = offset;
    }

    /// Reserve the range for the file header.
    ///
    /// This must be at the start of the file.
    pub fn reserve_file_header(&mut self) {
        debug_assert_eq!(self.mode.len, 0);
        self.reserve(self.class().file_header_size(), 1);
    }

    /// Reserve the range for the program headers.
    ///
    /// If `num` is >= `elf::PN_XNUM`, you must also reserve and write
    /// the section table; this is checked in `write_file_header`.
    ///
    /// Does nothing if `num` is zero.
    pub fn reserve_program_headers(&mut self, num: u32) {
        debug_assert_eq!(self.layout.segment_offset, 0);
        if num == 0 {
            return;
        }
        self.layout.segment_num = num;
        self.layout.segment_offset = self.reserve(
            num as usize * self.class().program_header_size(),
            self.elf_align,
        );
    }

    /// Reserve the section index for the null section header.
    ///
    /// The null section header is usually automatically reserved,
    /// but this can be used to force an empty section table.
    ///
    /// Must be called before [`Self::reserve_section_index`] and
    /// [`Self::reserve_section_headers`].
    pub fn reserve_null_section_index(&mut self) -> SectionIndex {
        debug_assert_eq!(self.layout.section_num, 0);
        if self.layout.section_num == 0 {
            self.layout.section_num = 1;
        }
        SectionIndex(0)
    }

    /// Reserve a section table index.
    ///
    /// Automatically also reserves the null section header if required.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_section_index(&mut self) -> SectionIndex {
        debug_assert_eq!(self.layout.section_offset, 0);
        if self.layout.section_num == 0 {
            self.layout.section_num = 1;
        }
        let index = self.layout.section_num;
        self.layout.section_num += 1;
        SectionIndex(index)
    }

    /// Reserve the range for the section headers.
    ///
    /// Does nothing if no sections were reserved.
    /// Must be called after [`Self::reserve_section_index`]
    /// and other functions that reserve section indices.
    pub fn reserve_section_headers(&mut self) {
        debug_assert_eq!(self.layout.section_offset, 0);
        if self.layout.section_num == 0 {
            return;
        }
        self.layout.section_offset = self.reserve(
            self.layout.section_num as usize * self.class().section_header_size(),
            self.elf_align,
        );
    }

    /// Reserve the range for the section header string table.
    ///
    /// This range is used for a section named `.shstrtab`.
    ///
    /// Does nothing if no sections were reserved.
    /// Must be called after [`Self::add_section_name`]
    /// and other functions that add section names and reserve indices.
    ///
    /// Returns an error if the string table could not be finalized.
    pub fn reserve_shstrtab(&mut self) -> Result<()> {
        debug_assert_eq!(self.shstrtab_offset, 0);
        if self.layout.section_num == 0 {
            return Ok(());
        }
        // Start with null section name.
        self.mode.shstrtab_data = vec![0];
        self.shstrtab_size = self.shstrtab.write(1, &mut self.mode.shstrtab_data)?;
        self.shstrtab_offset = self.reserve(self.shstrtab_size as usize, 1);
        Ok(())
    }

    /// Write the section header string table.
    ///
    /// Does nothing if the section was not reserved.
    pub fn write_shstrtab(&mut self) {
        if self.shstrtab_offset == 0 {
            return;
        }
        debug_assert_eq!(self.shstrtab_offset, self.offset());
        self.buffer.write_bytes(&self.mode.shstrtab_data);
    }

    /// Reserve the section index for the section header string table.
    ///
    /// Must be called before [`Self::reserve_shstrtab`]
    /// and [`Self::reserve_section_headers`].
    pub fn reserve_shstrtab_section_index(&mut self) -> SectionIndex {
        self.reserve_shstrtab_section_index_with_name(&b".shstrtab"[..])
    }

    /// Reserve the section index for the section header string table.
    ///
    /// Must be called before [`Self::reserve_shstrtab`]
    /// and [`Self::reserve_section_headers`].
    pub fn reserve_shstrtab_section_index_with_name(&mut self, name: &'a [u8]) -> SectionIndex {
        debug_assert_eq!(self.layout.shstrtab_index, SectionIndex(0));
        self.shstrtab_str_id = Some(self.add_section_name(name));
        self.layout.shstrtab_index = self.reserve_section_index();
        self.layout.shstrtab_index
    }

    /// Return true if `.strtab` is needed.
    pub fn strtab_needed(&self) -> bool {
        self.need_strtab || !self.strtab.is_empty()
    }

    /// Require the string table even if no strings were added.
    pub fn require_strtab(&mut self) {
        self.need_strtab = true;
    }

    /// Reserve the range for the string table.
    ///
    /// This range is used for a section named `.strtab`.
    ///
    /// The range is only reserved if the string table is needed (either `require_strtab`
    /// was called, or at least one string or symbol was added).
    /// Must be called after [`Self::add_string`].
    ///
    /// Returns an error if the string table could not be finalized.
    pub fn reserve_strtab(&mut self) -> Result<()> {
        debug_assert_eq!(self.strtab_offset, 0);
        if !self.strtab_needed() {
            return Ok(());
        }
        // Start with null string.
        self.mode.strtab_data = vec![0];
        self.strtab_size = self.strtab.write(1, &mut self.mode.strtab_data)?;
        self.strtab_offset = self.reserve(self.strtab_size as usize, 1);
        Ok(())
    }

    /// Write the string table.
    ///
    /// Does nothing if the section was not reserved.
    pub fn write_strtab(&mut self) {
        if self.strtab_offset == 0 {
            return;
        }
        debug_assert_eq!(self.strtab_offset, self.offset());
        self.buffer.write_bytes(&self.mode.strtab_data);
    }

    /// Reserve the section index for the string table.
    ///
    /// You should check [`Self::strtab_needed`] before calling this
    /// unless you have other means of knowing if this section is needed.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_strtab_section_index(&mut self) -> SectionIndex {
        self.reserve_strtab_section_index_with_name(&b".strtab"[..])
    }

    /// Reserve the section index for the string table.
    ///
    /// You should check [`Self::strtab_needed`] before calling this
    /// unless you have other means of knowing if this section is needed.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_strtab_section_index_with_name(&mut self, name: &'a [u8]) -> SectionIndex {
        debug_assert_eq!(self.strtab_index, SectionIndex(0));
        self.strtab_str_id = Some(self.add_section_name(name));
        self.strtab_index = self.reserve_section_index();
        self.strtab_index
    }

    /// Reserve the null symbol table entry.
    ///
    /// This will be stored in the `.symtab` section.
    ///
    /// The null symbol table entry is usually automatically reserved,
    /// but this can be used to force an empty symbol table.
    ///
    /// Must be called before [`Self::reserve_symbol_index`] and
    /// [`Self::reserve_symtab`].
    pub fn reserve_null_symbol_index(&mut self) -> SymbolIndex {
        debug_assert_eq!(self.symtab_offset, 0);
        debug_assert_eq!(self.symtab_num, 0);
        self.symtab_num = 1;
        // The symtab must link to a strtab.
        self.need_strtab = true;
        SymbolIndex(0)
    }

    /// Reserve a symbol table entry.
    ///
    /// This will be stored in the `.symtab` section.
    ///
    /// `section_index` is used to determine whether `.symtab_shndx` is required.
    ///
    /// Automatically also reserves the null symbol if required.
    /// Callers may assume that the returned indices will be sequential
    /// starting at 1.
    ///
    /// Must be called before [`Self::reserve_symtab`] and
    /// [`Self::reserve_symtab_shndx`].
    pub fn reserve_symbol_index(&mut self, section_index: Option<SectionIndex>) -> SymbolIndex {
        debug_assert_eq!(self.symtab_offset, 0);
        debug_assert_eq!(self.symtab_shndx_offset, 0);
        if self.symtab_num == 0 {
            self.symtab_num = 1;
            // The symtab must link to a strtab.
            self.need_strtab = true;
        }
        let index = self.symtab_num;
        self.symtab_num += 1;
        if let Some(section_index) = section_index {
            if section_index.0 >= elf::SHN_LORESERVE.into() {
                self.need_symtab_shndx = true;
            }
        }
        SymbolIndex(index)
    }

    /// Return the number of reserved symbol table entries.
    ///
    /// Includes the null symbol.
    pub fn symbol_count(&self) -> u32 {
        self.symtab_num
    }

    /// Reserve the range for the symbol table.
    ///
    /// This range is used for a section named `.symtab`.
    /// Does nothing if no symbols were reserved.
    /// Must be called after [`Self::reserve_symbol_index`].
    pub fn reserve_symtab(&mut self) {
        debug_assert_eq!(self.symtab_offset, 0);
        if self.symtab_num == 0 {
            return;
        }
        self.symtab_offset = self.reserve(
            self.symtab_num as usize * self.class().sym_size(),
            self.elf_align,
        );
    }

    /// Reserve the section index for the symbol table.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_symtab_section_index(&mut self) -> SectionIndex {
        self.reserve_symtab_section_index_with_name(&b".symtab"[..])
    }

    /// Reserve the section index for the symbol table.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_symtab_section_index_with_name(&mut self, name: &'a [u8]) -> SectionIndex {
        debug_assert_eq!(self.symtab_index, SectionIndex(0));
        self.symtab_str_id = Some(self.add_section_name(name));
        self.symtab_index = self.reserve_section_index();
        self.symtab_index
    }

    /// Return the section index of the symbol table.
    pub fn symtab_index(&mut self) -> SectionIndex {
        self.symtab_index
    }

    /// Return true if `.symtab_shndx` is needed.
    pub fn symtab_shndx_needed(&self) -> bool {
        self.need_symtab_shndx
    }

    /// Require the extended section indices for the symbol table even
    /// if no section indices are too large.
    pub fn require_symtab_shndx(&mut self) {
        self.need_symtab_shndx = true;
    }

    /// Reserve the range for the extended section indices for the symbol table.
    ///
    /// This range is used for a section named `.symtab_shndx`.
    /// This also reserves a section index.
    ///
    /// Does nothing if extended section indices are not needed.
    /// Must be called after [`Self::reserve_symbol_index`].
    pub fn reserve_symtab_shndx(&mut self) {
        debug_assert_eq!(self.symtab_shndx_offset, 0);
        if !self.symtab_shndx_needed() {
            return;
        }
        self.symtab_shndx_offset = self.reserve(self.symtab_num as usize * 4, ALIGN_SYMTAB_SHNDX);
        self.symtab_shndx_data.reserve(self.symtab_num as usize * 4);
    }

    /// Reserve the section index for the extended section indices symbol table.
    ///
    /// You should check [`Self::symtab_shndx_needed`] before calling this
    /// unless you have other means of knowing if this section is needed.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_symtab_shndx_section_index(&mut self) -> SectionIndex {
        self.reserve_symtab_shndx_section_index_with_name(&b".symtab_shndx"[..])
    }

    /// Reserve the section index for the extended section indices symbol table.
    ///
    /// You should check [`Self::symtab_shndx_needed`] before calling this
    /// unless you have other means of knowing if this section is needed.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_symtab_shndx_section_index_with_name(&mut self, name: &'a [u8]) -> SectionIndex {
        debug_assert!(self.symtab_shndx_str_id.is_none());
        self.symtab_shndx_str_id = Some(self.add_section_name(name));
        self.reserve_section_index()
    }

    /// Return true if `.dynstr` is needed.
    pub fn dynstr_needed(&self) -> bool {
        self.need_dynstr || !self.dynstr.is_empty()
    }

    /// Require the dynamic string table even if no strings were added.
    pub fn require_dynstr(&mut self) {
        self.need_dynstr = true;
    }

    /// Reserve the range for the dynamic string table.
    ///
    /// This range is used for a section named `.dynstr`.
    ///
    /// The range is only reserved if the string table is needed (either `require_dynstr`
    /// was called, or dynamic symbols or dynamic strings are present).
    /// Must be called after [`Self::add_dynamic_string`].
    ///
    /// Returns the file offset of the data.
    /// Returns 0 if the range was not reserved.
    /// Returns an error if the string table could not be finalized.
    pub fn reserve_dynstr(&mut self) -> Result<u64> {
        debug_assert_eq!(self.dynstr_offset, 0);
        if !self.dynstr_needed() {
            return Ok(0);
        }
        // Start with null string.
        self.mode.dynstr_data = vec![0];
        self.dynstr_size = self.dynstr.write(1, &mut self.mode.dynstr_data)?;
        self.dynstr_offset = self.reserve(self.dynstr_size as usize, 1);
        Ok(self.dynstr_offset)
    }

    /// Return the size of the dynamic string table.
    ///
    /// Must be called after [`Self::reserve_dynstr`].
    pub fn dynstr_len(&mut self) -> u32 {
        debug_assert_ne!(self.dynstr_offset, 0);
        self.dynstr_size
    }

    /// Write the dynamic string table.
    ///
    /// Does nothing if the section was not reserved.
    pub fn write_dynstr(&mut self) {
        if self.dynstr_offset == 0 {
            return;
        }
        debug_assert_eq!(self.dynstr_offset, self.offset());
        self.buffer.write_bytes(&self.mode.dynstr_data);
    }

    /// Reserve the section index for the dynamic string table.
    ///
    /// You should check [`Self::dynstr_needed`] before calling this
    /// unless you have other means of knowing if this section is needed.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_dynstr_section_index(&mut self) -> SectionIndex {
        self.reserve_dynstr_section_index_with_name(&b".dynstr"[..])
    }

    /// Reserve the section index for the dynamic string table.
    ///
    /// You should check [`Self::dynstr_needed`] before calling this
    /// unless you have other means of knowing if this section is needed.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_dynstr_section_index_with_name(&mut self, name: &'a [u8]) -> SectionIndex {
        debug_assert_eq!(self.dynstr_index, SectionIndex(0));
        self.dynstr_str_id = Some(self.add_section_name(name));
        self.dynstr_index = self.reserve_section_index();
        self.dynstr_index
    }

    /// Return the section index of the dynamic string table.
    pub fn dynstr_index(&mut self) -> SectionIndex {
        self.dynstr_index
    }

    /// Reserve the null dynamic symbol table entry.
    ///
    /// This will be stored in the `.dynsym` section.
    ///
    /// The null dynamic symbol table entry is usually automatically reserved,
    /// but this can be used to force an empty dynamic symbol table.
    ///
    /// Must be called before [`Self::reserve_dynamic_symbol_index`] and
    /// [`Self::reserve_dynsym`].
    pub fn reserve_null_dynamic_symbol_index(&mut self) -> SymbolIndex {
        debug_assert_eq!(self.dynsym_offset, 0);
        debug_assert_eq!(self.dynsym_num, 0);
        self.dynsym_num = 1;
        SymbolIndex(0)
    }

    /// Reserve a dynamic symbol table entry.
    ///
    /// This will be stored in the `.dynsym` section.
    ///
    /// Automatically also reserves the null symbol if required.
    /// Callers may assume that the returned indices will be sequential
    /// starting at 1.
    ///
    /// Must be called before [`Self::reserve_dynsym`].
    pub fn reserve_dynamic_symbol_index(&mut self) -> SymbolIndex {
        debug_assert_eq!(self.dynsym_offset, 0);
        if self.dynsym_num == 0 {
            self.dynsym_num = 1;
        }
        let index = self.dynsym_num;
        self.dynsym_num += 1;
        SymbolIndex(index)
    }

    /// Return the number of reserved dynamic symbols.
    ///
    /// Includes the null symbol.
    pub fn dynamic_symbol_count(&mut self) -> u32 {
        self.dynsym_num
    }

    /// Reserve the range for the dynamic symbol table.
    ///
    /// This range is used for a section named `.dynsym`.
    ///
    /// Must be called after [`Self::reserve_dynamic_symbol_index`].
    ///
    /// Returns the file offset of the symbol table.
    /// Returns 0 if no dynamic symbols were reserved.
    pub fn reserve_dynsym(&mut self) -> u64 {
        debug_assert_eq!(self.dynsym_offset, 0);
        if self.dynsym_num == 0 {
            return 0;
        }
        self.dynsym_offset = self.reserve(
            self.dynsym_num as usize * self.class().sym_size(),
            self.elf_align,
        );
        self.dynsym_offset
    }

    /// Reserve the section index for the dynamic symbol table.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_dynsym_section_index(&mut self) -> SectionIndex {
        self.reserve_dynsym_section_index_with_name(&b".dynsym"[..])
    }

    /// Reserve the section index for the dynamic symbol table.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_dynsym_section_index_with_name(&mut self, name: &'a [u8]) -> SectionIndex {
        debug_assert_eq!(self.dynsym_index, SectionIndex(0));
        self.dynsym_str_id = Some(self.add_section_name(name));
        self.dynsym_index = self.reserve_section_index();
        self.dynsym_index
    }

    /// Return the section index of the dynamic symbol table.
    pub fn dynsym_index(&mut self) -> SectionIndex {
        self.dynsym_index
    }

    /// Reserve the range for the `.dynamic` section.
    ///
    /// Returns the file offset of the reserved range.
    /// Returns 0 if `dynamic_num` is zero.
    pub fn reserve_dynamic(&mut self, dynamic_num: usize) -> u64 {
        debug_assert_eq!(self.dynamic_offset, 0);
        if dynamic_num == 0 {
            return 0;
        }
        self.dynamic_offset = self.reserve_dynamics(dynamic_num);
        self.dynamic_offset
    }

    /// Reserve a file range for the given number of dynamic entries.
    ///
    /// Returns the offset of the range.
    pub fn reserve_dynamics(&mut self, dynamic_num: usize) -> u64 {
        self.dynamic_num += dynamic_num;
        self.reserve(dynamic_num * self.class().dyn_size(), self.elf_align)
    }

    /// Reserve the section index for the dynamic table.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_dynamic_section_index(&mut self) -> SectionIndex {
        debug_assert!(self.dynamic_str_id.is_none());
        self.dynamic_str_id = Some(self.add_section_name(&b".dynamic"[..]));
        self.reserve_section_index()
    }

    /// Reserve a file range for a SysV hash section.
    ///
    /// `symbol_count` is the number of symbols in the hash,
    /// not the total number of symbols.
    pub fn reserve_hash(&mut self, bucket_count: u32, chain_count: u32) -> u64 {
        let size = self.class().hash_size(bucket_count, chain_count);
        self.hash_offset = self.reserve(size, ALIGN_HASH);
        self.hash_size = size as u64;
        self.hash_offset
    }

    /// Reserve the section index for the SysV hash table.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_hash_section_index(&mut self) -> SectionIndex {
        self.reserve_hash_section_index_with_name(&b".hash"[..])
    }

    /// Reserve the section index for the SysV hash table.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_hash_section_index_with_name(&mut self, name: &'a [u8]) -> SectionIndex {
        debug_assert!(self.hash_str_id.is_none());
        self.hash_str_id = Some(self.add_section_name(name));
        self.reserve_section_index()
    }

    /// Reserve a file range for a GNU hash section.
    ///
    /// `symbol_count` is the number of symbols in the hash,
    /// not the total number of symbols.
    pub fn reserve_gnu_hash(
        &mut self,
        bloom_count: u32,
        bucket_count: u32,
        symbol_count: u32,
    ) -> u64 {
        let size = self
            .class()
            .gnu_hash_size(bloom_count, bucket_count, symbol_count);
        self.gnu_hash_offset = self.reserve(size, self.elf_align);
        self.gnu_hash_size = size as u64;
        self.gnu_hash_offset
    }

    /// Reserve the section index for the GNU hash table.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_gnu_hash_section_index(&mut self) -> SectionIndex {
        self.reserve_gnu_hash_section_index_with_name(&b".gnu.hash"[..])
    }

    /// Reserve the section index for the GNU hash table.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_gnu_hash_section_index_with_name(&mut self, name: &'a [u8]) -> SectionIndex {
        debug_assert!(self.gnu_hash_str_id.is_none());
        self.gnu_hash_str_id = Some(self.add_section_name(name));
        self.reserve_section_index()
    }

    /// Reserve the range for the `.gnu.version` section.
    ///
    /// Returns the file offset of the reserved range.
    /// Returns 0 if no dynamic symbols were reserved.
    pub fn reserve_gnu_versym(&mut self) -> u64 {
        debug_assert_eq!(self.gnu_versym_offset, 0);
        if self.dynsym_num == 0 {
            return 0;
        }
        self.gnu_versym_offset = self.reserve(self.dynsym_num as usize * 2, ALIGN_GNU_VERSYM);
        self.gnu_versym_offset
    }

    /// Reserve the section index for the `.gnu.version` section.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_gnu_versym_section_index(&mut self) -> SectionIndex {
        self.reserve_gnu_versym_section_index_with_name(&b".gnu.version"[..])
    }

    /// Reserve the section index for the `.gnu.version` section.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_gnu_versym_section_index_with_name(&mut self, name: &'a [u8]) -> SectionIndex {
        debug_assert!(self.gnu_versym_str_id.is_none());
        self.gnu_versym_str_id = Some(self.add_section_name(name));
        self.reserve_section_index()
    }

    /// Reserve the range for the `.gnu.version_d` section.
    ///
    /// Returns the file offset of the reserved range.
    /// Returns 0 if `verdef_count` is zero.
    pub fn reserve_gnu_verdef(&mut self, verdef_count: usize, verdaux_count: usize) -> u64 {
        debug_assert_eq!(self.gnu_verdef_offset, 0);
        if verdef_count == 0 {
            return 0;
        }
        let size = self.class().gnu_verdef_size(verdef_count, verdaux_count);
        self.gnu_verdef_offset = self.reserve(size, ALIGN_GNU_VERDEF);
        self.gnu_verdef_count = verdef_count as u16;
        self.gnu_verdaux_count = verdaux_count;
        self.gnu_verdef_remaining = self.gnu_verdef_count;
        self.gnu_verdef_offset
    }

    /// Reserve the section index for the `.gnu.version_d` section.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_gnu_verdef_section_index(&mut self) -> SectionIndex {
        self.reserve_gnu_verdef_section_index_with_name(&b".gnu.version_d"[..])
    }

    /// Reserve the section index for the `.gnu.version_d` section.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_gnu_verdef_section_index_with_name(&mut self, name: &'a [u8]) -> SectionIndex {
        debug_assert!(self.gnu_verdef_str_id.is_none());
        self.gnu_verdef_str_id = Some(self.add_section_name(name));
        self.reserve_section_index()
    }

    /// Reserve the range for the `.gnu.version_r` section.
    ///
    /// Returns the file offset of the reserved range.
    /// Returns 0 if `verneed_count` is zero.
    pub fn reserve_gnu_verneed(&mut self, verneed_count: usize, vernaux_count: usize) -> u64 {
        debug_assert_eq!(self.gnu_verneed_offset, 0);
        if verneed_count == 0 {
            return 0;
        }
        let size = self.class().gnu_verneed_size(verneed_count, vernaux_count);
        self.gnu_verneed_offset = self.reserve(size, ALIGN_GNU_VERNEED);
        self.gnu_verneed_count = verneed_count as u16;
        self.gnu_vernaux_count = vernaux_count;
        self.gnu_verneed_remaining = self.gnu_verneed_count;
        self.gnu_verneed_offset
    }

    /// Reserve the section index for the `.gnu.version_r` section.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_gnu_verneed_section_index(&mut self) -> SectionIndex {
        self.reserve_gnu_verneed_section_index_with_name(&b".gnu.version_r"[..])
    }

    /// Reserve the section index for the `.gnu.version_r` section.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_gnu_verneed_section_index_with_name(&mut self, name: &'a [u8]) -> SectionIndex {
        debug_assert!(self.gnu_verneed_str_id.is_none());
        self.gnu_verneed_str_id = Some(self.add_section_name(name));
        self.reserve_section_index()
    }

    /// Reserve the section index for the `.gnu.attributes` section.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_gnu_attributes_section_index(&mut self) -> SectionIndex {
        self.reserve_gnu_attributes_section_index_with_name(&b".gnu.attributes"[..])
    }

    /// Reserve the section index for the `.gnu.attributes` section.
    ///
    /// Must be called before [`Self::reserve_section_headers`].
    pub fn reserve_gnu_attributes_section_index_with_name(
        &mut self,
        name: &'a [u8],
    ) -> SectionIndex {
        debug_assert!(self.gnu_attributes_str_id.is_none());
        self.gnu_attributes_str_id = Some(self.add_section_name(name));
        self.reserve_section_index()
    }

    /// Reserve the range for the `.gnu.attributes` section.
    ///
    /// Returns the file offset of the reserved range.
    /// Returns 0 if `gnu_attributes_size` is zero.
    pub fn reserve_gnu_attributes(&mut self, gnu_attributes_size: usize) -> u64 {
        debug_assert_eq!(self.gnu_attributes_offset, 0);
        if gnu_attributes_size == 0 {
            return 0;
        }
        self.gnu_attributes_size = gnu_attributes_size as u64;
        self.gnu_attributes_offset = self.reserve(gnu_attributes_size, self.elf_align);
        self.gnu_attributes_offset
    }

    /// Reserve a file range for the given number of relocations.
    ///
    /// Returns the offset of the range.
    pub fn reserve_relocations(&mut self, count: usize, is_rela: bool) -> u64 {
        self.reserve(count * self.class().rel_size(is_rela), self.elf_align)
    }

    /// Reserve a file range for a COMDAT section.
    ///
    /// `count` is the number of sections in the COMDAT group.
    ///
    /// Returns the offset of the range.
    pub fn reserve_comdat(&mut self, count: usize) -> u64 {
        self.reserve((count + 1) * 4, 4)
    }
}

/// A helper for writing an attributes section.
///
/// Attributes have a variable length encoding, so it is awkward to write them in a
/// single pass. Instead, we build the entire attributes section data in memory, using
/// placeholders for unknown lengths that are filled in later.
#[allow(missing_debug_implementations)]
pub struct AttributesWriter {
    endian: Endianness,
    data: Vec<u8>,
    subsection_offset: usize,
    subsubsection_offset: usize,
}

impl AttributesWriter {
    /// Create a new `AttributesWriter` for the given endianness.
    pub fn new(endian: Endianness) -> Self {
        AttributesWriter {
            endian,
            data: vec![0x41],
            subsection_offset: 0,
            subsubsection_offset: 0,
        }
    }

    /// Start a new subsection with the given vendor name.
    pub fn start_subsection(&mut self, vendor: &[u8]) {
        debug_assert_eq!(self.subsection_offset, 0);
        debug_assert_eq!(self.subsubsection_offset, 0);
        self.subsection_offset = self.data.len();
        self.data.extend_from_slice(&[0; 4]);
        self.data.extend_from_slice(vendor);
        self.data.push(0);
    }

    /// End the subsection.
    ///
    /// The subsection length is automatically calculated and written.
    pub fn end_subsection(&mut self) {
        debug_assert_ne!(self.subsection_offset, 0);
        debug_assert_eq!(self.subsubsection_offset, 0);
        let length = self.data.len() - self.subsection_offset;
        self.data[self.subsection_offset..][..4]
            .copy_from_slice(pod::bytes_of(&U32::new(self.endian, length as u32)));
        self.subsection_offset = 0;
    }

    /// Start a new sub-subsection with the given tag.
    pub fn start_subsubsection(&mut self, tag: elf::AttributeTag) {
        debug_assert_ne!(self.subsection_offset, 0);
        debug_assert_eq!(self.subsubsection_offset, 0);
        self.subsubsection_offset = self.data.len();
        self.data.push(tag.0);
        self.data.extend_from_slice(&[0; 4]);
    }

    /// Write a section or symbol index to the sub-subsection.
    ///
    /// The user must also call this function to write the terminating 0 index.
    pub fn write_subsubsection_index(&mut self, index: u32) {
        debug_assert_ne!(self.subsection_offset, 0);
        debug_assert_ne!(self.subsubsection_offset, 0);
        util::write_uleb128(&mut self.data, u64::from(index));
    }

    /// Write raw index data to the sub-subsection.
    ///
    /// The terminating 0 index is automatically written.
    pub fn write_subsubsection_indices(&mut self, indices: &[u8]) {
        debug_assert_ne!(self.subsection_offset, 0);
        debug_assert_ne!(self.subsubsection_offset, 0);
        self.data.extend_from_slice(indices);
        self.data.push(0);
    }

    /// Write an attribute tag to the sub-subsection.
    pub fn write_attribute_tag(&mut self, tag: u64) {
        debug_assert_ne!(self.subsection_offset, 0);
        debug_assert_ne!(self.subsubsection_offset, 0);
        util::write_uleb128(&mut self.data, tag);
    }

    /// Write an attribute integer value to the sub-subsection.
    pub fn write_attribute_integer(&mut self, value: u64) {
        debug_assert_ne!(self.subsection_offset, 0);
        debug_assert_ne!(self.subsubsection_offset, 0);
        util::write_uleb128(&mut self.data, value);
    }

    /// Write an attribute string value to the sub-subsection.
    ///
    /// The value must not include the null terminator.
    pub fn write_attribute_string(&mut self, value: &[u8]) {
        debug_assert_ne!(self.subsection_offset, 0);
        debug_assert_ne!(self.subsubsection_offset, 0);
        self.data.extend_from_slice(value);
        self.data.push(0);
    }

    /// Write raw attribute data to the sub-subsection.
    pub fn write_subsubsection_attributes(&mut self, attributes: &[u8]) {
        debug_assert_ne!(self.subsection_offset, 0);
        debug_assert_ne!(self.subsubsection_offset, 0);
        self.data.extend_from_slice(attributes);
    }

    /// End the sub-subsection.
    ///
    /// The sub-subsection length is automatically calculated and written.
    pub fn end_subsubsection(&mut self) {
        debug_assert_ne!(self.subsection_offset, 0);
        debug_assert_ne!(self.subsubsection_offset, 0);
        let length = self.data.len() - self.subsubsection_offset;
        self.data[self.subsubsection_offset + 1..][..4]
            .copy_from_slice(pod::bytes_of(&U32::new(self.endian, length as u32)));
        self.subsubsection_offset = 0;
    }

    /// Return the completed section data.
    pub fn data(self) -> Vec<u8> {
        debug_assert_eq!(self.subsection_offset, 0);
        debug_assert_eq!(self.subsubsection_offset, 0);
        self.data
    }
}

/// An ELF file class.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Class {
    /// Whether the file is 64-bit.
    pub is_64: bool,
}

impl Class {
    /// Return the alignment size.
    pub fn align(self) -> usize {
        if self.is_64 { 8 } else { 4 }
    }

    /// Return the size of the file header.
    pub fn file_header_size(self) -> usize {
        if self.is_64 {
            mem::size_of::<elf::FileHeader64<Endianness>>()
        } else {
            mem::size_of::<elf::FileHeader32<Endianness>>()
        }
    }

    /// Return the size of a program header.
    pub fn program_header_size(self) -> usize {
        if self.is_64 {
            mem::size_of::<elf::ProgramHeader64<Endianness>>()
        } else {
            mem::size_of::<elf::ProgramHeader32<Endianness>>()
        }
    }

    /// Return the size of a section header.
    pub fn section_header_size(self) -> usize {
        if self.is_64 {
            mem::size_of::<elf::SectionHeader64<Endianness>>()
        } else {
            mem::size_of::<elf::SectionHeader32<Endianness>>()
        }
    }

    /// Return the size of a symbol.
    pub fn sym_size(self) -> usize {
        if self.is_64 {
            mem::size_of::<elf::Sym64<Endianness>>()
        } else {
            mem::size_of::<elf::Sym32<Endianness>>()
        }
    }

    /// Return the size of a relocation entry.
    pub fn rel_size(self, is_rela: bool) -> usize {
        if self.is_64 {
            if is_rela {
                mem::size_of::<elf::Rela64<Endianness>>()
            } else {
                mem::size_of::<elf::Rel64<Endianness>>()
            }
        } else {
            if is_rela {
                mem::size_of::<elf::Rela32<Endianness>>()
            } else {
                mem::size_of::<elf::Rel32<Endianness>>()
            }
        }
    }

    /// Return the size of a relative relocation entry.
    pub fn relr_size(self) -> usize {
        if self.is_64 {
            mem::size_of::<elf::Relr64<Endianness>>()
        } else {
            mem::size_of::<elf::Relr32<Endianness>>()
        }
    }

    /// Return the size of a dynamic entry.
    pub fn dyn_size(self) -> usize {
        if self.is_64 {
            mem::size_of::<elf::Dyn64<Endianness>>()
        } else {
            mem::size_of::<elf::Dyn32<Endianness>>()
        }
    }

    /// Return the size of a hash table.
    pub fn hash_size(self, bucket_count: u32, chain_count: u32) -> usize {
        mem::size_of::<elf::HashHeader<Endianness>>()
            + bucket_count as usize * 4
            + chain_count as usize * 4
    }

    /// Return the size of a GNU hash table.
    pub fn gnu_hash_size(self, bloom_count: u32, bucket_count: u32, symbol_count: u32) -> usize {
        let bloom_size = if self.is_64 { 8 } else { 4 };
        mem::size_of::<elf::GnuHashHeader<Endianness>>()
            + bloom_count as usize * bloom_size
            + bucket_count as usize * 4
            + symbol_count as usize * 4
    }

    /// Return the size of a GNU symbol version section.
    pub fn gnu_versym_size(self, symbol_count: usize) -> usize {
        symbol_count * 2
    }

    /// Return the size of a GNU version definition section.
    pub fn gnu_verdef_size(self, verdef_count: usize, verdaux_count: usize) -> usize {
        verdef_count * mem::size_of::<elf::Verdef<Endianness>>()
            + verdaux_count * mem::size_of::<elf::Verdaux<Endianness>>()
    }

    /// Return the size of a GNU version dependency section.
    pub fn gnu_verneed_size(self, verneed_count: usize, vernaux_count: usize) -> usize {
        verneed_count * mem::size_of::<elf::Verneed<Endianness>>()
            + vernaux_count * mem::size_of::<elf::Vernaux<Endianness>>()
    }
}

/// Native endian version of [`elf::FileHeader64`].
#[allow(missing_docs)]
#[derive(Debug, Clone, Default)]
pub struct FileHeader {
    pub os_abi: elf::OsAbi,
    pub abi_version: u8,
    pub e_type: elf::FileType,
    pub e_machine: elf::Machine,
    pub e_entry: u64,
    pub e_flags: elf::FileFlags,
}

#[derive(Debug, Clone, Default)]
struct FileHeaderLayout {
    segment_offset: u64,
    segment_num: u32,
    section_offset: u64,
    section_num: u32,
    shstrtab_index: SectionIndex,
}

/// Native endian version of [`elf::ProgramHeader64`].
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct ProgramHeader {
    pub p_type: elf::ProgramType,
    pub p_flags: elf::ProgramFlags,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

/// Native endian version of [`elf::SectionHeader64`].
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub name: Option<StringId>,
    pub sh_type: elf::SectionType,
    pub sh_flags: elf::SectionFlags,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

/// Native endian version of [`elf::Sym64`].
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct Sym {
    pub name: Option<StringId>,
    pub section: Option<SectionIndex>,
    pub st_info: elf::SymbolInfo,
    pub st_other: elf::SymbolOther,
    pub st_shndx: elf::SymbolSection,
    pub st_value: u64,
    pub st_size: u64,
}

/// Unified native endian version of [`elf::Rel64`] and [`elf::Rela64`].
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct Rel {
    pub r_offset: u64,
    pub r_sym: u32,
    pub r_type: u32,
    pub r_addend: i64,
}

/// Information required for writing [`elf::Verdef`].
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct Verdef {
    pub version: u16,
    pub flags: elf::VersionFlags,
    pub index: elf::VersionIndex,
    pub aux_count: u16,
    /// The name for the first [`elf::Verdaux`] entry.
    pub name: StringId,
}

/// Information required for writing [`elf::Verneed`].
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct Verneed {
    pub version: u16,
    pub aux_count: u16,
    pub file: StringId,
}

/// Information required for writing [`elf::Vernaux`].
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct Vernaux {
    pub flags: elf::VersionFlags,
    pub index: elf::VersionIndex,
    pub name: StringId,
}
