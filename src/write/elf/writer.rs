//! Helper for writing ELF files.
use std::mem;
use std::string::String;
use std::vec::Vec;

use crate::elf;
use crate::endian::*;
use crate::write::string::{StringId, StringTable};
use crate::write::util;
use crate::write::{Error, Result, WritableBuffer};

/// The index of an ELF section.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SectionIndex(pub u32);

/// The index of an ELF symbol.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolIndex(pub u32);

/// A helper for writing ELF files.
///
/// Writing uses a two phase approach. The first phase builds up all of the information
/// that may need to be known ahead of time:
/// - build string tables
/// - reserve section indices
/// - reserve symbol indices
/// - reserve file ranges for headers and sections
///
/// Some of the information has ordering requirements. For example, strings must be added
/// to string tables before reserving the file range for the string table. Symbol indices
/// must be reserved after reserving the section indices they reference. There are debug
/// asserts to check some of these requirements.
///
/// The second phase writes everything out in order. Thus the caller must ensure writing
/// is in the same order that file ranges were reserved. There are debug asserts to assist
/// with checking this.
#[allow(missing_debug_implementations)]
pub struct Writer<'a> {
    endian: Endianness,
    is_64: bool,
    is_mips64el: bool,
    elf_align: usize,

    buffer: &'a mut dyn WritableBuffer,
    len: usize,

    segment_offset: usize,
    segment_num: u32,

    section_offset: usize,
    section_num: u32,

    shstrtab: StringTable<'a>,
    shstrtab_str_id: Option<StringId>,
    shstrtab_index: SectionIndex,
    shstrtab_offset: usize,
    shstrtab_data: Vec<u8>,

    need_strtab: bool,
    strtab: StringTable<'a>,
    strtab_str_id: Option<StringId>,
    strtab_index: SectionIndex,
    strtab_offset: usize,
    strtab_data: Vec<u8>,

    symtab_str_id: Option<StringId>,
    symtab_index: SectionIndex,
    symtab_offset: usize,
    symtab_num: u32,

    need_symtab_shndx: bool,
    symtab_shndx_str_id: Option<StringId>,
    symtab_shndx_offset: usize,
    symtab_shndx_data: Vec<u8>,

    need_dynstr: bool,
    dynstr: StringTable<'a>,
    dynstr_str_id: Option<StringId>,
    dynstr_index: SectionIndex,
    dynstr_offset: usize,
    dynstr_data: Vec<u8>,

    dynsym_str_id: Option<StringId>,
    dynsym_index: SectionIndex,
    dynsym_offset: usize,
    dynsym_num: u32,

    dynamic_str_id: Option<StringId>,
    dynamic_offset: usize,
    dynamic_num: usize,
}

impl<'a> Writer<'a> {
    /// Create a new `Writer` for the given endianness and ELF class.
    pub fn new(endian: Endianness, is_64: bool, buffer: &'a mut dyn WritableBuffer) -> Self {
        let elf_align = if is_64 { 8 } else { 4 };
        Writer {
            endian,
            is_64,
            // Determined later.
            is_mips64el: false,
            elf_align,

            buffer,
            len: 0,

            segment_offset: 0,
            segment_num: 0,

            section_offset: 0,
            section_num: 0,

            shstrtab: StringTable::default(),
            shstrtab_str_id: None,
            shstrtab_index: SectionIndex(0),
            shstrtab_offset: 0,
            shstrtab_data: Vec::new(),

            need_strtab: false,
            strtab: StringTable::default(),
            strtab_str_id: None,
            strtab_index: SectionIndex(0),
            strtab_offset: 0,
            strtab_data: Vec::new(),

            symtab_str_id: None,
            symtab_index: SectionIndex(0),
            symtab_offset: 0,
            symtab_num: 0,

            need_symtab_shndx: false,
            symtab_shndx_str_id: None,
            symtab_shndx_offset: 0,
            symtab_shndx_data: Vec::new(),

            need_dynstr: false,
            dynstr: StringTable::default(),
            dynstr_str_id: None,
            dynstr_index: SectionIndex(0),
            dynstr_offset: 0,
            dynstr_data: Vec::new(),

            dynsym_str_id: None,
            dynsym_index: SectionIndex(0),
            dynsym_offset: 0,
            dynsym_num: 0,

            dynamic_str_id: None,
            dynamic_offset: 0,
            dynamic_num: 0,
        }
    }

    /// Return the current file length that has been reserved.
    pub fn reserved_len(&self) -> usize {
        self.len
    }

    /// Return the current file length that has been written.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Reserve a file range with the given size and starting alignment.
    ///
    /// Returns the aligned offset of the start of the range.
    pub fn reserve(&mut self, len: usize, align_start: usize) -> usize {
        if len == 0 {
            return self.len;
        }
        self.len = util::align(self.len, align_start);
        let offset = self.len;
        self.len += len;
        offset
    }

    /// Write alignment padding bytes.
    pub fn write_align(&mut self, align_start: usize) {
        util::write_align(self.buffer, align_start);
    }

    /// Write data.
    ///
    /// This is typically used to write section data.
    pub fn write(&mut self, data: &[u8]) {
        self.buffer.write_bytes(data);
    }

    /// Reserve the file range up to the given file offset.
    pub fn reserve_until(&mut self, offset: usize) {
        debug_assert!(self.len <= offset);
        self.len = offset;
    }

    /// Write padding up to the given file offset.
    pub fn pad_until(&mut self, offset: usize) {
        debug_assert!(self.buffer.len() <= offset);
        self.buffer.resize(offset, 0);
    }

    fn file_header_size(&self) -> usize {
        if self.is_64 {
            mem::size_of::<elf::FileHeader64<Endianness>>()
        } else {
            mem::size_of::<elf::FileHeader32<Endianness>>()
        }
    }

    /// Reserve the range for the file header.
    ///
    /// This must be at the start of the file.
    pub fn reserve_file_header(&mut self) {
        debug_assert_eq!(self.len, 0);
        self.reserve(self.file_header_size(), 1);
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

        // Start writing.
        self.buffer
            .reserve(self.len)
            .map_err(|_| Error(String::from("Cannot allocate buffer")))?;

        // Write file header.
        let e_ident = elf::Ident {
            magic: elf::ELFMAG,
            class: if self.is_64 {
                elf::ELFCLASS64
            } else {
                elf::ELFCLASS32
            },
            data: if self.endian.is_little_endian() {
                elf::ELFDATA2LSB
            } else {
                elf::ELFDATA2MSB
            },
            version: elf::EV_CURRENT,
            os_abi: header.os_abi,
            abi_version: header.abi_version,
            padding: [0; 7],
        };

        let e_ehsize = self.file_header_size() as u16;

        let e_phoff = self.segment_offset as u64;
        let e_phentsize = if self.segment_num == 0 {
            0
        } else {
            self.program_header_size() as u16
        };
        // TODO: overflow
        let e_phnum = self.segment_num as u16;

        let e_shoff = self.section_offset as u64;
        let e_shentsize = if self.section_num == 0 {
            0
        } else {
            self.section_header_size() as u16
        };
        let e_shnum = if self.section_num >= elf::SHN_LORESERVE.into() {
            0
        } else {
            self.section_num as u16
        };
        let e_shstrndx = if self.shstrtab_index.0 >= elf::SHN_LORESERVE.into() {
            elf::SHN_XINDEX
        } else {
            self.shstrtab_index.0 as u16
        };

        let endian = self.endian;
        if self.is_64 {
            let file = elf::FileHeader64 {
                e_ident,
                e_type: U16::new(endian, header.e_type),
                e_machine: U16::new(endian, header.e_machine),
                e_version: U32::new(endian, elf::EV_CURRENT.into()),
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
            self.buffer.write(&file)
        } else {
            let file = elf::FileHeader32 {
                e_ident,
                e_type: U16::new(endian, header.e_type),
                e_machine: U16::new(endian, header.e_machine),
                e_version: U32::new(endian, elf::EV_CURRENT.into()),
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
            self.buffer.write(&file);
        }

        Ok(())
    }

    fn program_header_size(&self) -> usize {
        if self.is_64 {
            mem::size_of::<elf::ProgramHeader64<Endianness>>()
        } else {
            mem::size_of::<elf::ProgramHeader32<Endianness>>()
        }
    }

    /// Reserve the range for the program headers.
    pub fn reserve_program_headers(&mut self, num: u32) {
        debug_assert_eq!(self.segment_offset, 0);
        if num == 0 {
            return;
        }
        self.segment_num = num;
        self.segment_offset =
            self.reserve(num as usize * self.program_header_size(), self.elf_align);
    }

    /// Write alignment padding bytes prior to the program headers.
    pub fn write_align_program_headers(&mut self) {
        if self.segment_offset == 0 {
            return;
        }
        util::write_align(self.buffer, self.elf_align);
        debug_assert_eq!(self.segment_offset, self.buffer.len());
    }

    /// Write a program header.
    pub fn write_program_header(&mut self, header: &ProgramHeader) {
        let endian = self.endian;
        if self.is_64 {
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
            self.buffer.write(&header);
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
            self.buffer.write(&header);
        }
    }

    /// Reserve the section index for the null section header.
    ///
    /// The null section header is usually automatically reserved,
    /// but this can be used to force an empty section table.
    ///
    /// This must be called before [`Self::reserve_section_headers`].
    pub fn reserve_null_section_index(&mut self) -> SectionIndex {
        debug_assert_eq!(self.section_num, 0);
        if self.section_num == 0 {
            self.section_num = 1;
        }
        SectionIndex(0)
    }

    /// Reserve a section table index.
    ///
    /// Automatically also reserves the null section header if required.
    ///
    /// This must be called before [`Self::reserve_section_headers`].
    pub fn reserve_section_index(&mut self) -> SectionIndex {
        debug_assert_eq!(self.section_offset, 0);
        if self.section_num == 0 {
            self.section_num = 1;
        }
        let index = self.section_num;
        self.section_num += 1;
        SectionIndex(index)
    }

    fn section_header_size(&self) -> usize {
        if self.is_64 {
            mem::size_of::<elf::SectionHeader64<Endianness>>()
        } else {
            mem::size_of::<elf::SectionHeader32<Endianness>>()
        }
    }

    /// Reserve the range for the section headers.
    ///
    /// This function does nothing if no sections were reserved.
    /// This must be called after [`Self::reserve_section_index`]
    /// and other functions that reserve section indices.
    pub fn reserve_section_headers(&mut self) {
        debug_assert_eq!(self.section_offset, 0);
        if self.section_num == 0 {
            return;
        }
        self.section_offset = self.reserve(
            self.section_num as usize * self.section_header_size(),
            self.elf_align,
        );
    }

    /// Write the null section header.
    ///
    /// This must be the first section header that is written.
    /// This function does nothing if no sections were reserved.
    pub fn write_null_section_header(&mut self) {
        if self.section_num == 0 {
            return;
        }
        util::write_align(self.buffer, self.elf_align);
        debug_assert_eq!(self.section_offset, self.buffer.len());
        self.write_section_header(&SectionHeader {
            name: None,
            sh_type: 0,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: 0,
            sh_size: if self.section_num >= elf::SHN_LORESERVE.into() {
                self.section_num.into()
            } else {
                0
            },
            sh_link: if self.shstrtab_index.0 >= elf::SHN_LORESERVE.into() {
                self.shstrtab_index.0
            } else {
                0
            },
            // TODO: e_phnum overflow
            sh_info: 0,
            sh_addralign: 0,
            sh_entsize: 0,
        });
    }

    /// Write a section header.
    pub fn write_section_header(&mut self, section: &SectionHeader) {
        let sh_name = if let Some(name) = section.name {
            self.shstrtab.get_offset(name) as u32
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
                sh_flags: U32::new(endian, section.sh_flags as u32),
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
    }

    /// Add a section name to the section header string table.
    ///
    /// This will be stored in the `.shstrtab` section.
    ///
    /// This must be called before [`Self::reserve_shstrtab`].
    pub fn add_section_name(&mut self, name: &'a [u8]) -> StringId {
        debug_assert_eq!(self.shstrtab_offset, 0);
        self.shstrtab.add(name)
    }

    /// Reserve the range for the section header string table.
    ///
    /// This range is used for a section named `.shstrtab`.
    ///
    /// This function does nothing if no sections were reserved.
    /// This must be called after [`Self::add_section_name`].
    /// and other functions that reserve section names and indices.
    pub fn reserve_shstrtab(&mut self) {
        debug_assert_eq!(self.shstrtab_offset, 0);
        if self.section_num == 0 {
            return;
        }
        // Start with null section name.
        self.shstrtab_data = vec![0];
        self.shstrtab.write(1, &mut self.shstrtab_data);
        self.shstrtab_offset = self.reserve(self.shstrtab_data.len(), 1);
    }

    /// Write the section header string table.
    ///
    /// This function does nothing if the section was not reserved.
    pub fn write_shstrtab(&mut self) {
        if self.shstrtab_offset == 0 {
            return;
        }
        debug_assert_eq!(self.shstrtab_offset, self.buffer.len());
        self.buffer.write_bytes(&self.shstrtab_data);
    }

    /// Reserve the section index for the section header string table.
    ///
    /// This must be called before [`Self::reserve_shstrtab`]
    /// and [`Self::reserve_section_headers`].
    pub fn reserve_shstrtab_section_index(&mut self) -> SectionIndex {
        debug_assert_eq!(self.shstrtab_index, SectionIndex(0));
        self.shstrtab_str_id = Some(self.add_section_name(&b".shstrtab"[..]));
        self.shstrtab_index = self.reserve_section_index();
        self.shstrtab_index
    }

    /// Write the section header for the section header string table.
    ///
    /// This function does nothing if the section index was not reserved.
    pub fn write_shstrtab_section_header(&mut self) {
        if self.shstrtab_index == SectionIndex(0) {
            return;
        }
        self.write_section_header(&SectionHeader {
            name: self.shstrtab_str_id,
            sh_type: elf::SHT_STRTAB,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: self.shstrtab_offset as u64,
            sh_size: self.shstrtab_data.len() as u64,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 0,
        });
    }

    /// Add a string to the string table.
    ///
    /// This will be stored in the `.strtab` section.
    ///
    /// This must be called before [`Self::reserve_strtab`].
    pub fn add_string(&mut self, name: &'a [u8]) -> StringId {
        debug_assert_eq!(self.strtab_offset, 0);
        self.need_strtab = true;
        self.strtab.add(name)
    }

    /// Return true if `.strtab` is needed.
    pub fn strtab_needed(&self) -> bool {
        self.need_strtab
    }

    /// Reserve the range for the string table.
    ///
    /// This range is used for a section named `.strtab`.
    ///
    /// This function does nothing if no strings or symbols were defined.
    /// This must be called after [`Self::add_string`].
    pub fn reserve_strtab(&mut self) {
        debug_assert_eq!(self.strtab_offset, 0);
        if !self.need_strtab {
            return;
        }
        // Start with null string.
        self.strtab_data = vec![0];
        self.strtab.write(1, &mut self.strtab_data);
        self.strtab_offset = self.reserve(self.strtab_data.len(), 1);
    }

    /// Write the string table.
    ///
    /// This function does nothing if the section was not reserved.
    pub fn write_strtab(&mut self) {
        if self.strtab_offset == 0 {
            return;
        }
        debug_assert_eq!(self.strtab_offset, self.buffer.len());
        self.buffer.write_bytes(&self.strtab_data);
    }

    /// Reserve the section index for the string table.
    ///
    /// This must be called before [`Self::reserve_section_headers`].
    pub fn reserve_strtab_section_index(&mut self) -> SectionIndex {
        debug_assert_eq!(self.strtab_index, SectionIndex(0));
        self.strtab_str_id = Some(self.add_section_name(&b".strtab"[..]));
        self.strtab_index = self.reserve_section_index();
        self.strtab_index
    }

    /// Write the section header for the string table.
    ///
    /// This function does nothing if the section index was not reserved.
    pub fn write_strtab_section_header(&mut self) {
        if self.strtab_index == SectionIndex(0) {
            return;
        }
        self.write_section_header(&SectionHeader {
            name: self.strtab_str_id,
            sh_type: elf::SHT_STRTAB,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: self.strtab_offset as u64,
            sh_size: self.strtab_data.len() as u64,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 0,
        });
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
    /// This must be called before [`Self::reserve_symtab`] and
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

    fn symbol_size(&self) -> usize {
        if self.is_64 {
            mem::size_of::<elf::Sym64<Endianness>>()
        } else {
            mem::size_of::<elf::Sym32<Endianness>>()
        }
    }

    /// Reserve the range for the symbol table.
    ///
    /// This range is used for a section named `.symtab`.
    /// This function does nothing if no symbols were reserved.
    /// This must be called after [`Self::reserve_symbol_index`].
    pub fn reserve_symtab(&mut self) {
        debug_assert_eq!(self.symtab_offset, 0);
        if self.symtab_num == 0 {
            return;
        }
        self.symtab_offset = self.reserve(
            self.symtab_num as usize * self.symbol_size(),
            self.elf_align,
        );
    }

    /// Write the null symbol.
    ///
    /// This must be the first symbol that is written.
    /// This function does nothing if no symbols were reserved.
    pub fn write_null_symbol(&mut self) {
        if self.symtab_num == 0 {
            return;
        }
        util::write_align(self.buffer, self.elf_align);
        debug_assert_eq!(self.symtab_offset, self.buffer.len());
        if self.is_64 {
            self.buffer.write(&elf::Sym64::<Endianness>::default());
        } else {
            self.buffer.write(&elf::Sym32::<Endianness>::default());
        }

        if self.need_symtab_shndx {
            self.symtab_shndx_data.write_pod(&U32::new(self.endian, 0));
        }
    }

    /// Write a symbol.
    pub fn write_symbol(&mut self, sym: &Sym) {
        let st_name = if let Some(name) = sym.name {
            self.strtab.get_offset(name) as u32
        } else {
            0
        };
        let st_shndx = if let Some(section) = sym.section {
            if section.0 >= elf::SHN_LORESERVE as u32 {
                elf::SHN_XINDEX
            } else {
                section.0 as u16
            }
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

        if self.need_symtab_shndx {
            let section_index = sym.section.unwrap_or(SectionIndex(0));
            self.symtab_shndx_data
                .write_pod(&U32::new(self.endian, section_index.0));
        }
    }

    /// Reserve the section index for the symbol table.
    ///
    /// This must be called before [`Self::reserve_section_headers`].
    pub fn reserve_symtab_section_index(&mut self) -> SectionIndex {
        debug_assert_eq!(self.symtab_index, SectionIndex(0));
        self.symtab_str_id = Some(self.add_section_name(&b".symtab"[..]));
        self.symtab_index = self.reserve_section_index();
        self.symtab_index
    }

    /// Return the section index of the symbol table.
    pub fn symtab_index(&mut self) -> SectionIndex {
        self.symtab_index
    }

    /// Write the section header for the symbol table.
    ///
    /// This function does nothing if the section index was not reserved.
    pub fn write_symtab_section_header(&mut self, num_local: u32) {
        if self.symtab_index == SectionIndex(0) {
            return;
        }
        self.write_section_header(&SectionHeader {
            name: self.symtab_str_id,
            sh_type: elf::SHT_SYMTAB,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: self.symtab_offset as u64,
            sh_size: self.symtab_num as u64 * self.symbol_size() as u64,
            sh_link: self.strtab_index.0,
            sh_info: num_local,
            sh_addralign: self.elf_align as u64,
            sh_entsize: self.symbol_size() as u64,
        });
    }

    /// Return true if `.symtab_shndx` is needed.
    pub fn symtab_shndx_needed(&self) -> bool {
        self.need_symtab_shndx
    }

    /// Reserve the range for the extended section indices for the symbol table.
    ///
    /// This range is used for a section named `.symtab_shndx`.
    /// This also reserves a section index.
    ///
    /// This function does nothing if extended section indices are not needed.
    /// This must be called after [`Self::reserve_symbol_index`].
    pub fn reserve_symtab_shndx(&mut self) {
        debug_assert_eq!(self.symtab_shndx_offset, 0);
        if !self.need_symtab_shndx {
            return;
        }
        self.symtab_shndx_offset = self.reserve(self.symtab_num as usize * 4, 4);
    }

    /// Write the extended section indices for the symbol table.
    ///
    /// This function does nothing if the section was not reserved.
    pub fn write_symtab_shndx(&mut self) {
        if self.symtab_shndx_offset == 0 {
            return;
        }
        debug_assert_eq!(self.symtab_shndx_offset, self.buffer.len());
        debug_assert_eq!(self.symtab_num as usize * 4, self.symtab_shndx_data.len());
        self.buffer.write_bytes(&self.symtab_shndx_data);
    }

    /// Reserve the section index for the extended section indices symbol table.
    ///
    /// You should check [`Self::symtab_shndx_needed`] before calling this
    /// unless you have other means of knowing if this section is needed.
    ///
    /// This must be called before [`Self::reserve_section_headers`].
    pub fn reserve_symtab_shndx_section_index(&mut self) -> SectionIndex {
        debug_assert!(self.symtab_shndx_str_id.is_none());
        self.symtab_shndx_str_id = Some(self.add_section_name(&b".symtab_shndx"[..]));
        self.reserve_section_index()
    }

    /// Write the section header for the extended section indices for the symbol table.
    ///
    /// This function does nothing if the section index was not reserved.
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
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: self.symtab_shndx_offset as u64,
            sh_size,
            sh_link: self.symtab_index.0,
            sh_info: 0,
            sh_addralign: 4,
            sh_entsize: 4,
        });
    }

    /// Add a string to the dynamic string table.
    ///
    /// This will be stored in the `.dynstr` section.
    ///
    /// This must be called before [`Self::reserve_dynstr`].
    pub fn add_dynamic_string(&mut self, name: &'a [u8]) -> StringId {
        debug_assert_eq!(self.dynstr_offset, 0);
        self.need_dynstr = true;
        self.dynstr.add(name)
    }

    /// Return true if `.dynstr` is needed.
    pub fn dynstr_needed(&self) -> bool {
        self.need_dynstr
    }

    /// Reserve the range for the dynamic string table.
    ///
    /// This range is used for a section named `.dynstr`.
    ///
    /// This function does nothing if no dynamic strings or symbols were defined.
    /// This must be called after [`Self::add_dynamic_string`].
    pub fn reserve_dynstr(&mut self) {
        debug_assert_eq!(self.dynstr_offset, 0);
        if !self.need_dynstr {
            return;
        }
        // Start with null string.
        self.dynstr_data = vec![0];
        self.dynstr.write(1, &mut self.dynstr_data);
        self.dynstr_offset = self.reserve(self.dynstr_data.len(), 1);
    }

    /// Write the dynamic string table.
    ///
    /// This function does nothing if the section was not reserved.
    pub fn write_dynstr(&mut self) {
        if self.dynstr_offset == 0 {
            return;
        }
        debug_assert_eq!(self.dynstr_offset, self.buffer.len());
        self.buffer.write_bytes(&self.dynstr_data);
    }

    /// Reserve the section index for the dynamic string table.
    ///
    /// This must be called before [`Self::reserve_section_headers`].
    pub fn reserve_dynstr_section_index(&mut self) -> SectionIndex {
        debug_assert_eq!(self.dynstr_index, SectionIndex(0));
        self.dynstr_str_id = Some(self.add_section_name(&b".dynstr"[..]));
        self.dynstr_index = self.reserve_section_index();
        self.dynstr_index
    }

    /// Return the section index of the dynamic string table.
    pub fn dynstr_index(&mut self) -> SectionIndex {
        self.dynstr_index
    }

    /// Write the section header for the dynamic string table.
    ///
    /// This function does nothing if the section index was not reserved.
    pub fn write_dynstr_section_header(&mut self, sh_addr: u64) {
        if self.dynstr_index == SectionIndex(0) {
            return;
        }
        self.write_section_header(&SectionHeader {
            name: self.dynstr_str_id,
            sh_type: elf::SHT_STRTAB,
            sh_flags: elf::SHF_ALLOC.into(),
            sh_addr,
            sh_offset: self.dynstr_offset as u64,
            sh_size: self.dynstr_data.len() as u64,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 0,
        });
    }

    /// Reserve a dynamic symbol table entry.
    ///
    /// This will be stored in the `.dynsym` section.
    ///
    /// Automatically also reserves the null symbol if required.
    /// Callers may assume that the returned indices will be sequential
    /// starting at 1.
    ///
    /// This must be called before [`Self::reserve_dynsym`].
    pub fn reserve_dynamic_symbol_index(&mut self) -> SymbolIndex {
        debug_assert_eq!(self.dynsym_offset, 0);
        if self.dynsym_num == 0 {
            self.dynsym_num = 1;
            // The symtab must link to a strtab.
            self.need_dynstr = true;
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
    /// This function does nothing if no dynamic symbols were reserved.
    /// This must be called after [`Self::reserve_dynamic_symbol_index`].
    pub fn reserve_dynsym(&mut self) {
        debug_assert_eq!(self.dynsym_offset, 0);
        if self.dynsym_num == 0 {
            return;
        }
        self.dynsym_offset = self.reserve(
            self.dynsym_num as usize * self.symbol_size(),
            self.elf_align,
        );
    }

    /// Write the null dynamic symbol.
    ///
    /// This must be the first dynamic symbol that is written.
    /// This function does nothing if no dynamic symbols were reserved.
    pub fn write_null_dynamic_symbol(&mut self) {
        if self.dynsym_num == 0 {
            return;
        }
        util::write_align(self.buffer, self.elf_align);
        debug_assert_eq!(self.dynsym_offset, self.buffer.len());
        if self.is_64 {
            self.buffer.write(&elf::Sym64::<Endianness>::default());
        } else {
            self.buffer.write(&elf::Sym32::<Endianness>::default());
        }
    }

    /// Write a dynamic symbol.
    pub fn write_dynamic_symbol(&mut self, sym: &Sym) {
        let st_name = if let Some(name) = sym.name {
            self.dynstr.get_offset(name) as u32
        } else {
            0
        };

        let st_shndx = if let Some(section) = sym.section {
            if section.0 >= elf::SHN_LORESERVE as u32 {
                // TODO: we don't actually write out .dynsym_shndx yet.
                // This is unlikely to be needed though.
                elf::SHN_XINDEX
            } else {
                section.0 as u16
            }
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
    }

    /// Reserve the section index for the dynamic symbol table.
    ///
    /// This must be called before [`Self::reserve_section_headers`].
    pub fn reserve_dynsym_section_index(&mut self) -> SectionIndex {
        debug_assert_eq!(self.dynsym_index, SectionIndex(0));
        self.dynsym_str_id = Some(self.add_section_name(&b".dynsym"[..]));
        self.dynsym_index = self.reserve_section_index();
        self.dynsym_index
    }

    /// Return the section index of the dynamic symbol table.
    pub fn dynsym_index(&mut self) -> SectionIndex {
        self.dynsym_index
    }

    /// Write the section header for the dynamic symbol table.
    ///
    /// This function does nothing if the section index was not reserved.
    pub fn write_dynsym_section_header(&mut self, sh_addr: u64, num_local: u32) {
        if self.dynsym_index == SectionIndex(0) {
            return;
        }
        self.write_section_header(&SectionHeader {
            name: self.dynsym_str_id,
            sh_type: elf::SHT_DYNSYM,
            sh_flags: elf::SHF_ALLOC.into(),
            sh_addr,
            sh_offset: self.dynsym_offset as u64,
            sh_size: self.dynsym_num as u64 * self.symbol_size() as u64,
            sh_link: self.dynstr_index.0,
            sh_info: num_local,
            sh_addralign: self.elf_align as u64,
            sh_entsize: self.symbol_size() as u64,
        });
    }

    fn dyn_size(&self) -> usize {
        if self.is_64 {
            mem::size_of::<elf::Dyn64<Endianness>>()
        } else {
            mem::size_of::<elf::Dyn32<Endianness>>()
        }
    }

    /// Reserve the range for the `.dynamic` section.
    ///
    /// This function does nothing if `dynamic_num` is zero.
    pub fn reserve_dynamic(&mut self, dynamic_num: usize) {
        debug_assert_eq!(self.dynamic_offset, 0);
        if dynamic_num == 0 {
            return;
        }
        self.dynamic_num = dynamic_num;
        self.dynamic_offset = self.reserve(dynamic_num * self.dyn_size(), self.elf_align);
    }

    /// Write alignment padding bytes prior to the `.dynamic` section.
    ///
    /// This function does nothing if the section was not reserved.
    pub fn write_align_dynamic(&mut self) {
        if self.dynamic_offset == 0 {
            return;
        }
        util::write_align(self.buffer, self.elf_align);
        debug_assert_eq!(self.dynamic_offset, self.buffer.len());
    }

    /// Write a dynamic string entry.
    pub fn write_dynamic_string(&mut self, tag: u32, id: StringId) {
        self.write_dynamic(tag, self.dynstr.get_offset(id) as u64);
    }

    /// Write a dynamic value entry.
    pub fn write_dynamic(&mut self, d_tag: u32, d_val: u64) {
        debug_assert!(self.dynamic_offset <= self.buffer.len());
        let endian = self.endian;
        if self.is_64 {
            let d = elf::Dyn64 {
                d_tag: U64::new(endian, d_tag.into()),
                d_val: U64::new(endian, d_val),
            };
            self.buffer.write(&d);
        } else {
            let d = elf::Dyn32 {
                d_tag: U32::new(endian, d_tag),
                d_val: U32::new(endian, d_val as u32),
            };
            self.buffer.write(&d);
        }
        debug_assert!(
            self.dynamic_offset + self.dynamic_num * self.dyn_size() >= self.buffer.len()
        );
    }

    /// Reserve the section index for the dynamic table.
    pub fn reserve_dynamic_section_index(&mut self) -> SectionIndex {
        debug_assert!(self.dynamic_str_id.is_none());
        self.dynamic_str_id = Some(self.add_section_name(&b".dynamic"[..]));
        self.reserve_section_index()
    }

    /// Write the section header for the dynamic table.
    ///
    /// This function does nothing if the section index was not reserved.
    pub fn write_dynamic_section_header(&mut self, sh_addr: u64) {
        if self.dynamic_str_id.is_none() {
            return;
        }
        self.write_section_header(&SectionHeader {
            name: self.dynamic_str_id,
            sh_type: elf::SHT_DYNAMIC,
            sh_flags: (elf::SHF_WRITE | elf::SHF_ALLOC).into(),
            sh_addr,
            sh_offset: self.dynamic_offset as u64,
            sh_size: (self.dynamic_num * self.dyn_size()) as u64,
            sh_link: self.dynstr_index.0,
            sh_info: 0,
            sh_addralign: self.elf_align as u64,
            sh_entsize: self.dyn_size() as u64,
        });
    }

    fn rel_size(&self, is_rela: bool) -> usize {
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

    /// Reserve a file range for the given number of relocations.
    ///
    /// Returns the offset of the range.
    pub fn reserve_relocations(&mut self, count: usize, is_rela: bool) -> usize {
        self.reserve(count * self.rel_size(is_rela), self.elf_align)
    }

    /// Write alignment padding bytes prior to a relocation section.
    pub fn write_align_relocation(&mut self) {
        util::write_align(self.buffer, self.elf_align);
    }

    /// Write a relocation.
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
        offset: usize,
        count: usize,
        is_rela: bool,
    ) {
        self.write_section_header(&SectionHeader {
            name: Some(name),
            sh_type: if is_rela { elf::SHT_RELA } else { elf::SHT_REL },
            sh_flags: elf::SHF_INFO_LINK.into(),
            sh_addr: 0,
            sh_offset: offset as u64,
            sh_size: (count * self.rel_size(is_rela)) as u64,
            sh_link: symtab.0,
            sh_info: section.0,
            sh_addralign: self.elf_align as u64,
            sh_entsize: self.rel_size(is_rela) as u64,
        });
    }

    /// Reserve a file range for a COMDAT section.
    ///
    /// `count` is the number of sections in the COMDAT group.
    ///
    /// Returns the offset of the range.
    pub fn reserve_comdat(&mut self, count: usize) -> usize {
        self.reserve((count + 1) * 4, 4)
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
        offset: usize,
        count: usize,
    ) {
        self.write_section_header(&SectionHeader {
            name: Some(name),
            sh_type: elf::SHT_GROUP,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: offset as u64,
            sh_size: ((count + 1) * 4) as u64,
            sh_link: symtab.0,
            sh_info: symbol.0,
            sh_addralign: 4,
            sh_entsize: 4,
        });
    }
}

/// Native endian version of [`elf::FileHeader64`].
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct FileHeader {
    pub os_abi: u8,
    pub abi_version: u8,
    pub e_type: u16,
    pub e_machine: u16,
    pub e_entry: u64,
    pub e_flags: u32,
}

/// Native endian version of [`elf::ProgramHeader64`].
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
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
    pub sh_type: u32,
    pub sh_flags: u64,
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
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
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
