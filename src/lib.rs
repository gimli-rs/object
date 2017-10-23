//! # `object`
//!
//! The `object` crate provides a unified interface to working with object files
//! across platforms.
//!
//! See the [`File` struct](./struct.File.html) for details.

#![deny(missing_docs)]

extern crate goblin;

use goblin::{elf, mach};
use std::cmp::Ordering;
use std::io::Cursor;

/// An object file.
pub struct File<'a> {
    kind: ObjectKind<'a>,
    data: &'a [u8],
}

enum ObjectKind<'a> {
    Elf(elf::Elf<'a>),
    MachO(mach::MachO<'a>),
}

/// The kind of a sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    /// The section kind is unknown.
    Unknown,
    /// An executable code section.
    Text,
    /// A data section.
    Data,
    /// A read only data section.
    ReadOnlyData,
    /// An uninitialized data section.
    UninitializedData,
    /// Some other type of text or data section.
    Other,
}

/// A symbol table entry.
#[derive(Debug)]
pub struct Symbol<'a> {
    kind: SymbolKind,
    section: usize,
    section_kind: Option<SectionKind>,
    global: bool,
    name: &'a [u8],
    address: u64,
    size: u64,
}

/// The kind of a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    /// The symbol kind is unknown.
    Unknown,
    /// The symbol is for executable code.
    Text,
    /// The symbol is for a data object.
    Data,
    /// The symbol is for a section.
    Section,
    /// The symbol is the name of a file. It precedes symbols within that file.
    File,
    /// The symbol is for an uninitialized common block.
    Common,
    /// The symbol is for a thread local storage entity.
    Tls,
}

impl<'a> File<'a> {
    /// Parse the raw object file data.
    pub fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        let mut cursor = Cursor::new(data);
        let kind = match goblin::peek(&mut cursor).map_err(|_| "Could not parse file magic")? {
            goblin::Hint::Elf(_) => {
                let elf = elf::Elf::parse(data).map_err(|_| "Could not parse ELF header")?;
                ObjectKind::Elf(elf)
            }
            goblin::Hint::Mach(_) => {
                let macho =
                    mach::MachO::parse(data, 0).map_err(|_| "Could not parse Mach-O header")?;
                ObjectKind::MachO(macho)
            }
            _ => return Err("Unknown file magic"),
        };
        Ok(File { kind, data })
    }

    /// Get the contents of the section named `section_name`, if such
    /// a section exists.
    pub fn get_section(&self, section_name: &str) -> Option<&'a [u8]> {
        match self.kind {
            ObjectKind::Elf(ref elf) => elf_get_section(elf, section_name, self.data),
            ObjectKind::MachO(ref macho) => macho_get_section(macho, section_name),
        }
    }

    /// Get a `Vec` of the symbols defined in the file.
    pub fn get_symbols(&self) -> Vec<Symbol<'a>> {
        match self.kind {
            ObjectKind::Elf(ref elf) => elf_get_symbols(elf),
            ObjectKind::MachO(ref macho) => macho_get_symbols(macho),
        }
    }

    /// Return true if the file is little endian, false if it is big endian.
    pub fn is_little_endian(&self) -> bool {
        match self.kind {
            ObjectKind::Elf(ref elf) => elf.little_endian,
            ObjectKind::MachO(ref macho) => macho.header.is_little_endian(),
        }
    }
}

impl<'a> Symbol<'a> {
    /// Return the kind of this symbol.
    #[inline]
    pub fn kind(&self) -> SymbolKind {
        self.kind
    }

    /// Returns the section kind for the symbol, or `None` if the symbol is undefnined.
    #[inline]
    pub fn section_kind(&self) -> Option<SectionKind> {
        self.section_kind
    }

    /// Return true if the symbol is undefined.
    #[inline]
    pub fn is_undefined(&self) -> bool {
        self.section_kind.is_none()
    }

    /// Return true if the symbol is global.
    #[inline]
    pub fn is_global(&self) -> bool {
        self.global
    }

    /// Return true if the symbol is local.
    #[inline]
    pub fn is_local(&self) -> bool {
        !self.global
    }

    /// The name of the symbol.
    #[inline]
    pub fn name(&self) -> &'a [u8] {
        self.name
    }

    /// The address of the symbol. May be zero if the address is unknown.
    #[inline]
    pub fn address(&self) -> u64 {
        self.address
    }

    /// The size of the symbol. May be zero if the size is unknown.
    #[inline]
    pub fn size(&self) -> u64 {
        self.size
    }
}

fn elf_get_section<'a>(elf: &elf::Elf<'a>, section_name: &str, data: &'a [u8]) -> Option<&'a [u8]> {
    for header in &elf.section_headers {
        if let Some(Ok(name)) = elf.shdr_strtab.get(header.sh_name) {
            if name == section_name {
                return Some(&data[header.sh_offset as usize..][..header.sh_size as usize]);
            }
        }
    }
    None
}

fn elf_get_symbols<'a>(elf: &elf::Elf<'a>) -> Vec<Symbol<'a>> {
    // Determine section kinds.
    // The section kinds are inherited by symbols in those sections.
    let mut section_kinds = Vec::new();
    for sh in &elf.section_headers {
        let kind = match sh.sh_type {
            elf::section_header::SHT_PROGBITS => {
                if sh.sh_flags & elf::section_header::SHF_EXECINSTR as u64 != 0 {
                    SectionKind::Text
                } else if sh.sh_flags & elf::section_header::SHF_WRITE as u64 != 0 {
                    SectionKind::Data
                } else {
                    SectionKind::ReadOnlyData
                }
            }
            elf::section_header::SHT_NOBITS => SectionKind::UninitializedData,
            _ => SectionKind::Unknown,
        };
        section_kinds.push(kind);
    }

    let mut symbols = Vec::new();
    // Skip undefined symbol index.
    for sym in elf.syms.iter().skip(1) {
        let kind = match elf::sym::st_type(sym.st_info) {
            elf::sym::STT_OBJECT => SymbolKind::Data,
            elf::sym::STT_FUNC => SymbolKind::Text,
            elf::sym::STT_SECTION => SymbolKind::Section,
            elf::sym::STT_FILE => SymbolKind::File,
            elf::sym::STT_COMMON => SymbolKind::Common,
            elf::sym::STT_TLS => SymbolKind::Tls,
            _ => SymbolKind::Unknown,
        };
        let global = elf::sym::st_bind(sym.st_info) != elf::sym::STB_LOCAL;
        let section_kind = if sym.st_shndx == elf::section_header::SHN_UNDEF as usize
            || sym.st_shndx >= section_kinds.len()
        {
            None
        } else {
            Some(section_kinds[sym.st_shndx])
        };
        let name = match elf.strtab.get(sym.st_name) {
            Some(Ok(name)) => name.as_bytes(),
            _ => continue,
        };
        symbols.push(Symbol {
            kind,
            section: sym.st_shndx,
            section_kind,
            global,
            name,
            address: sym.st_value,
            size: sym.st_size,
        });
    }
    symbols
}

fn macho_get_section<'a>(macho: &mach::MachO<'a>, section_name: &str) -> Option<&'a [u8]> {
    let segment_name = if section_name == ".eh_frame" {
        "__TEXT"
    } else {
        "__DWARF"
    };
    let section_name = macho_translate_section_name(section_name);

    for segment in &macho.segments {
        if let Ok(name) = segment.name() {
            if name == segment_name {
                for section in segment {
                    if let Ok((section, data)) = section {
                        if let Ok(name) = section.name() {
                            if name.as_bytes() == &*section_name {
                                return Some(data);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

// Translate the "." prefix to the "__" prefix used by OSX/Mach-O, eg
// ".debug_info" to "__debug_info".
fn macho_translate_section_name(section_name: &str) -> Vec<u8> {
    let mut name = Vec::with_capacity(section_name.len() + 1);
    name.push(b'_');
    name.push(b'_');
    for ch in &section_name.as_bytes()[1..] {
        name.push(*ch);
    }
    name
}

fn macho_get_symbols<'a>(macho: &mach::MachO<'a>) -> Vec<Symbol<'a>> {
    // Determine section kinds and end addresses.
    // The section kinds are inherited by symbols in those sections.
    // The section end addresses are needed for calculating symbol sizes.
    let mut section_kinds = Vec::new();
    let mut section_ends = Vec::new();
    for segment in &macho.segments {
        for section in segment {
            if let Ok((section, _)) = section {
                let sectname = section
                    .name()
                    .map(str::as_bytes)
                    .unwrap_or(&section.sectname[..]);
                let segname = section
                    .segname()
                    .map(str::as_bytes)
                    .unwrap_or(&section.segname[..]);
                let (section_kind, symbol_kind) = if segname == b"__TEXT" && sectname == b"__text" {
                    (SectionKind::Text, SymbolKind::Text)
                } else if segname == b"__DATA" && sectname == b"__data" {
                    (SectionKind::Data, SymbolKind::Data)
                } else if segname == b"__DATA" && sectname == b"__bss" {
                    (SectionKind::UninitializedData, SymbolKind::Data)
                } else {
                    (SectionKind::Other, SymbolKind::Unknown)
                };
                let section_index = section_kinds.len();
                section_kinds.push((section_kind, symbol_kind));
                section_ends.push(Symbol {
                    kind: SymbolKind::Section,
                    section: section_index + 1,
                    section_kind: Some(section_kind),
                    global: false,
                    name: &[],
                    address: section.addr + section.size,
                    size: 0,
                });
            } else {
                // Add placeholder so that indexing works.
                section_kinds.push((SectionKind::Unknown, SymbolKind::Unknown));
            }
        }
    }

    let mut symbols = Vec::new();
    for sym in macho.symbols() {
        if let Ok((name, nlist)) = sym {
            // Skip STAB debugging symbols.
            // FIXME: use N_STAB constant
            if nlist.n_type & 0xe0 != 0 {
                continue;
            }
            let n_type = nlist.n_type & mach::symbols::NLIST_TYPE_MASK;
            let (section_kind, kind) = if n_type == mach::symbols::N_SECT {
                if nlist.n_sect == 0 || nlist.n_sect - 1 >= section_kinds.len() {
                    (None, SymbolKind::Unknown)
                } else {
                    let (section_kind, kind) = section_kinds[nlist.n_sect - 1];
                    (Some(section_kind), kind)
                }
            } else {
                (None, SymbolKind::Unknown)
            };
            symbols.push(Symbol {
                kind,
                section: nlist.n_sect,
                section_kind,
                global: nlist.is_global(),
                name: name.as_bytes(),
                address: nlist.n_value,
                size: 0,
            });
        }
    }

    {
        // Calculate symbol sizes by sorting and finding the next symbol.
        let mut symbol_refs = Vec::with_capacity(symbols.len() + section_ends.len());
        symbol_refs.extend(symbols.iter_mut().filter(|s| !s.is_undefined()));
        symbol_refs.extend(section_ends.iter_mut());
        symbol_refs.sort_by(|a, b| {
            let ord = a.section.cmp(&b.section);
            if ord != Ordering::Equal {
                return ord;
            }
            let ord = a.address.cmp(&b.address);
            if ord != Ordering::Equal {
                return ord;
            }
            // Place the dummy end of section symbols last.
            (a.kind == SymbolKind::Section).cmp(&(b.kind == SymbolKind::Section))
        });

        for i in 0..symbol_refs.len() {
            let (before, after) = symbol_refs.split_at_mut(i + 1);
            let sym = &mut before[i];
            if sym.kind != SymbolKind::Section {
                if let Some(next) = after
                    .iter()
                    .skip_while(|x| {
                        x.kind != SymbolKind::Section && x.address == sym.address
                    })
                    .next()
                {
                    sym.size = next.address - sym.address;
                }
            }
        }
    }

    symbols
}

#[doc(hidden)]
#[deprecated]
pub trait Object {}
