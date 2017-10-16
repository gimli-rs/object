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

/// A symbol table entry.
pub struct Symbol<'a> {
    kind: SymbolKind,
    global: bool,
    name: &'a [u8],
    address: u64,
    size: u64,
    section: usize,
    // Symbol represents end of section. Internal use only.
    section_end: bool,
}

/// The kind of a symbol.
/// This is determined based on symbol flags, and the containing section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    /// The symbol kind is unknown.
    Unknown,
    /// The symbol is in a text section.
    Text,
    /// The symbol is in a data section.
    Data,
    /// The symbol is in a read only data section.
    ReadOnlyData,
    /// The symbol is in an uninitialized data section.
    UninitializedData,
    /// The symbol is in some other type of text or data section.
    Other,
    /// The symbol contains debugging information.
    Debug,
    /// The symbol is undefined.
    Undefined,
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
    pub fn get_symbols(&self) -> Vec<Symbol> {
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
    pub fn kind(&self) -> SymbolKind {
        self.kind
    }

    /// Return true if the symbol is global.
    pub fn is_global(&self) -> bool {
        self.global
    }

    /// Return true if the symbol is local.
    pub fn is_local(&self) -> bool {
        !self.global
    }

    /// The name of the symbol.
    pub fn name(&self) -> &'a [u8] {
        self.name
    }

    /// The address of the symbol. May be zero if the address is unknown.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// The size of the symbol. May be zero if the size is unknown.
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
                    SymbolKind::Text
                } else if sh.sh_flags & elf::section_header::SHF_WRITE as u64 != 0 {
                    SymbolKind::Data
                } else {
                    SymbolKind::ReadOnlyData
                }
            }
            elf::section_header::SHT_NOBITS => SymbolKind::UninitializedData,
            _ => SymbolKind::Unknown,
        };
        section_kinds.push(kind);
    }

    let mut symbols = Vec::new();
    // Skip undefined symbol index.
    for sym in elf.syms.iter().skip(1) {
        let kind = match elf::sym::st_type(sym.st_info) {
            elf::sym::STT_SECTION | elf::sym::STT_FILE => SymbolKind::Debug,
            _ => if sym.st_shndx == elf::section_header::SHN_UNDEF as usize {
                SymbolKind::Undefined
            } else if sym.st_shndx < section_kinds.len() {
                section_kinds[sym.st_shndx]
            } else {
                SymbolKind::Unknown
            },
        };
        let global = elf::sym::st_bind(sym.st_info) != elf::sym::STB_LOCAL;
        let name = match elf.strtab.get(sym.st_name) {
            Some(Ok(name)) => name.as_bytes(),
            _ => continue,
        };
        symbols.push(Symbol {
            kind,
            global,
            name,
            address: sym.st_value,
            size: sym.st_size,
            section: sym.st_shndx,
            section_end: false,
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
                let kind = if segname == b"__TEXT" && sectname == b"__text" {
                    SymbolKind::Text
                } else if segname == b"__DATA" && sectname == b"__data" {
                    SymbolKind::Data
                } else if segname == b"__DATA" && sectname == b"__bss" {
                    SymbolKind::UninitializedData
                } else {
                    SymbolKind::Other
                };
                let section_index = section_kinds.len();
                section_kinds.push(kind);
                section_ends.push(Symbol {
                    kind: SymbolKind::Unknown,
                    global: false,
                    name: &[],
                    address: section.addr + section.size,
                    size: 0,
                    section: section_index + 1,
                    section_end: true,
                });
            } else {
                // Add placeholder so that indexing works.
                section_kinds.push(SymbolKind::Unknown);
            }
        }
    }

    let mut symbols = Vec::new();
    for sym in macho.symbols() {
        if let Ok((name, nlist)) = sym {
            // Skip STAB debugging symbols.
            if nlist.n_type & 0xe0 != 0 {
                continue;
            }
            let n_type = nlist.n_type & mach::symbols::NLIST_TYPE_MASK;
            let kind = if n_type == mach::symbols::N_UNDF {
                SymbolKind::Undefined
            } else if n_type == mach::symbols::N_SECT {
                if nlist.n_sect == 0 || nlist.n_sect - 1 >= section_kinds.len() {
                    SymbolKind::Unknown
                } else {
                    section_kinds[nlist.n_sect - 1]
                }
            } else {
                SymbolKind::Unknown
            };
            symbols.push(Symbol {
                kind,
                global: nlist.is_global(),
                name: name.as_bytes(),
                address: nlist.n_value,
                size: 0,
                section: nlist.n_sect,
                section_end: false,
            });
        }
    }

    {
        // Calculate symbol sizes by sorting and finding the next symbol.
        let mut symbol_refs = Vec::with_capacity(symbols.len() + section_ends.len());
        symbol_refs.extend(symbols.iter_mut());
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
            a.section_end.cmp(&b.section_end)
        });

        for i in 0..symbol_refs.len() {
            let (before, after) = symbol_refs.split_at_mut(i + 1);
            let sym = &mut before[i];
            if !sym.section_end {
                if let Some(next) = after
                    .iter()
                    .skip_while(|x| !x.section_end && x.address == sym.address)
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
