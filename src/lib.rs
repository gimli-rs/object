//! # `object`
//!
//! The `object` crate provides a unified interface to working with object files
//! across platforms.
//!
//! See the [`File` struct](./struct.File.html) for details.

#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

extern crate goblin;

use std::fmt;
use std::io::Cursor;
use std::slice;

mod elf;
mod macho;

/// An object file.
#[derive(Debug)]
pub struct File<'a> {
    kind: ObjectKind<'a>,
    data: &'a [u8],
}

#[derive(Debug)]
enum ObjectKind<'a> {
    Elf(goblin::elf::Elf<'a>),
    MachO(goblin::mach::MachO<'a>),
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

/// An iterator of the sections of an File
pub struct SectionIterator<'a, 'b> {
    inner: SectionIteratorInternal<'a, 'b>,
}

impl<'a, 'b> fmt::Debug for SectionIterator<'a, 'b> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // It's painful to do much better than this
        f.debug_struct("SectionIterator").finish()
    }
}

// we wrap our enums in a struct so that they are kept private.
enum SectionIteratorInternal<'a, 'b> {
    MachO(
        Box<
            Iterator<
                Item = (
                    goblin::mach::segment::Section,
                    goblin::mach::segment::SectionData<'a>,
                ),
            >
                + 'b,
        >,
    ),
    Elf(
        slice::Iter<'a, goblin::elf::SectionHeader>,
        &'a goblin::elf::Elf<'a>,
        &'a [u8],
    ),
}

enum SectionInternal<'a> {
    MachO(
        (
            goblin::mach::segment::Section,
            goblin::mach::segment::SectionData<'a>,
        ),
    ),
    Elf(
        <slice::Iter<'a, goblin::elf::SectionHeader> as Iterator>::Item,
        &'a goblin::elf::Elf<'a>,
        &'a [u8],
    ),
}

/// A Section of a File
pub struct Section<'a> {
    inner: SectionInternal<'a>,
}

impl<'a> fmt::Debug for Section<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // It's painful to do much better than this
        f.debug_struct("Section")
            .field("name", &self.name().unwrap_or("<invalid name>"))
            .field("address", &self.address())
            .field("size", &self.data().len())
            .finish()
    }
}

impl<'a> Section<'a> {
    /// returns the address of the section
    pub fn address(&self) -> u64 {
        match &self.inner {
            &SectionInternal::MachO(ref macho) => macho.0.addr,
            &SectionInternal::Elf(ref elf, _, _) => elf.sh_addr,
        }
    }

    /// returns a reference to contents of the section
    pub fn data(&self) -> &'a [u8] {
        match &self.inner {
            &SectionInternal::MachO(ref macho) => macho.1,
            &SectionInternal::Elf(ref header, _, ref data) => {
                &data[header.sh_offset as usize..][..header.sh_size as usize]
            }
        }
    }

    /// returns the name of the section
    pub fn name(&self) -> Option<&str> {
        match &self.inner {
            &SectionInternal::MachO(ref macho) => macho.0.name().ok(),
            &SectionInternal::Elf(ref header, ref elf, ref _data) => {
                elf.shdr_strtab.get(header.sh_name).and_then(|x| x.ok())
            }
        }
    }
}

impl<'a, 'b> Iterator for SectionIterator<'a, 'b> {
    type Item = Section<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            &mut SectionIteratorInternal::MachO(ref mut macho) => macho.next().map(|x| {
                Section {
                    inner: SectionInternal::MachO(x),
                }
            }),
            &mut SectionIteratorInternal::Elf(ref mut iter, ref elf, ref data) => {
                iter.next().map(|x| {
                    Section {
                        inner: SectionInternal::Elf(x, elf, data),
                    }
                })
            }
        }
    }
}

impl<'a> File<'a> {
    /// Parse the raw object file data.
    pub fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        let mut cursor = Cursor::new(data);
        let kind = match goblin::peek(&mut cursor).map_err(|_| "Could not parse file magic")? {
            goblin::Hint::Elf(_) => {
                let elf = goblin::elf::Elf::parse(data).map_err(|_| "Could not parse ELF header")?;
                ObjectKind::Elf(elf)
            }
            goblin::Hint::Mach(_) => {
                let macho = goblin::mach::MachO::parse(data, 0)
                    .map_err(|_| "Could not parse Mach-O header")?;
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
            ObjectKind::Elf(ref elf) => elf::get_section(elf, section_name, self.data),
            ObjectKind::MachO(ref macho) => macho::get_section(macho, section_name),
        }
    }

    /// Get an Iterator over the sections in the file.
    pub fn get_sections(&self) -> SectionIterator {
        match self.kind {
            ObjectKind::Elf(ref elf) => SectionIterator {
                inner: SectionIteratorInternal::Elf(elf.section_headers.iter(), &elf, self.data),
            },
            ObjectKind::MachO(ref macho) => SectionIterator {
                inner: SectionIteratorInternal::MachO(Box::new(macho.segments.iter()
                .flat_map(|x| x) // iterate over the sections
                .flat_map(|x| x))),
            },
        }
    }

    /// Get a `Vec` of the symbols defined in the file.
    pub fn get_symbols(&self) -> Vec<Symbol<'a>> {
        match self.kind {
            ObjectKind::Elf(ref elf) => elf::get_symbols(elf),
            ObjectKind::MachO(ref macho) => macho::get_symbols(macho),
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

#[doc(hidden)]
#[deprecated]
pub trait Object {}
