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

mod elf;
pub use elf::*;

mod macho;
pub use macho::*;

/// An object file.
#[derive(Debug)]
pub struct File<'a> {
    inner: FileInternal<'a>,
}

#[derive(Debug)]
enum FileInternal<'a> {
    Elf(ElfFile<'a>),
    MachO(MachOFile<'a>),
}

/// An iterator of the sections of a `File`.
#[derive(Debug)]
pub struct SectionIterator<'a> {
    inner: SectionIteratorInternal<'a>,
}

// we wrap our enums in a struct so that they are kept private.
#[derive(Debug)]
enum SectionIteratorInternal<'a> {
    Elf(ElfSectionIterator<'a>),
    MachO(MachOSectionIterator<'a>),
}

/// A Section of a File
pub struct Section<'a> {
    inner: SectionInternal<'a>,
}

enum SectionInternal<'a> {
    Elf(ElfSection<'a>),
    MachO(MachOSection<'a>),
}

/// The kind of a section.
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
        let inner = match goblin::peek(&mut cursor).map_err(|_| "Could not parse file magic")? {
            goblin::Hint::Elf(_) => FileInternal::Elf(ElfFile::parse(data)?),
            goblin::Hint::Mach(_) => FileInternal::MachO(MachOFile::parse(data)?),
            _ => return Err("Unknown file magic"),
        };
        Ok(File { inner })
    }

    /// Get the contents of the section named `section_name`, if such
    /// a section exists.
    pub fn get_section(&self, section_name: &str) -> Option<&'a [u8]> {
        match self.inner {
            FileInternal::Elf(ref elf) => elf.get_section(section_name),
            FileInternal::MachO(ref macho) => macho.get_section(section_name),
        }
    }

    /// Get an Iterator over the sections in the file.
    pub fn get_sections(&self) -> SectionIterator {
        match self.inner {
            FileInternal::Elf(ref elf) => SectionIterator {
                inner: SectionIteratorInternal::Elf(elf.get_sections()),
            },
            FileInternal::MachO(ref macho) => SectionIterator {
                inner: SectionIteratorInternal::MachO(macho.get_sections()),
            },
        }
    }

    /// Get a `Vec` of the symbols defined in the file.
    pub fn get_symbols(&self) -> Vec<Symbol<'a>> {
        match self.inner {
            FileInternal::Elf(ref elf) => elf.get_symbols(),
            FileInternal::MachO(ref macho) => macho.get_symbols(),
        }
    }

    /// Return true if the file is little endian, false if it is big endian.
    pub fn is_little_endian(&self) -> bool {
        match self.inner {
            FileInternal::Elf(ref elf) => elf.is_little_endian(),
            FileInternal::MachO(ref macho) => macho.is_little_endian(),
        }
    }
}

impl<'a> Iterator for SectionIterator<'a> {
    type Item = Section<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner {
            SectionIteratorInternal::Elf(ref mut elf) => elf.next().map(|x| {
                Section {
                    inner: SectionInternal::Elf(x),
                }
            }),
            SectionIteratorInternal::MachO(ref mut macho) => macho.next().map(|x| {
                Section {
                    inner: SectionInternal::MachO(x),
                }
            }),
        }
    }
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
        match self.inner {
            SectionInternal::Elf(ref elf) => elf.address(),
            SectionInternal::MachO(ref macho) => macho.address(),
        }
    }

    /// returns a reference to contents of the section
    pub fn data(&self) -> &'a [u8] {
        match self.inner {
            SectionInternal::Elf(ref elf) => elf.data(),
            SectionInternal::MachO(ref macho) => macho.data(),
        }
    }

    /// returns the name of the section
    pub fn name(&self) -> Option<&str> {
        match self.inner {
            SectionInternal::Elf(ref elf) => elf.name(),
            SectionInternal::MachO(ref macho) => macho.name(),
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
