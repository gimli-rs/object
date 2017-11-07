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

mod pe;
pub use pe::*;

mod traits;
pub use traits::*;

/// An object file.
#[derive(Debug)]
pub struct File<'a> {
    inner: FileInternal<'a>,
}

#[derive(Debug)]
enum FileInternal<'a> {
    Elf(ElfFile<'a>),
    MachO(MachOFile<'a>),
    Pe(PeFile<'a>),
}

/// The machine type of an object file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Machine {
    /// An unrecognized machine type.
    Other,
    /// ARM
    Arm,
    /// ARM64
    Arm64,
    /// x86
    X86,
    /// x86-64
    #[allow(non_camel_case_types)]
    X86_64,
}

/// An iterator over the segments of a `File`.
#[derive(Debug)]
pub struct SegmentIterator<'a> {
    inner: SegmentIteratorInternal<'a>,
}

#[derive(Debug)]
enum SegmentIteratorInternal<'a> {
    Elf(ElfSegmentIterator<'a>),
    MachO(MachOSegmentIterator<'a>),
    Pe(PeSegmentIterator<'a>),
}

/// A segment of a `File`.
pub struct Segment<'a> {
    inner: SegmentInternal<'a>,
}

#[derive(Debug)]
enum SegmentInternal<'a> {
    Elf(ElfSegment<'a>),
    MachO(MachOSegment<'a>),
    Pe(PeSegment<'a>),
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
    Pe(PeSectionIterator<'a>),
}

/// A Section of a File
pub struct Section<'a> {
    inner: SectionInternal<'a>,
}

enum SectionInternal<'a> {
    Elf(ElfSection<'a>),
    MachO(MachOSection<'a>),
    Pe(PeSection<'a>),
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
    name: Option<&'a str>,
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

impl<'a> Object<'a> for File<'a> {
    type Segment = Segment<'a>;
    type SegmentIterator = SegmentIterator<'a>;
    type Section = Section<'a>;
    type SectionIterator = SectionIterator<'a>;

    fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        let mut cursor = Cursor::new(data);
        let inner = match goblin::peek(&mut cursor).map_err(|_| "Could not parse file magic")? {
            goblin::Hint::Elf(_) => FileInternal::Elf(ElfFile::parse(data)?),
            goblin::Hint::Mach(_) => FileInternal::MachO(MachOFile::parse(data)?),
            goblin::Hint::PE => FileInternal::Pe(PeFile::parse(data)?),
            _ => return Err("Unknown file magic"),
        };
        Ok(File { inner })
    }

    fn machine(&self) -> Machine {
        match self.inner {
            FileInternal::Elf(ref elf) => elf.machine(),
            FileInternal::MachO(ref macho) => macho.machine(),
            FileInternal::Pe(ref pe) => pe.machine(),
        }
    }

    fn segments(&'a self) -> SegmentIterator<'a> {
        match self.inner {
            FileInternal::Elf(ref elf) => SegmentIterator {
                inner: SegmentIteratorInternal::Elf(elf.segments()),
            },
            FileInternal::MachO(ref macho) => SegmentIterator {
                inner: SegmentIteratorInternal::MachO(macho.segments()),
            },
            FileInternal::Pe(ref pe) => SegmentIterator {
                inner: SegmentIteratorInternal::Pe(pe.segments()),
            },
        }
    }

    fn section_data_by_name(&self, section_name: &str) -> Option<&'a [u8]> {
        match self.inner {
            FileInternal::Elf(ref elf) => elf.section_data_by_name(section_name),
            FileInternal::MachO(ref macho) => macho.section_data_by_name(section_name),
            FileInternal::Pe(ref pe) => pe.section_data_by_name(section_name),
        }
    }

    fn sections(&'a self) -> SectionIterator<'a> {
        match self.inner {
            FileInternal::Elf(ref elf) => SectionIterator {
                inner: SectionIteratorInternal::Elf(elf.sections()),
            },
            FileInternal::MachO(ref macho) => SectionIterator {
                inner: SectionIteratorInternal::MachO(macho.sections()),
            },
            FileInternal::Pe(ref pe) => SectionIterator {
                inner: SectionIteratorInternal::Pe(pe.sections()),
            },
        }
    }

    fn symbols(&self) -> Vec<Symbol<'a>> {
        match self.inner {
            FileInternal::Elf(ref elf) => elf.symbols(),
            FileInternal::MachO(ref macho) => macho.symbols(),
            FileInternal::Pe(ref pe) => pe.symbols(),
        }
    }

    fn is_little_endian(&self) -> bool {
        match self.inner {
            FileInternal::Elf(ref elf) => elf.is_little_endian(),
            FileInternal::MachO(ref macho) => macho.is_little_endian(),
            FileInternal::Pe(ref pe) => pe.is_little_endian(),
        }
    }
}

impl<'a> Iterator for SegmentIterator<'a> {
    type Item = Segment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner {
            SegmentIteratorInternal::Elf(ref mut elf) => elf.next().map(|x| {
                Segment {
                    inner: SegmentInternal::Elf(x),
                }
            }),
            SegmentIteratorInternal::MachO(ref mut macho) => macho.next().map(|x| {
                Segment {
                    inner: SegmentInternal::MachO(x),
                }
            }),
            SegmentIteratorInternal::Pe(ref mut pe) => pe.next().map(|x| {
                Segment {
                    inner: SegmentInternal::Pe(x),
                }
            }),
        }
    }
}

impl<'a> fmt::Debug for Segment<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // It's painful to do much better than this
        f.debug_struct("Segment")
            .field("name", &self.name().unwrap_or("<unnamed>"))
            .field("address", &self.address())
            .field("size", &self.data().len())
            .finish()
    }
}

impl<'a> Segment<'a> {
    fn inner(&self) -> &ObjectSegment<'a> {
        match self.inner {
            SegmentInternal::Elf(ref elf) => elf,
            SegmentInternal::MachO(ref macho) => macho,
            SegmentInternal::Pe(ref pe) => pe,
        }
    }
}

impl<'a> ObjectSegment<'a> for Segment<'a> {
    fn address(&self) -> u64 {
        self.inner().address()
    }

    fn size(&self) -> u64 {
        self.inner().size()
    }

    fn data(&self) -> &'a [u8] {
        self.inner().data()
    }

    fn name(&self) -> Option<&str> {
        self.inner().name()
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
            SectionIteratorInternal::Pe(ref mut pe) => pe.next().map(|x| {
                Section {
                    inner: SectionInternal::Pe(x),
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
    fn inner(&self) -> &ObjectSection<'a> {
        match self.inner {
            SectionInternal::Elf(ref elf) => elf,
            SectionInternal::MachO(ref macho) => macho,
            SectionInternal::Pe(ref pe) => pe,
        }
    }
}

impl<'a> ObjectSection<'a> for Section<'a> {
    fn address(&self) -> u64 {
        self.inner().address()
    }

    fn size(&self) -> u64 {
        self.inner().size()
    }

    fn data(&self) -> &'a [u8] {
        self.inner().data()
    }

    fn name(&self) -> Option<&str> {
        self.inner().name()
    }

    fn segment_name(&self) -> Option<&str> {
        self.inner().segment_name()
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
    pub fn name(&self) -> Option<&'a str> {
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
