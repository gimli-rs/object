//! Interface for writing object files.

use std::borrow::Cow;
use std::boxed::Box;
use std::collections::HashMap;
use std::string::String;
use std::vec::Vec;
use std::{error, fmt, io, result, str};

use crate::endian::{Endianness, U32, U64};
use crate::{
    Architecture, BinaryFormat, ComdatKind, FileFlags, RelocationEncoding, RelocationKind,
    SectionFlags, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};

#[cfg(feature = "coff")]
mod coff;

#[cfg(feature = "elf")]
pub mod elf;

#[cfg(feature = "macho")]
mod macho;

#[cfg(feature = "pe")]
pub mod pe;

mod string;
pub use string::StringId;

mod util;
pub use util::*;

/// The error type used within the write module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(String);

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl error::Error for Error {}

/// The result type used within the write module.
pub type Result<T> = result::Result<T, Error>;

/// A writable object file.
#[derive(Debug)]
pub struct Object<'a> {
    format: BinaryFormat,
    architecture: Architecture,
    endian: Endianness,
    sections: Vec<Section<'a>>,
    standard_sections: HashMap<StandardSection, SectionId>,
    symbols: Vec<Symbol>,
    symbol_map: HashMap<Vec<u8>, SymbolId>,
    stub_symbols: HashMap<SymbolId, SymbolId>,
    comdats: Vec<Comdat>,
    /// File flags that are specific to each file format.
    pub flags: FileFlags,
    /// The symbol name mangling scheme.
    pub mangling: Mangling,
    /// Mach-O "_tlv_bootstrap" symbol.
    tlv_bootstrap: Option<SymbolId>,
}

impl<'a> Object<'a> {
    /// Create an empty object file.
    pub fn new(format: BinaryFormat, architecture: Architecture, endian: Endianness) -> Object<'a> {
        Object {
            format,
            architecture,
            endian,
            sections: Vec::new(),
            standard_sections: HashMap::new(),
            symbols: Vec::new(),
            symbol_map: HashMap::new(),
            stub_symbols: HashMap::new(),
            comdats: Vec::new(),
            flags: FileFlags::None,
            mangling: Mangling::default(format, architecture),
            tlv_bootstrap: None,
        }
    }

    /// Return the file format.
    #[inline]
    pub fn format(&self) -> BinaryFormat {
        self.format
    }

    /// Return the architecture.
    #[inline]
    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    /// Return the current mangling setting.
    #[inline]
    pub fn mangling(&self) -> Mangling {
        self.mangling
    }

    /// Specify the mangling setting.
    #[inline]
    pub fn set_mangling(&mut self, mangling: Mangling) {
        self.mangling = mangling;
    }

    /// Return the name for a standard segment.
    ///
    /// This will vary based on the file format.
    #[allow(unused_variables)]
    pub fn segment_name(&self, segment: StandardSegment) -> &'static [u8] {
        match self.format {
            #[cfg(feature = "coff")]
            BinaryFormat::Coff => &[],
            #[cfg(feature = "elf")]
            BinaryFormat::Elf => &[],
            #[cfg(feature = "macho")]
            BinaryFormat::MachO => self.macho_segment_name(segment),
            _ => unimplemented!(),
        }
    }

    /// Get the section with the given `SectionId`.
    #[inline]
    pub fn section(&self, section: SectionId) -> &Section<'a> {
        &self.sections[section.0]
    }

    /// Mutably get the section with the given `SectionId`.
    #[inline]
    pub fn section_mut(&mut self, section: SectionId) -> &mut Section<'a> {
        &mut self.sections[section.0]
    }

    /// Set the data for an existing section.
    ///
    /// Must not be called for sections that already have data, or that contain uninitialized data.
    pub fn set_section_data<T>(&mut self, section: SectionId, data: T, align: u64)
    where
        T: Into<Cow<'a, [u8]>>,
    {
        self.sections[section.0].set_data(data, align)
    }

    /// Append data to an existing section. Returns the section offset of the data.
    pub fn append_section_data(&mut self, section: SectionId, data: &[u8], align: u64) -> u64 {
        self.sections[section.0].append_data(data, align)
    }

    /// Append zero-initialized data to an existing section. Returns the section offset of the data.
    pub fn append_section_bss(&mut self, section: SectionId, size: u64, align: u64) -> u64 {
        self.sections[section.0].append_bss(size, align)
    }

    /// Return the `SectionId` of a standard section.
    ///
    /// If the section doesn't already exist then it is created.
    pub fn section_id(&mut self, section: StandardSection) -> SectionId {
        self.standard_sections
            .get(&section)
            .cloned()
            .unwrap_or_else(|| {
                let (segment, name, kind) = self.section_info(section);
                self.add_section(segment.to_vec(), name.to_vec(), kind)
            })
    }

    /// Add a new section and return its `SectionId`.
    ///
    /// This also creates a section symbol.
    pub fn add_section(&mut self, segment: Vec<u8>, name: Vec<u8>, kind: SectionKind) -> SectionId {
        let id = SectionId(self.sections.len());
        self.sections.push(Section {
            segment,
            name,
            kind,
            size: 0,
            align: 1,
            data: Cow::Borrowed(&[]),
            relocations: Vec::new(),
            symbol: None,
            flags: SectionFlags::None,
        });

        // Add to self.standard_sections if required. This may match multiple standard sections.
        let section = &self.sections[id.0];
        for standard_section in StandardSection::all() {
            if !self.standard_sections.contains_key(standard_section) {
                let (segment, name, kind) = self.section_info(*standard_section);
                if segment == &*section.segment && name == &*section.name && kind == section.kind {
                    self.standard_sections.insert(*standard_section, id);
                }
            }
        }

        id
    }

    fn section_info(
        &self,
        section: StandardSection,
    ) -> (&'static [u8], &'static [u8], SectionKind) {
        match self.format {
            #[cfg(feature = "coff")]
            BinaryFormat::Coff => self.coff_section_info(section),
            #[cfg(feature = "elf")]
            BinaryFormat::Elf => self.elf_section_info(section),
            #[cfg(feature = "macho")]
            BinaryFormat::MachO => self.macho_section_info(section),
            _ => unimplemented!(),
        }
    }

    /// Add a subsection. Returns the `SectionId` and section offset of the data.
    pub fn add_subsection(
        &mut self,
        section: StandardSection,
        name: &[u8],
        data: &[u8],
        align: u64,
    ) -> (SectionId, u64) {
        let section_id = if self.has_subsections_via_symbols() {
            self.set_subsections_via_symbols();
            self.section_id(section)
        } else {
            let (segment, name, kind) = self.subsection_info(section, name);
            self.add_section(segment.to_vec(), name, kind)
        };
        let offset = self.append_section_data(section_id, data, align);
        (section_id, offset)
    }

    fn has_subsections_via_symbols(&self) -> bool {
        match self.format {
            BinaryFormat::Coff | BinaryFormat::Elf => false,
            BinaryFormat::MachO => true,
            _ => unimplemented!(),
        }
    }

    fn set_subsections_via_symbols(&mut self) {
        match self.format {
            #[cfg(feature = "macho")]
            BinaryFormat::MachO => self.macho_set_subsections_via_symbols(),
            _ => unimplemented!(),
        }
    }

    fn subsection_info(
        &self,
        section: StandardSection,
        value: &[u8],
    ) -> (&'static [u8], Vec<u8>, SectionKind) {
        let (segment, section, kind) = self.section_info(section);
        let name = self.subsection_name(section, value);
        (segment, name, kind)
    }

    #[allow(unused_variables)]
    fn subsection_name(&self, section: &[u8], value: &[u8]) -> Vec<u8> {
        debug_assert!(!self.has_subsections_via_symbols());
        match self.format {
            #[cfg(feature = "coff")]
            BinaryFormat::Coff => self.coff_subsection_name(section, value),
            #[cfg(feature = "elf")]
            BinaryFormat::Elf => self.elf_subsection_name(section, value),
            _ => unimplemented!(),
        }
    }

    /// Get the COMDAT section group with the given `ComdatId`.
    #[inline]
    pub fn comdat(&self, comdat: ComdatId) -> &Comdat {
        &self.comdats[comdat.0]
    }

    /// Mutably get the COMDAT section group with the given `ComdatId`.
    #[inline]
    pub fn comdat_mut(&mut self, comdat: ComdatId) -> &mut Comdat {
        &mut self.comdats[comdat.0]
    }

    /// Add a new COMDAT section group and return its `ComdatId`.
    pub fn add_comdat(&mut self, comdat: Comdat) -> ComdatId {
        let comdat_id = ComdatId(self.comdats.len());
        self.comdats.push(comdat);
        comdat_id
    }

    /// Get the `SymbolId` of the symbol with the given name.
    pub fn symbol_id(&self, name: &[u8]) -> Option<SymbolId> {
        self.symbol_map.get(name).cloned()
    }

    /// Get the symbol with the given `SymbolId`.
    #[inline]
    pub fn symbol(&self, symbol: SymbolId) -> &Symbol {
        &self.symbols[symbol.0]
    }

    /// Mutably get the symbol with the given `SymbolId`.
    #[inline]
    pub fn symbol_mut(&mut self, symbol: SymbolId) -> &mut Symbol {
        &mut self.symbols[symbol.0]
    }

    /// Add a new symbol and return its `SymbolId`.
    pub fn add_symbol(&mut self, mut symbol: Symbol) -> SymbolId {
        // Defined symbols must have a scope.
        debug_assert!(symbol.is_undefined() || symbol.scope != SymbolScope::Unknown);
        if symbol.kind == SymbolKind::Section {
            // There can only be one section symbol, but update its flags, since
            // the automatically generated section symbol will have none.
            let symbol_id = self.section_symbol(symbol.section.id().unwrap());
            if symbol.flags != SymbolFlags::None {
                self.symbol_mut(symbol_id).flags = symbol.flags;
            }
            return symbol_id;
        }
        if !symbol.name.is_empty()
            && (symbol.kind == SymbolKind::Text
                || symbol.kind == SymbolKind::Data
                || symbol.kind == SymbolKind::Tls)
        {
            let unmangled_name = symbol.name.clone();
            if let Some(prefix) = self.mangling.global_prefix() {
                symbol.name.insert(0, prefix);
            }
            let symbol_id = self.add_raw_symbol(symbol);
            self.symbol_map.insert(unmangled_name, symbol_id);
            symbol_id
        } else {
            self.add_raw_symbol(symbol)
        }
    }

    fn add_raw_symbol(&mut self, symbol: Symbol) -> SymbolId {
        let symbol_id = SymbolId(self.symbols.len());
        self.symbols.push(symbol);
        symbol_id
    }

    /// Return true if the file format supports `StandardSection::UninitializedTls`.
    #[inline]
    pub fn has_uninitialized_tls(&self) -> bool {
        self.format != BinaryFormat::Coff
    }

    /// Return true if the file format supports `StandardSection::Common`.
    #[inline]
    pub fn has_common(&self) -> bool {
        self.format == BinaryFormat::MachO
    }

    /// Add a new common symbol and return its `SymbolId`.
    ///
    /// For Mach-O, this appends the symbol to the `__common` section.
    pub fn add_common_symbol(&mut self, mut symbol: Symbol, size: u64, align: u64) -> SymbolId {
        if self.has_common() {
            let symbol_id = self.add_symbol(symbol);
            let section = self.section_id(StandardSection::Common);
            self.add_symbol_bss(symbol_id, section, size, align);
            symbol_id
        } else {
            symbol.section = SymbolSection::Common;
            symbol.size = size;
            self.add_symbol(symbol)
        }
    }

    /// Add a new file symbol and return its `SymbolId`.
    pub fn add_file_symbol(&mut self, name: Vec<u8>) -> SymbolId {
        self.add_raw_symbol(Symbol {
            name,
            value: 0,
            size: 0,
            kind: SymbolKind::File,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::None,
            flags: SymbolFlags::None,
        })
    }

    /// Get the symbol for a section.
    pub fn section_symbol(&mut self, section_id: SectionId) -> SymbolId {
        let section = &mut self.sections[section_id.0];
        if let Some(symbol) = section.symbol {
            return symbol;
        }
        let name = if self.format == BinaryFormat::Coff {
            section.name.clone()
        } else {
            Vec::new()
        };
        let symbol_id = SymbolId(self.symbols.len());
        self.symbols.push(Symbol {
            name,
            value: 0,
            size: 0,
            kind: SymbolKind::Section,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(section_id),
            flags: SymbolFlags::None,
        });
        section.symbol = Some(symbol_id);
        symbol_id
    }

    /// Append data to an existing section, and update a symbol to refer to it.
    ///
    /// For Mach-O, this also creates a `__thread_vars` entry for TLS symbols, and the
    /// symbol will indirectly point to the added data via the `__thread_vars` entry.
    ///
    /// Returns the section offset of the data.
    pub fn add_symbol_data(
        &mut self,
        symbol_id: SymbolId,
        section: SectionId,
        data: &[u8],
        align: u64,
    ) -> u64 {
        let offset = self.append_section_data(section, data, align);
        self.set_symbol_data(symbol_id, section, offset, data.len() as u64);
        offset
    }

    /// Append zero-initialized data to an existing section, and update a symbol to refer to it.
    ///
    /// For Mach-O, this also creates a `__thread_vars` entry for TLS symbols, and the
    /// symbol will indirectly point to the added data via the `__thread_vars` entry.
    ///
    /// Returns the section offset of the data.
    pub fn add_symbol_bss(
        &mut self,
        symbol_id: SymbolId,
        section: SectionId,
        size: u64,
        align: u64,
    ) -> u64 {
        let offset = self.append_section_bss(section, size, align);
        self.set_symbol_data(symbol_id, section, offset, size);
        offset
    }

    /// Update a symbol to refer to the given data within a section.
    ///
    /// For Mach-O, this also creates a `__thread_vars` entry for TLS symbols, and the
    /// symbol will indirectly point to the data via the `__thread_vars` entry.
    #[allow(unused_mut)]
    pub fn set_symbol_data(
        &mut self,
        mut symbol_id: SymbolId,
        section: SectionId,
        offset: u64,
        size: u64,
    ) {
        // Defined symbols must have a scope.
        debug_assert!(self.symbol(symbol_id).scope != SymbolScope::Unknown);
        match self.format {
            #[cfg(feature = "macho")]
            BinaryFormat::MachO => symbol_id = self.macho_add_thread_var(symbol_id),
            _ => {}
        }
        let symbol = self.symbol_mut(symbol_id);
        symbol.value = offset;
        symbol.size = size;
        symbol.section = SymbolSection::Section(section);
    }

    /// Convert a symbol to a section symbol and offset.
    ///
    /// Returns `None` if the symbol does not have a section.
    pub fn symbol_section_and_offset(&mut self, symbol_id: SymbolId) -> Option<(SymbolId, u64)> {
        let symbol = self.symbol(symbol_id);
        if symbol.kind == SymbolKind::Section {
            return Some((symbol_id, 0));
        }
        let symbol_offset = symbol.value;
        let section = symbol.section.id()?;
        let section_symbol = self.section_symbol(section);
        Some((section_symbol, symbol_offset))
    }

    /// Add a relocation to a section.
    ///
    /// Relocations must only be added after the referenced symbols have been added
    /// and defined (if applicable).
    pub fn add_relocation(&mut self, section: SectionId, mut relocation: Relocation) -> Result<()> {
        let addend = match self.format {
            #[cfg(feature = "coff")]
            BinaryFormat::Coff => self.coff_fixup_relocation(&mut relocation),
            #[cfg(feature = "elf")]
            BinaryFormat::Elf => self.elf_fixup_relocation(&mut relocation)?,
            #[cfg(feature = "macho")]
            BinaryFormat::MachO => self.macho_fixup_relocation(&mut relocation),
            _ => unimplemented!(),
        };
        if addend != 0 {
            self.write_relocation_addend(section, &relocation, addend)?;
        }
        self.sections[section.0].relocations.push(relocation);
        Ok(())
    }

    fn write_relocation_addend(
        &mut self,
        section: SectionId,
        relocation: &Relocation,
        addend: i64,
    ) -> Result<()> {
        let data = self.sections[section.0].data_mut();
        let offset = relocation.offset as usize;
        match relocation.size {
            32 => data.write_at(offset, &U32::new(self.endian, addend as u32)),
            64 => data.write_at(offset, &U64::new(self.endian, addend as u64)),
            _ => {
                return Err(Error(format!(
                    "unimplemented relocation addend {:?}",
                    relocation
                )));
            }
        }
        .map_err(|_| {
            Error(format!(
                "invalid relocation offset {}+{} (max {})",
                relocation.offset,
                relocation.size,
                data.len()
            ))
        })
    }

    /// Write the object to a `Vec`.
    pub fn write(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        self.emit(&mut buffer)?;
        Ok(buffer)
    }

    /// Write the object to a `Write` implementation.
    ///
    /// Also flushes the writer.
    ///
    /// It is advisable to use a buffered writer like [`BufWriter`](std::io::BufWriter)
    /// instead of an unbuffered writer like [`File`](std::fs::File).
    pub fn write_stream<W: io::Write>(&self, w: W) -> result::Result<(), Box<dyn error::Error>> {
        let mut stream = StreamingBuffer::new(w);
        self.emit(&mut stream)?;
        stream.result()?;
        stream.into_inner().flush()?;
        Ok(())
    }

    /// Write the object to a `WritableBuffer`.
    pub fn emit(&self, buffer: &mut dyn WritableBuffer) -> Result<()> {
        match self.format {
            #[cfg(feature = "coff")]
            BinaryFormat::Coff => self.coff_write(buffer),
            #[cfg(feature = "elf")]
            BinaryFormat::Elf => self.elf_write(buffer),
            #[cfg(feature = "macho")]
            BinaryFormat::MachO => self.macho_write(buffer),
            _ => unimplemented!(),
        }
    }
}

/// A standard segment kind.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum StandardSegment {
    Text,
    Data,
    Debug,
}

/// A standard section kind.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum StandardSection {
    Text,
    Data,
    ReadOnlyData,
    ReadOnlyDataWithRel,
    ReadOnlyString,
    UninitializedData,
    Tls,
    /// Zero-fill TLS initializers. Unsupported for COFF.
    UninitializedTls,
    /// TLS variable structures. Only supported for Mach-O.
    TlsVariables,
    /// Common data. Only supported for Mach-O.
    Common,
}

impl StandardSection {
    /// Return the section kind of a standard section.
    pub fn kind(self) -> SectionKind {
        match self {
            StandardSection::Text => SectionKind::Text,
            StandardSection::Data => SectionKind::Data,
            StandardSection::ReadOnlyData | StandardSection::ReadOnlyDataWithRel => {
                SectionKind::ReadOnlyData
            }
            StandardSection::ReadOnlyString => SectionKind::ReadOnlyString,
            StandardSection::UninitializedData => SectionKind::UninitializedData,
            StandardSection::Tls => SectionKind::Tls,
            StandardSection::UninitializedTls => SectionKind::UninitializedTls,
            StandardSection::TlsVariables => SectionKind::TlsVariables,
            StandardSection::Common => SectionKind::Common,
        }
    }

    // TODO: remembering to update this is error-prone, can we do better?
    fn all() -> &'static [StandardSection] {
        &[
            StandardSection::Text,
            StandardSection::Data,
            StandardSection::ReadOnlyData,
            StandardSection::ReadOnlyDataWithRel,
            StandardSection::ReadOnlyString,
            StandardSection::UninitializedData,
            StandardSection::Tls,
            StandardSection::UninitializedTls,
            StandardSection::TlsVariables,
            StandardSection::Common,
        ]
    }
}

/// An identifier used to reference a section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SectionId(usize);

/// A section in an object file.
#[derive(Debug)]
pub struct Section<'a> {
    segment: Vec<u8>,
    name: Vec<u8>,
    kind: SectionKind,
    size: u64,
    align: u64,
    data: Cow<'a, [u8]>,
    relocations: Vec<Relocation>,
    symbol: Option<SymbolId>,
    /// Section flags that are specific to each file format.
    pub flags: SectionFlags,
}

impl<'a> Section<'a> {
    /// Try to convert the name to a utf8 string.
    #[inline]
    pub fn name(&self) -> Option<&str> {
        str::from_utf8(&self.name).ok()
    }

    /// Try to convert the segment to a utf8 string.
    #[inline]
    pub fn segment(&self) -> Option<&str> {
        str::from_utf8(&self.segment).ok()
    }

    /// Return true if this section contains zerofill data.
    #[inline]
    pub fn is_bss(&self) -> bool {
        self.kind.is_bss()
    }

    /// Set the data for a section.
    ///
    /// Must not be called for sections that already have data, or that contain uninitialized data.
    pub fn set_data<T>(&mut self, data: T, align: u64)
    where
        T: Into<Cow<'a, [u8]>>,
    {
        debug_assert!(!self.is_bss());
        debug_assert_eq!(align & (align - 1), 0);
        debug_assert!(self.data.is_empty());
        self.data = data.into();
        self.size = self.data.len() as u64;
        self.align = align;
    }

    /// Append data to a section.
    ///
    /// Must not be called for sections that contain uninitialized data.
    pub fn append_data(&mut self, append_data: &[u8], align: u64) -> u64 {
        debug_assert!(!self.is_bss());
        debug_assert_eq!(align & (align - 1), 0);
        if self.align < align {
            self.align = align;
        }
        let align = align as usize;
        let data = self.data.to_mut();
        let mut offset = data.len();
        if offset & (align - 1) != 0 {
            offset += align - (offset & (align - 1));
            data.resize(offset, 0);
        }
        data.extend_from_slice(append_data);
        self.size = data.len() as u64;
        offset as u64
    }

    /// Append unitialized data to a section.
    ///
    /// Must not be called for sections that contain initialized data.
    pub fn append_bss(&mut self, size: u64, align: u64) -> u64 {
        debug_assert!(self.is_bss());
        debug_assert_eq!(align & (align - 1), 0);
        if self.align < align {
            self.align = align;
        }
        let mut offset = self.size;
        if offset & (align - 1) != 0 {
            offset += align - (offset & (align - 1));
            self.size = offset;
        }
        self.size += size;
        offset as u64
    }

    /// Returns the section as-built so far.
    ///
    /// This requires that the section is not a bss section.
    pub fn data(&self) -> &[u8] {
        debug_assert!(!self.is_bss());
        &self.data
    }

    /// Returns the section as-built so far.
    ///
    /// This requires that the section is not a bss section.
    pub fn data_mut(&mut self) -> &mut [u8] {
        debug_assert!(!self.is_bss());
        self.data.to_mut()
    }
}

/// The section where a symbol is defined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SymbolSection {
    /// The section is not applicable for this symbol (such as file symbols).
    None,
    /// The symbol is undefined.
    Undefined,
    /// The symbol has an absolute value.
    Absolute,
    /// The symbol is a zero-initialized symbol that will be combined with duplicate definitions.
    Common,
    /// The symbol is defined in the given section.
    Section(SectionId),
}

impl SymbolSection {
    /// Returns the section id for the section where the symbol is defined.
    ///
    /// May return `None` if the symbol is not defined in a section.
    #[inline]
    pub fn id(self) -> Option<SectionId> {
        if let SymbolSection::Section(id) = self {
            Some(id)
        } else {
            None
        }
    }
}

/// An identifier used to reference a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolId(usize);

/// A symbol in an object file.
#[derive(Debug)]
pub struct Symbol {
    /// The name of the symbol.
    pub name: Vec<u8>,
    /// The value of the symbol.
    ///
    /// If the symbol defined in a section, then this is the section offset of the symbol.
    pub value: u64,
    /// The size of the symbol.
    pub size: u64,
    /// The kind of the symbol.
    pub kind: SymbolKind,
    /// The scope of the symbol.
    pub scope: SymbolScope,
    /// Whether the symbol has weak binding.
    pub weak: bool,
    /// The section containing the symbol.
    pub section: SymbolSection,
    /// Symbol flags that are specific to each file format.
    pub flags: SymbolFlags<SectionId>,
}

impl Symbol {
    /// Try to convert the name to a utf8 string.
    #[inline]
    pub fn name(&self) -> Option<&str> {
        str::from_utf8(&self.name).ok()
    }

    /// Return true if the symbol is undefined.
    #[inline]
    pub fn is_undefined(&self) -> bool {
        self.section == SymbolSection::Undefined
    }

    /// Return true if the symbol is common data.
    ///
    /// Note: does not check for `SymbolSection::Section` with `SectionKind::Common`.
    #[inline]
    pub fn is_common(&self) -> bool {
        self.section == SymbolSection::Common
    }

    /// Return true if the symbol scope is local.
    #[inline]
    pub fn is_local(&self) -> bool {
        self.scope == SymbolScope::Compilation
    }
}

/// A relocation in an object file.
#[derive(Debug)]
pub struct Relocation {
    /// The section offset of the place of the relocation.
    pub offset: u64,
    /// The size in bits of the place of relocation.
    pub size: u8,
    /// The operation used to calculate the result of the relocation.
    pub kind: RelocationKind,
    /// Information about how the result of the relocation operation is encoded in the place.
    pub encoding: RelocationEncoding,
    /// The symbol referred to by the relocation.
    ///
    /// This may be a section symbol.
    pub symbol: SymbolId,
    /// The addend to use in the relocation calculation.
    ///
    /// This may be in addition to an implicit addend stored at the place of the relocation.
    pub addend: i64,
}

/// An identifier used to reference a COMDAT section group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ComdatId(usize);

/// A COMDAT section group.
#[derive(Debug)]
pub struct Comdat {
    /// The COMDAT selection kind.
    ///
    /// This determines the way in which the linker resolves multiple definitions of the COMDAT
    /// sections.
    pub kind: ComdatKind,
    /// The COMDAT symbol.
    ///
    /// If this symbol is referenced, then all sections in the group will be included by the
    /// linker.
    pub symbol: SymbolId,
    /// The sections in the group.
    pub sections: Vec<SectionId>,
}

/// The symbol name mangling scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Mangling {
    /// No symbol mangling.
    None,
    /// Windows COFF symbol mangling.
    Coff,
    /// Windows COFF i386 symbol mangling.
    CoffI386,
    /// ELF symbol mangling.
    Elf,
    /// Mach-O symbol mangling.
    MachO,
}

impl Mangling {
    /// Return the default symboling mangling for the given format and architecture.
    pub fn default(format: BinaryFormat, architecture: Architecture) -> Self {
        match (format, architecture) {
            (BinaryFormat::Coff, Architecture::I386) => Mangling::CoffI386,
            (BinaryFormat::Coff, _) => Mangling::Coff,
            (BinaryFormat::Elf, _) => Mangling::Elf,
            (BinaryFormat::MachO, _) => Mangling::MachO,
            _ => Mangling::None,
        }
    }

    /// Return the prefix to use for global symbols.
    pub fn global_prefix(self) -> Option<u8> {
        match self {
            Mangling::None | Mangling::Elf | Mangling::Coff => None,
            Mangling::CoffI386 | Mangling::MachO => Some(b'_'),
        }
    }
}
