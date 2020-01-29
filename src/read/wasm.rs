//! Support for reading WASM files.
//!
//! Provides `WasmFile` and related types which implement the `Object` trait.
//!
//! Currently implements the minimum required to access DWARF debugging information.
use crate::alloc::borrow::Cow;
use crate::alloc::vec::Vec;
use core::{slice, str};
use target_lexicon::Architecture;

use crate::read::{
    FileFlags, Object, ObjectSection, ObjectSegment, Relocation, SectionFlags, SectionIndex,
    SectionKind, Symbol, SymbolFlags, SymbolIndex, SymbolKind, SymbolMap, SymbolScope,
    SymbolSection,
};

const SECTION_TYPE: u8 = 1;
const SECTION_IMPORT: u8 = 2;
const SECTION_FUNCTION: u8 = 3;
const SECTION_TABLE: u8 = 4;
const SECTION_MEMORY: u8 = 5;
const SECTION_GLOBAL: u8 = 6;
const SECTION_EXPORT: u8 = 7;
const SECTION_START: u8 = 8;
const SECTION_ELEMENT: u8 = 9;
const SECTION_CODE: u8 = 10;
const SECTION_DATA: u8 = 11;

/// A WebAssembly object file.
#[derive(Debug)]
pub struct WasmFile<'data> {
    // All sections, including custom sections.
    sections: Vec<SectionHeader<'data>>,
    // Indices into `sections` of sections with a non-zero id.
    id_sections: Vec<Option<usize>>,
    // Index into `sections` of custom section called "name".
    name: &'data [u8],
}

impl<'data> WasmFile<'data> {
    /// Parse the raw wasm data.
    pub fn parse(mut data: &'data [u8]) -> Result<Self, &'static str> {
        let header = read_bytes(&mut data, 8).ok_or("Invalid WASM header size")?;
        if header != [0x00, b'a', b's', b'm', 0x01, 0x00, 0x00, 0x00] {
            return Err("Unsupported WASM header");
        }

        let mut sections = Vec::new();
        let mut id_sections = Vec::with_capacity(16);
        let mut name = &[][..];

        while let Some(id) = read_byte(&mut data) {
            // TODO: validate section order
            let mut section_data = read_u32_bytes(&mut data).ok_or("Invalid section size")?;
            let section_name;
            if id == 0 {
                let section_name_bytes =
                    read_u32_bytes(&mut section_data).ok_or("Invalid section name size")?;
                section_name =
                    str::from_utf8(section_name_bytes).map_err(|_| "Invalid section name")?;
                if section_name == "name" {
                    name = section_data;
                }
            } else {
                section_name = match id {
                    SECTION_TYPE => "<type>",
                    SECTION_IMPORT => "<import>",
                    SECTION_FUNCTION => "<function>",
                    SECTION_TABLE => "<table>",
                    SECTION_MEMORY => "<memory>",
                    SECTION_GLOBAL => "<global>",
                    SECTION_EXPORT => "<export>",
                    SECTION_START => "<start>",
                    SECTION_ELEMENT => "<element>",
                    SECTION_CODE => "<code>",
                    SECTION_DATA => "<data>",
                    _ => "<unknown>",
                };
                if id_sections.len() <= id as usize {
                    id_sections.resize(id as usize + 1, None);
                }
                id_sections[id as usize] = Some(sections.len());
            }
            sections.push(SectionHeader {
                index: SectionIndex(id as usize),
                name: section_name,
                data: section_data,
            });
        }

        Ok(WasmFile {
            sections,
            id_sections,
            name,
        })
    }
}

impl<'data, 'file> Object<'data, 'file> for WasmFile<'data>
where
    'data: 'file,
{
    type Segment = WasmSegment<'data, 'file>;
    type SegmentIterator = WasmSegmentIterator<'data, 'file>;
    type Section = WasmSection<'data, 'file>;
    type SectionIterator = WasmSectionIterator<'data, 'file>;
    type SymbolIterator = WasmSymbolIterator<'data, 'file>;

    #[inline]
    fn architecture(&self) -> Architecture {
        Architecture::Wasm32
    }

    #[inline]
    fn is_little_endian(&self) -> bool {
        true
    }

    #[inline]
    fn is_64(&self) -> bool {
        false
    }

    fn segments(&'file self) -> Self::SegmentIterator {
        WasmSegmentIterator { file: self }
    }

    fn entry(&'file self) -> u64 {
        // TODO: Convert start section to an address.
        0
    }

    fn section_by_name(&'file self, section_name: &str) -> Option<WasmSection<'data, 'file>> {
        self.sections()
            .find(|section| section.name() == Some(section_name))
    }

    fn section_by_index(&'file self, index: SectionIndex) -> Option<WasmSection<'data, 'file>> {
        let id_section = self.id_sections.get(index.0)?;
        let section = self.sections.get((*id_section)?)?;
        Some(WasmSection { section })
    }

    fn sections(&'file self) -> Self::SectionIterator {
        WasmSectionIterator {
            sections: self.sections.iter(),
        }
    }

    fn symbol_by_index(&self, _index: SymbolIndex) -> Option<Symbol<'data>> {
        // WASM doesn't need or support looking up symbols by index.
        None
    }

    fn symbols(&'file self) -> Self::SymbolIterator {
        let mut data = find_subsection(self.name, 1).unwrap_or(&[]);
        let length = read_u32(&mut data).unwrap_or(0) as usize;
        WasmSymbolIterator {
            file: self,
            index: 0,
            length,
            data,
        }
    }

    fn dynamic_symbols(&'file self) -> Self::SymbolIterator {
        WasmSymbolIterator {
            file: self,
            index: 0,
            length: 0,
            data: &[],
        }
    }

    fn symbol_map(&self) -> SymbolMap<'data> {
        SymbolMap {
            symbols: Vec::new(),
        }
    }

    fn has_debug_symbols(&self) -> bool {
        // We ignore the "name" section, and use this to mean whether the wasm
        // has DWARF.
        self.sections.iter().any(|s| s.name.starts_with(".debug_"))
    }

    fn flags(&self) -> FileFlags {
        FileFlags::None
    }
}

/// An iterator over the segments of a `WasmFile`.
#[derive(Debug)]
pub struct WasmSegmentIterator<'data, 'file> {
    file: &'file WasmFile<'data>,
}

impl<'data, 'file> Iterator for WasmSegmentIterator<'data, 'file> {
    type Item = WasmSegment<'data, 'file>;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

/// A segment of a `WasmFile`.
#[derive(Debug)]
pub struct WasmSegment<'data, 'file> {
    file: &'file WasmFile<'data>,
}

impl<'data, 'file> ObjectSegment<'data> for WasmSegment<'data, 'file> {
    #[inline]
    fn address(&self) -> u64 {
        unreachable!()
    }

    #[inline]
    fn size(&self) -> u64 {
        unreachable!()
    }

    #[inline]
    fn align(&self) -> u64 {
        unreachable!()
    }

    #[inline]
    fn file_range(&self) -> (u64, u64) {
        unreachable!()
    }

    fn data(&self) -> &'data [u8] {
        unreachable!()
    }

    fn data_range(&self, _address: u64, _size: u64) -> Option<&'data [u8]> {
        unreachable!()
    }

    #[inline]
    fn name(&self) -> Option<&str> {
        unreachable!()
    }
}

/// An iterator over the sections of a `WasmFile`.
#[derive(Debug)]
pub struct WasmSectionIterator<'data, 'file> {
    sections: slice::Iter<'file, SectionHeader<'data>>,
}

impl<'data, 'file> Iterator for WasmSectionIterator<'data, 'file> {
    type Item = WasmSection<'data, 'file>;

    fn next(&mut self) -> Option<Self::Item> {
        let section = self.sections.next()?;
        Some(WasmSection { section })
    }
}

/// A section of a `WasmFile`.
#[derive(Debug)]
struct SectionHeader<'data> {
    index: SectionIndex,
    // Name is only valid for custom sections.
    name: &'data str,
    data: &'data [u8],
}

/// A section of a `WasmFile`.
#[derive(Debug)]
pub struct WasmSection<'data, 'file> {
    section: &'file SectionHeader<'data>,
}

impl<'data, 'file> ObjectSection<'data> for WasmSection<'data, 'file> {
    type RelocationIterator = WasmRelocationIterator;

    #[inline]
    fn index(&self) -> SectionIndex {
        // Note that we treat all custom sections as index 0.
        // This is ok because they are never looked up by index.
        self.section.index
    }

    #[inline]
    fn address(&self) -> u64 {
        // TODO: figure out if this should be different for code sections
        0
    }

    #[inline]
    fn size(&self) -> u64 {
        self.section.data.len() as u64
    }

    #[inline]
    fn align(&self) -> u64 {
        1
    }

    #[inline]
    fn file_range(&self) -> Option<(u64, u64)> {
        None
    }

    fn data(&self) -> &'data [u8] {
        self.section.data
    }

    fn data_range(&self, _address: u64, _size: u64) -> Option<&'data [u8]> {
        unimplemented!()
    }

    #[inline]
    fn uncompressed_data(&self) -> Cow<'data, [u8]> {
        Cow::from(self.data())
    }

    fn name(&self) -> Option<&str> {
        Some(self.section.name)
    }

    #[inline]
    fn segment_name(&self) -> Option<&str> {
        None
    }

    fn kind(&self) -> SectionKind {
        SectionKind::Unknown
    }

    fn relocations(&self) -> WasmRelocationIterator {
        WasmRelocationIterator
    }

    fn flags(&self) -> SectionFlags {
        SectionFlags::None
    }
}

/// An iterator over the symbols of a `WasmFile`.
#[derive(Debug)]
pub struct WasmSymbolIterator<'data, 'file> {
    file: &'file WasmFile<'data>,
    index: usize,
    length: usize,
    data: &'data [u8],
}

impl<'data, 'file> Iterator for WasmSymbolIterator<'data, 'file> {
    type Item = (SymbolIndex, Symbol<'data>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.length {
            return None;
        }
        let func = read_u32(&mut self.data)?;
        let name = read_u32_bytes(&mut self.data)?;
        let index = SymbolIndex(self.index);
        self.index += 1;
        Some((
            index,
            Symbol {
                name: str::from_utf8(name).ok(),
                address: func as u64,
                size: 0,
                kind: SymbolKind::Text,
                // TODO: maybe treat each function as a section?
                section: SymbolSection::Unknown,
                weak: false,
                scope: SymbolScope::Unknown,
                flags: SymbolFlags::None,
            },
        ))
    }
}

/// An iterator over the relocations in a `WasmSection`.
#[derive(Debug)]
pub struct WasmRelocationIterator;

impl Iterator for WasmRelocationIterator {
    type Item = (u64, Relocation);

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

fn find_subsection(mut bytes: &[u8], match_id: u8) -> Option<&[u8]> {
    while let Some(id) = read_byte(&mut bytes) {
        let subsection = read_u32_bytes(&mut bytes)?;
        if id == match_id {
            return Some(subsection);
        }
    }
    None
}

fn read_u32_bytes<'data>(bytes: &mut &'data [u8]) -> Option<&'data [u8]> {
    let size = read_u32(bytes)? as usize;
    read_bytes(bytes, size)
}

fn read_bytes<'data>(bytes: &mut &'data [u8], size: usize) -> Option<&'data [u8]> {
    let head = bytes.get(..size)?;
    let tail = bytes.get(size..)?;
    *bytes = tail;
    Some(head)
}

fn read_byte(bytes: &mut &[u8]) -> Option<u8> {
    let head = *bytes.get(0)?;
    *bytes = bytes.get(1..)?;
    Some(head)
}

// Read an intermediate leb128 byte.
// Updates the value.
// Returns the value if the continuation bit is not set.
// Returns None if input is empty.
macro_rules! read_u7 {
    ($input:expr, $value:expr, $shift:expr) => {
        let byte = read_byte($input)?;
        $value |= u32::from(byte & 0x7f) << $shift;
        if byte & 0x80 == 0 {
            return Some($value);
        }
    };
}

// Read a final leb128 byte.
// Returns the value.
// Returns None if input is empty or more than `$bits` bits are set.
macro_rules! read_u7_final {
    ($input:expr, $value:expr, $shift:expr, $bits:expr) => {{
        let byte = read_byte($input)?;
        if byte >> $bits == 0 {
            Some($value | u32::from(byte) << $shift)
        } else {
            None
        }
    }};
}

// leb128
fn read_u32(bytes: &mut &[u8]) -> Option<u32> {
    let mut value = 0;
    read_u7!(bytes, value, 0);
    read_u7!(bytes, value, 7);
    read_u7!(bytes, value, 14);
    read_u7!(bytes, value, 21);
    read_u7_final!(bytes, value, 28, 4)
}
