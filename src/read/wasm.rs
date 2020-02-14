//! Support for reading WASM files.
//!
//! Provides `WasmFile` and related types which implement the `Object` trait.
//!
//! Currently implements the minimum required to access DWARF debugging information.
#[cfg(feature = "compression")]
use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::{fmt, slice, str};
use target_lexicon::Architecture;
use wasmparser as wp;

use crate::read::{
    self, Error, FileFlags, Object, ObjectSection, ObjectSegment, Relocation, Result, SectionFlags,
    SectionIndex, SectionKind, Symbol, SymbolFlags, SymbolIndex, SymbolKind, SymbolMap,
    SymbolScope, SymbolSection,
};

const SECTION_CUSTOM: usize = 0;
const SECTION_TYPE: usize = 1;
const SECTION_IMPORT: usize = 2;
const SECTION_FUNCTION: usize = 3;
const SECTION_TABLE: usize = 4;
const SECTION_MEMORY: usize = 5;
const SECTION_GLOBAL: usize = 6;
const SECTION_EXPORT: usize = 7;
const SECTION_START: usize = 8;
const SECTION_ELEMENT: usize = 9;
const SECTION_CODE: usize = 10;
const SECTION_DATA: usize = 11;
const SECTION_DATA_COUNT: usize = 12;
// Update this constant when adding new section id:
const MAX_SECTION_ID: usize = SECTION_DATA_COUNT;

/// A WebAssembly object file.
#[derive(Debug, Default)]
pub struct WasmFile<'data> {
    // All sections, including custom sections.
    sections: Vec<wp::Section<'data>>,
    // Indices into `sections` of sections with a non-zero id.
    id_sections: Box<[Option<usize>; MAX_SECTION_ID + 1]>,
    // Payload of custom section called "name".
    names_data: Option<&'data [u8]>,
    // Whether the file has DWARF information.
    has_debug_symbols: bool,
}

impl<'data> WasmFile<'data> {
    /// Parse the raw wasm data.
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        let module = wp::ModuleReader::new(data).map_err(|_| Error("Invalid WASM header"))?;

        let mut file = WasmFile::default();

        for section in module {
            let section = section.map_err(|_| Error("Invalid WASM section header"))?;

            match section.code {
                wp::SectionCode::Custom { kind, name } => {
                    if kind == wp::CustomSectionKind::Name {
                        file.names_data = Some(section.range().slice(data));
                    } else if name.starts_with(".debug_") {
                        file.has_debug_symbols = true;
                    }
                }
                code => {
                    let id = section_code_to_id(code);
                    file.id_sections[id] = Some(file.sections.len());
                }
            }

            file.sections.push(section);
        }

        Ok(file)
    }
}

impl<'data> read::private::Sealed for WasmFile<'data> {}

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

    #[inline]
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

    #[inline]
    fn symbol_by_index(&self, _index: SymbolIndex) -> Option<Symbol<'data>> {
        // WASM doesn't need or support looking up symbols by index.
        None
    }

    fn symbols(&'file self) -> Self::SymbolIterator {
        WasmSymbolIterator {
            file: self,
            names: self.names_data.and_then(|names| {
                let func = wp::NameSectionReader::new(names, 0)
                    .ok()?
                    .into_iter()
                    .filter_map(|name| name.ok())
                    .find_map(|name| match name {
                        wp::Name::Function(func) => Some(func),
                        _ => None,
                    })?;

                let reader = func.get_map().ok()?;

                Some(NamingIterator { reader }.enumerate())
            }),
        }
    }

    fn dynamic_symbols(&'file self) -> Self::SymbolIterator {
        WasmSymbolIterator {
            file: self,
            names: None,
        }
    }

    fn symbol_map(&self) -> SymbolMap<'data> {
        SymbolMap {
            symbols: Vec::new(),
        }
    }

    fn has_debug_symbols(&self) -> bool {
        self.has_debug_symbols
    }

    #[inline]
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

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

/// A segment of a `WasmFile`.
#[derive(Debug)]
pub struct WasmSegment<'data, 'file> {
    file: &'file WasmFile<'data>,
}

impl<'data, 'file> read::private::Sealed for WasmSegment<'data, 'file> {}

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
    sections: slice::Iter<'file, wp::Section<'data>>,
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
pub struct WasmSection<'data, 'file> {
    section: &'file wp::Section<'data>,
}

impl<'data, 'file> read::private::Sealed for WasmSection<'data, 'file> {}

impl<'data, 'file> ObjectSection<'data> for WasmSection<'data, 'file> {
    type RelocationIterator = WasmRelocationIterator<'data, 'file>;

    #[inline]
    fn index(&self) -> SectionIndex {
        // Note that we treat all custom sections as index 0.
        // This is ok because they are never looked up by index.
        SectionIndex(section_code_to_id(self.section.code))
    }

    #[inline]
    fn address(&self) -> u64 {
        // TODO: figure out if this should be different for code sections
        0
    }

    #[inline]
    fn size(&self) -> u64 {
        let range = self.section.range();
        (range.end - range.start) as u64
    }

    #[inline]
    fn align(&self) -> u64 {
        1
    }

    #[inline]
    fn file_range(&self) -> Option<(u64, u64)> {
        None
    }

    #[inline]
    fn data(&self) -> &'data [u8] {
        let mut reader = self.section.get_binary_reader();
        // TODO: raise a feature request upstream to be able
        // to get remaining slice from a BinaryReader directly.
        reader.read_bytes(reader.bytes_remaining()).unwrap()
    }

    fn data_range(&self, _address: u64, _size: u64) -> Option<&'data [u8]> {
        unimplemented!()
    }

    #[cfg(feature = "compression")]
    #[inline]
    fn uncompressed_data(&self) -> Option<Cow<'data, [u8]>> {
        Some(Cow::from(self.data()))
    }

    #[inline]
    fn name(&self) -> Option<&str> {
        Some(match self.section.code {
            wp::SectionCode::Custom { name, .. } => name,
            wp::SectionCode::Type => "<type>",
            wp::SectionCode::Import => "<import>",
            wp::SectionCode::Function => "<function>",
            wp::SectionCode::Table => "<table>",
            wp::SectionCode::Memory => "<memory>",
            wp::SectionCode::Global => "<global>",
            wp::SectionCode::Export => "<export>",
            wp::SectionCode::Start => "<start>",
            wp::SectionCode::Element => "<element>",
            wp::SectionCode::Code => "<code>",
            wp::SectionCode::Data => "<data>",
            wp::SectionCode::DataCount => "<data_count>",
        })
    }

    #[inline]
    fn segment_name(&self) -> Option<&str> {
        None
    }

    #[inline]
    fn kind(&self) -> SectionKind {
        SectionKind::Unknown
    }

    #[inline]
    fn relocations(&self) -> WasmRelocationIterator<'data, 'file> {
        WasmRelocationIterator::default()
    }

    #[inline]
    fn flags(&self) -> SectionFlags {
        SectionFlags::None
    }
}

// Upstream NamingReader doesn't have Debug derived,
// so we provide own wrapper that also serves as an Iterator.
struct NamingIterator<'data> {
    reader: wp::NamingReader<'data>,
}

impl fmt::Debug for NamingIterator<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NamingIterator")
            .field("count", &self.reader.get_count())
            .finish()
    }
}

impl<'data> Iterator for NamingIterator<'data> {
    type Item = wp::Naming<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        self.reader.read().ok()
    }
}

/// An iterator over the symbols of a `WasmFile`.
#[derive(Debug)]
pub struct WasmSymbolIterator<'data, 'file> {
    file: &'file WasmFile<'data>,
    names: Option<core::iter::Enumerate<NamingIterator<'data>>>,
}

impl<'data, 'file> Iterator for WasmSymbolIterator<'data, 'file> {
    type Item = (SymbolIndex, Symbol<'data>);

    fn next(&mut self) -> Option<Self::Item> {
        let (index, naming) = self.names.as_mut()?.next()?;
        Some((
            SymbolIndex(index),
            Symbol {
                name: Some(naming.name),
                address: naming.index as u64,
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
#[derive(Debug, Default)]
pub struct WasmRelocationIterator<'data, 'file>(PhantomData<(&'data (), &'file ())>);

impl<'data, 'file> Iterator for WasmRelocationIterator<'data, 'file> {
    type Item = (u64, Relocation);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

fn section_code_to_id(code: wp::SectionCode) -> usize {
    match code {
        wp::SectionCode::Custom { .. } => SECTION_CUSTOM,
        wp::SectionCode::Type => SECTION_TYPE,
        wp::SectionCode::Import => SECTION_IMPORT,
        wp::SectionCode::Function => SECTION_FUNCTION,
        wp::SectionCode::Table => SECTION_TABLE,
        wp::SectionCode::Memory => SECTION_MEMORY,
        wp::SectionCode::Global => SECTION_GLOBAL,
        wp::SectionCode::Export => SECTION_EXPORT,
        wp::SectionCode::Start => SECTION_START,
        wp::SectionCode::Element => SECTION_ELEMENT,
        wp::SectionCode::Code => SECTION_CODE,
        wp::SectionCode::Data => SECTION_DATA,
        wp::SectionCode::DataCount => SECTION_DATA_COUNT,
    }
}
