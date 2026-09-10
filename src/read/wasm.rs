//! Support for reading Wasm files.
//!
//! [`WasmFile`] implements the [`Object`] trait for Wasm files.
use crate::SkipDebugList;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ops::Range;
use core::{slice, str};
use wasmparser as wp;

use crate::read::{
    self, Architecture, ComdatKind, CompressedData, CompressedFileRange, Error, FileFlags,
    NoDynamicRelocationIterator, NoExportIterator, NoImportIterator, NoImportLibraryIterator,
    Object, ObjectComdat, ObjectKind, ObjectSection, ObjectSegment, ObjectSymbol,
    ObjectSymbolTable, Permissions, ReadError, ReadRef, Relocation, RelocationMap, Result,
    SectionFlags, SectionIndex, SectionKind, SegmentFlags, SymbolFlags, SymbolIndex, SymbolKind,
    SymbolScope, SymbolSection,
};
use crate::{RelocationEncoding, RelocationFlags, RelocationKind, RelocationTarget};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum SectionId {
    Unknown = 255,
    Custom = 0,
    Type = 1,
    Import = 2,
    Function = 3,
    Table = 4,
    Memory = 5,
    Global = 6,
    Export = 7,
    Start = 8,
    Element = 9,
    Code = 10,
    Data = 11,
    DataCount = 12,
    Tag = 13,
}
// Update this constant when adding new section id:
const MAX_SECTION_ID: usize = SectionId::Tag as usize;
// Section indices for data segments start after the Wasm section id space.
const DATA_SEGMENT_SECTION_INDEX_BASE: usize = MAX_SECTION_ID + 1;

/// The index of a section in the Wasm binary.
///
/// This is assigned to sections in the order they appear, and includes custom
/// sections. It is different from the `SectionIndex` used in the unified API.
//
// TODO: It's probably better to use this as the `SectionIndex` too
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WasmSectionIndex(u32);

/// The index of a segment in the data section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WasmDataSegmentIndex(u32);

impl WasmDataSegmentIndex {
    fn section_index(self) -> SectionIndex {
        SectionIndex(DATA_SEGMENT_SECTION_INDEX_BASE + self.0 as usize)
    }

    fn from_section_index(index: SectionIndex) -> Option<WasmDataSegmentIndex> {
        Some(WasmDataSegmentIndex(
            index
                .0
                .checked_sub(DATA_SEGMENT_SECTION_INDEX_BASE)?
                .try_into()
                .ok()?,
        ))
    }
}

/// A WebAssembly object file.
#[derive(Debug)]
pub struct WasmFile<'data, R = &'data [u8]> {
    data: SkipDebugList<&'data [u8]>,
    has_memory64: bool,
    // All sections, including custom sections, indexed by `WasmSectionIndex`.
    sections: Vec<SectionHeader<'data>>,
    // Map from `SectionId` to `WasmSectionIndex`.
    id_sections: Box<[Option<WasmSectionIndex>; MAX_SECTION_ID + 1]>,
    // Parsed `reloc.*` custom sections, keyed by the binary index of the target section.
    relocations: Vec<RelocSection>,
    // Data segments parsed from the `data` section.
    data_segments: Vec<WasmDataSegmentInternal<'data>>,
    // Whether the file has a `linking` custom section (relocatable object).
    has_linking: bool,
    // Whether the file has DWARF information.
    has_debug_symbols: bool,
    // Symbols collected from imports, exports, code and name sections.
    symbols: Vec<WasmSymbolInternal<'data>>,
    // Address of the function body for the entry point.
    entry: u64,
    marker: PhantomData<R>,
}

#[derive(Debug)]
struct RelocSection {
    target: WasmSectionIndex,
    entries: Vec<wp::RelocationEntry>,
}

impl RelocSection {
    /// Return the entries in the given offset range.
    ///
    /// `range` must be `0..u64::MAX` unless the target is the Wasm data section.
    fn entries_in_range(&self, range: &Range<u64>) -> &[wp::RelocationEntry] {
        if *range == (0..u64::MAX) {
            return &self.entries[..];
        }
        let start = self
            .entries
            .partition_point(|entry| u64::from(entry.offset) < range.start);
        let end = self
            .entries
            .partition_point(|entry| u64::from(entry.offset) < range.end);
        &self.entries[start..end]
    }
}

#[derive(Debug)]
struct WasmDataSegmentInternal<'data> {
    /// Metadata from the `SegmentInfo` subsection of `linking`, if present.
    info: Option<wp::Segment<'data>>,
    /// The address of the segment in linear memory (for active segments), or 0.
    address: u64,
    /// Whether this is a passive (non-active) data segment.
    is_passive: bool,
    /// File offset of `data` within the wasm module.
    file_offset: u64,
    /// Offset of `data` within the section.
    section_offset: u64,
    /// Raw bytes of the segment.
    data: &'data [u8],
}

impl<'data> WasmDataSegmentInternal<'data> {
    fn name(&self) -> &'data str {
        self.info.map(|info| info.name).unwrap_or("")
    }

    fn align(&self) -> u64 {
        match self.info {
            Some(info) => 1u64.checked_shl(info.alignment).unwrap_or(1),
            None => 1,
        }
    }

    fn flags(&self) -> crate::wasm::SegmentFlags {
        crate::wasm::SegmentFlags(self.info.map(|info| info.flags.bits()).unwrap_or(0))
    }

    fn section_kind(&self) -> SectionKind {
        let Some(info) = self.info else {
            return SectionKind::Data;
        };

        if info.name == ".tbss" || info.name.starts_with(".tbss.") {
            SectionKind::UninitializedTls
        } else if info.flags.contains(wp::SegmentFlags::TLS) {
            SectionKind::Tls
        } else if info.flags.contains(wp::SegmentFlags::STRINGS) {
            SectionKind::ReadOnlyString
        } else if info.name == ".rodata" || info.name.starts_with(".rodata.") {
            SectionKind::ReadOnlyData
        } else if info.name == ".bss" || info.name.starts_with(".bss.") {
            SectionKind::UninitializedData
        } else {
            SectionKind::Data
        }
    }
}

#[derive(Debug)]
struct SectionHeader<'data> {
    id: SectionId,
    range: Range<usize>,
    name: &'data str,
}

#[derive(Clone)]
enum LocalFunctionKind {
    Unknown,
    Exported,
}

impl<T> ReadError<T> for wasmparser::Result<T> {
    fn read_error(self, error: &'static str) -> Result<T> {
        self.map_err(|_| Error(error))
    }
}

impl<'data, R: ReadRef<'data>> WasmFile<'data, R> {
    /// Parse the raw wasm data.
    pub fn parse(data: R) -> Result<Self> {
        let len = data.len().read_error("Unknown Wasm file size")?;
        let data = data.read_bytes_at(0, len).read_error("Wasm read failed")?;
        let parser = wp::Parser::new(0).parse_all(data);

        let mut file = WasmFile {
            data: SkipDebugList(data),
            has_memory64: false,
            sections: Vec::new(),
            id_sections: Default::default(),
            relocations: Vec::new(),
            data_segments: Vec::new(),
            has_linking: false,
            has_debug_symbols: false,
            symbols: Vec::new(),
            entry: 0,
            marker: PhantomData,
        };

        let mut main_file_symbol = Some(WasmSymbolInternal {
            name: "",
            address: 0,
            size: 0,
            kind: SymbolKind::File,
            section: SymbolSection::None,
            scope: SymbolScope::Compilation,
            weak: false,
        });

        let mut entry_func_id = None;
        let mut code_range_start = 0;
        let mut imports_section = None;
        let mut exports = None;
        let mut names = None;
        let mut symbols = None;
        let mut segment_infos: Vec<wp::Segment<'data>> = Vec::new();

        // Function kind for each function section entry.
        let mut local_func_kinds = Vec::new();
        // Address range of each code section entry.
        let mut code_ranges = Vec::new();
        // Value of each global section entry if the global is a constant integer.
        let mut global_values = Vec::new();

        for payload in parser {
            let payload = payload.read_error("Invalid Wasm section header")?;

            match payload {
                wp::Payload::Version { encoding, .. } => {
                    if encoding != wp::Encoding::Module {
                        return Err(Error("Unsupported Wasm encoding"));
                    }
                }
                wp::Payload::TypeSection(section) => {
                    file.add_section(SectionId::Type, section.range(), "");
                }
                wp::Payload::ImportSection(section) => {
                    file.add_section(SectionId::Import, section.range(), "");
                    imports_section = Some(section);
                }
                wp::Payload::FunctionSection(section) => {
                    file.add_section(SectionId::Function, section.range(), "");
                    local_func_kinds =
                        vec![LocalFunctionKind::Unknown; section.into_iter().count()];
                }
                wp::Payload::TableSection(section) => {
                    file.add_section(SectionId::Table, section.range(), "");
                }
                wp::Payload::MemorySection(section) => {
                    file.add_section(SectionId::Memory, section.range(), "");
                    for memory in section {
                        let memory = memory.read_error("Couldn't read a memory item")?;
                        file.has_memory64 |= memory.memory64;
                    }
                }
                wp::Payload::GlobalSection(section) => {
                    file.add_section(SectionId::Global, section.range(), "");
                    for global in section {
                        let global = global.read_error("Couldn't read a global item")?;
                        let mut address = None;
                        if !global.ty.mutable {
                            // There should be exactly one instruction.
                            let init = global.init_expr.get_operators_reader().read();
                            address = match init.read_error("Couldn't read a global init expr")? {
                                wp::Operator::I32Const { value } => Some(value as u32 as u64),
                                wp::Operator::I64Const { value } => Some(value as u64),
                                _ => None,
                            };
                        }
                        global_values.push(address);
                    }
                }
                wp::Payload::ExportSection(section) => {
                    file.add_section(SectionId::Export, section.range(), "");
                    exports = Some(section);
                }
                wp::Payload::StartSection { func, range, .. } => {
                    file.add_section(SectionId::Start, range, "");
                    entry_func_id = Some(func);
                }
                wp::Payload::ElementSection(section) => {
                    file.add_section(SectionId::Element, section.range(), "");
                }
                wp::Payload::CodeSectionStart { range, .. } => {
                    code_range_start = range.start;
                    file.add_section(SectionId::Code, range, "");
                }
                wp::Payload::CodeSectionEntry(body) => {
                    let range = body.range();
                    let address = range.start as u64 - code_range_start as u64;
                    let size = (range.end - range.start) as u64;
                    code_ranges.push((address, size));
                }
                wp::Payload::DataSection(section) => {
                    let section_range = section.range();
                    file.add_section(SectionId::Data, section_range.clone(), "");
                    for segment in section.clone() {
                        let segment = segment.read_error("Couldn't read a data segment")?;
                        let mut address = 0u64;
                        let mut is_passive = false;
                        match &segment.kind {
                            wp::DataKind::Active { offset_expr, .. } => {
                                let init = offset_expr.get_operators_reader().read();
                                address = match init
                                    .read_error("Couldn't read a data segment offset expr")?
                                {
                                    wp::Operator::I32Const { value } => value as u32 as u64,
                                    wp::Operator::I64Const { value } => value as u64,
                                    _ => 0,
                                };
                            }
                            wp::DataKind::Passive => {
                                is_passive = true;
                            }
                        }
                        let file_offset = (segment.range.end - segment.data.len()) as u64;
                        let section_offset = file_offset - section_range.start as u64;
                        file.data_segments.push(WasmDataSegmentInternal {
                            info: None,
                            address,
                            is_passive,
                            file_offset,
                            section_offset,
                            data: segment.data,
                        });
                    }
                }
                wp::Payload::DataCountSection { range, .. } => {
                    file.add_section(SectionId::DataCount, range, "");
                }
                wp::Payload::TagSection(section) => {
                    file.add_section(SectionId::Tag, section.range(), "");
                }
                wp::Payload::UnknownSection { range, .. } => {
                    // TODO: report id
                    file.add_section(SectionId::Unknown, range, "");
                }
                wp::Payload::CustomSection(section) => {
                    let name = section.name();
                    let size = section.data().len();
                    let mut range = section.range();
                    range.start = range.end - size;
                    file.add_section(SectionId::Custom, range, name);
                    if name == "name" {
                        let reader = wp::BinaryReader::new(section.data(), section.data_offset());
                        names = Some(wp::NameSectionReader::new(reader));
                    } else if name == "linking" {
                        // https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md
                        file.has_linking = true;
                        let reader = wp::BinaryReader::new(section.data(), section.data_offset());
                        let linking = wp::LinkingSectionReader::new(reader)
                            .read_error("Invalid Wasm linking section")?;
                        for subsection in linking {
                            let subsection =
                                subsection.read_error("Invalid Wasm linking subsection")?;
                            match subsection {
                                wp::Linking::SymbolTable(s) => {
                                    symbols = Some(s);
                                }
                                wp::Linking::SegmentInfo(map) => {
                                    for segment in map {
                                        let segment = segment
                                            .read_error("Invalid Wasm linking SegmentInfo entry")?;
                                        segment_infos.push(segment);
                                    }
                                }
                                _ => {}
                            }
                        }
                    } else if name.strip_prefix("reloc.").is_some() {
                        // https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md#relocation-sections
                        let reader = wp::BinaryReader::new(section.data(), section.data_offset());
                        let reloc = wp::RelocSectionReader::new(reader)
                            .read_error("Invalid Wasm reloc section")?;
                        let target = WasmSectionIndex(reloc.section_index());
                        let mut entries = Vec::new();
                        for entry in reloc.entries() {
                            let entry = entry.read_error("Invalid Wasm reloc entry")?;
                            entries.push(entry);
                        }
                        if let Some(section) = file.sections.get(target.0 as usize) {
                            if section.id == SectionId::Data {
                                // Sort so that we can binary search for data segments.
                                entries.sort_by_key(|entry| entry.offset);
                            }
                        }
                        file.relocations.push(RelocSection { target, entries });
                    } else if name.starts_with(".debug_") {
                        file.has_debug_symbols = true;
                    }
                }
                _ => {}
            }
        }

        // Apply any `SegmentInfo` entries collected from the `linking` section to the already-parsed data segments.
        for (i, info) in segment_infos.into_iter().enumerate() {
            if let Some(slot) = file.data_segments.get_mut(i) {
                slot.info = Some(info);
            }
        }

        let mut import_func_names = Vec::new();
        let mut import_global_names = Vec::new();
        if let Some(imports_section) = imports_section {
            let mut last_module_name = None;

            for imports in imports_section {
                let imports = imports.read_error("Couldn't read an imports item")?;
                let add_import = &mut |module, ty, name| {
                    let kind = match ty {
                        wp::TypeRef::Func(_) | wp::TypeRef::FuncExact(_) => {
                            import_func_names.push(name);
                            SymbolKind::Text
                        }
                        wp::TypeRef::Memory(memory) => {
                            file.has_memory64 |= memory.memory64;
                            SymbolKind::Data
                        }
                        wp::TypeRef::Global(_) => {
                            import_global_names.push(name);
                            SymbolKind::Data
                        }
                        wp::TypeRef::Table(_) => SymbolKind::Data,
                        wp::TypeRef::Tag(_) => SymbolKind::Unknown,
                    };

                    if symbols.is_some() {
                        // We have a symbol table, so we don't need to add symbols for imports.
                        // TODO: never add symbols for imports. Return them via Object::imports instead.
                        return;
                    }

                    if last_module_name != Some(module) {
                        file.symbols.push(WasmSymbolInternal {
                            name: module,
                            address: 0,
                            size: 0,
                            kind: SymbolKind::File,
                            section: SymbolSection::None,
                            scope: SymbolScope::Dynamic,
                            weak: false,
                        });
                        last_module_name = Some(module);
                    }

                    file.symbols.push(WasmSymbolInternal {
                        name,
                        address: 0,
                        size: 0,
                        kind,
                        section: SymbolSection::Undefined,
                        scope: SymbolScope::Dynamic,
                        weak: false,
                    });
                };
                match imports {
                    wp::Imports::Single(_, import) => {
                        add_import(import.module, import.ty, import.name);
                    }
                    wp::Imports::Compact1 { module, items } => {
                        for item in items {
                            let item = item.read_error("Couldn't read an imports item")?;
                            add_import(module, item.ty, item.name);
                        }
                    }
                    wp::Imports::Compact2 { module, ty, names } => {
                        for name in names {
                            let name = name.read_error("Couldn't read an imports name")?;
                            add_import(module, ty, name);
                        }
                    }
                }
            }
        }

        // Bias to apply to function indices when accessing `local_func_kinds` and `code_ranges`.
        let local_func_base = import_func_names.len() as u32;
        // Bias to apply to global indices when accessing `global_values`.
        let local_global_base = import_global_names.len() as u32;

        if let Some(entry_func_id) = entry_func_id {
            if let Some(local_func_index) = entry_func_id.checked_sub(local_func_base) {
                if let Some(range) = code_ranges.get(local_func_index as usize) {
                    file.entry = range.0;
                }
            }
        }

        if let Some(symbols) = symbols {
            // We have a symbol table, so we don't need to add symbols for locals or exports.
            // These sections shouldn't be present at the same time as a symbol table anyway.
            // TODO: never add symbols for exports. Return them via Object::exports instead.
            exports = None;
            names = None;

            for symbol in symbols {
                let symbol = symbol.read_error("Invalid Wasm linking symbol")?;
                let flags = match symbol {
                    wp::SymbolInfo::Func { flags, .. } => flags,
                    wp::SymbolInfo::Data { flags, .. } => flags,
                    wp::SymbolInfo::Global { flags, .. } => flags,
                    wp::SymbolInfo::Section { flags, .. } => flags,
                    wp::SymbolInfo::Event { flags, .. } => flags,
                    wp::SymbolInfo::Table { flags, .. } => flags,
                };
                let kind = if flags.contains(wp::SymbolFlags::TLS) {
                    SymbolKind::Tls
                } else {
                    match symbol {
                        wp::SymbolInfo::Func { .. } => SymbolKind::Text,
                        wp::SymbolInfo::Data { .. } => SymbolKind::Data,
                        wp::SymbolInfo::Global { .. } => SymbolKind::Data,
                        wp::SymbolInfo::Section { .. } => SymbolKind::Section,
                        wp::SymbolInfo::Event { .. } => SymbolKind::Unknown,
                        wp::SymbolInfo::Table { .. } => SymbolKind::Data,
                    }
                };
                let section = if flags.contains(wp::SymbolFlags::UNDEFINED) {
                    SymbolSection::Undefined
                } else if flags.contains(wp::SymbolFlags::ABSOLUTE) {
                    SymbolSection::Absolute
                } else {
                    match symbol {
                        wp::SymbolInfo::Func { .. } => {
                            SymbolSection::Section(SectionIndex(SectionId::Code as usize))
                        }
                        wp::SymbolInfo::Data {
                            symbol: Some(data), ..
                        } => {
                            if (data.index as usize) >= file.data_segments.len() {
                                return Err(Error("Invalid Wasm data symbol segment index"));
                            }
                            SymbolSection::Section(WasmDataSegmentIndex(data.index).section_index())
                        }
                        _ => {
                            // TODO: anything that is defined should have a known section.
                            // Additionally, address and size should be within this section.
                            SymbolSection::Unknown
                        }
                    }
                };
                let scope = if flags.contains(wp::SymbolFlags::BINDING_LOCAL) {
                    SymbolScope::Compilation
                } else if flags.contains(wp::SymbolFlags::VISIBILITY_HIDDEN) {
                    SymbolScope::Linkage
                } else {
                    SymbolScope::Dynamic
                };
                let weak = flags.contains(wp::SymbolFlags::BINDING_WEAK);

                let mut address = 0;
                let mut size = 0;
                let name = match symbol {
                    wp::SymbolInfo::Func {
                        index, mut name, ..
                    } => {
                        if let Some(local_func_index) = index.checked_sub(local_func_base) {
                            if let Some(range) = code_ranges.get(local_func_index as usize).copied()
                            {
                                address = range.0;
                                size = range.1;
                            }
                        } else {
                            if !flags.contains(wp::SymbolFlags::EXPLICIT_NAME) {
                                name = Some(import_func_names[index as usize]);
                            }
                        }
                        name
                    }
                    wp::SymbolInfo::Data { name, symbol, .. } => {
                        if let Some(symbol) = symbol {
                            // Offset and size within the data segment, which is exposed as a section.
                            address = symbol.offset.into();
                            size = symbol.size.into();
                        }
                        Some(name)
                    }
                    wp::SymbolInfo::Section { .. } => {
                        // TODO: find the section name
                        None
                    }
                    wp::SymbolInfo::Global {
                        index, mut name, ..
                    } => {
                        if let Some(local_global_index) = index.checked_sub(local_global_base) {
                            if let Some(Some(value)) =
                                global_values.get(local_global_index as usize).copied()
                            {
                                address = value;
                            }
                        } else {
                            if !flags.contains(wp::SymbolFlags::EXPLICIT_NAME) {
                                name = import_global_names.get(index as usize).copied()
                            }
                        }
                        name
                    }
                    wp::SymbolInfo::Event { name, .. } | wp::SymbolInfo::Table { name, .. } => name,
                };

                file.symbols.push(WasmSymbolInternal {
                    name: name.unwrap_or(""),
                    address,
                    size,
                    kind,
                    section,
                    scope,
                    weak,
                });
            }
        }

        if let Some(exports) = exports {
            if let Some(main_file_symbol) = main_file_symbol.take() {
                file.symbols.push(main_file_symbol);
            }

            for export in exports {
                let export = export.read_error("Couldn't read an export item")?;

                let (kind, section_idx) = match export.kind {
                    wp::ExternalKind::Func | wp::ExternalKind::FuncExact => {
                        if let Some(local_func_index) = export.index.checked_sub(local_func_base) {
                            let local_func_kind = local_func_kinds
                                .get_mut(local_func_index as usize)
                                .read_error("Invalid Wasm export index")?;
                            *local_func_kind = LocalFunctionKind::Exported;
                        }
                        (SymbolKind::Text, SectionId::Code)
                    }
                    wp::ExternalKind::Table
                    | wp::ExternalKind::Memory
                    | wp::ExternalKind::Global => (SymbolKind::Data, SectionId::Data),
                    // TODO
                    wp::ExternalKind::Tag => continue,
                };

                // Try to guess the symbol address. Rust and C export a global containing
                // the address in linear memory of the symbol.
                let mut address = 0;
                let mut size = 0;
                if export.kind == wp::ExternalKind::Global {
                    if let Some(local_global_index) = export.index.checked_sub(local_global_base) {
                        if let Some(&Some(x)) = global_values.get(local_global_index as usize) {
                            address = x;
                        }
                    }
                }
                if export.kind == wp::ExternalKind::Func {
                    if let Some(local_func_index) = export.index.checked_sub(local_func_base) {
                        if let Some(range) = code_ranges.get(local_func_index as usize) {
                            address = range.0;
                            size = range.1
                        }
                    }
                }

                file.symbols.push(WasmSymbolInternal {
                    name: export.name,
                    address,
                    size,
                    kind,
                    section: SymbolSection::Section(SectionIndex(section_idx as usize)),
                    scope: SymbolScope::Dynamic,
                    weak: false,
                });
            }
        }
        if let Some(names) = names {
            if let Some(main_file_symbol) = main_file_symbol.take() {
                file.symbols.push(main_file_symbol);
            }
            for name in names {
                let name = name.read_error("Invalid wasm name section")?;
                let wp::Name::Function(name_map) = name else {
                    continue;
                };
                for naming in name_map {
                    let naming = naming.read_error("Couldn't read a function name")?;
                    let Some(local_func_index) = naming.index.checked_sub(local_func_base) else {
                        continue;
                    };
                    let Some(LocalFunctionKind::Unknown) =
                        local_func_kinds.get(local_func_index as usize)
                    else {
                        continue;
                    };
                    let Some((address, size)) = code_ranges.get(local_func_index as usize).copied()
                    else {
                        continue;
                    };
                    file.symbols.push(WasmSymbolInternal {
                        name: naming.name,
                        address,
                        size,
                        kind: SymbolKind::Text,
                        section: SymbolSection::Section(SectionIndex(SectionId::Code as usize)),
                        scope: SymbolScope::Compilation,
                        weak: false,
                    });
                }
            }
        }

        Ok(file)
    }

    fn add_section(&mut self, id: SectionId, range: Range<usize>, name: &'data str) {
        let section = SectionHeader { id, range, name };
        if id != SectionId::Custom && id != SectionId::Unknown {
            self.id_sections[id as usize] = Some(WasmSectionIndex(self.sections.len() as u32));
        }
        self.sections.push(section);
    }
}

impl<'data, R> read::private::Sealed for WasmFile<'data, R> {}

impl<'data, R: ReadRef<'data>> Object<'data> for WasmFile<'data, R> {
    type Segment<'file>
        = WasmSegment<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type SegmentIterator<'file>
        = WasmSegmentIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type Section<'file>
        = WasmSection<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type SectionIterator<'file>
        = WasmSectionIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type Comdat<'file>
        = WasmComdat<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type ComdatIterator<'file>
        = WasmComdatIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type Symbol<'file>
        = WasmSymbol<'data, 'file>
    where
        Self: 'file,
        'data: 'file;
    type SymbolIterator<'file>
        = WasmSymbolIterator<'data, 'file>
    where
        Self: 'file,
        'data: 'file;
    type SymbolTable<'file>
        = WasmSymbolTable<'data, 'file>
    where
        Self: 'file,
        'data: 'file;
    type DynamicRelocationIterator<'file>
        = NoDynamicRelocationIterator
    where
        Self: 'file,
        'data: 'file;
    type ImportLibraryIterator<'file>
        = NoImportLibraryIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type ImportIterator<'file>
        = NoImportIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type ExportIterator<'file>
        = NoExportIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;

    #[inline]
    fn architecture(&self) -> Architecture {
        if self.has_memory64 {
            Architecture::Wasm64
        } else {
            Architecture::Wasm32
        }
    }

    #[inline]
    fn is_little_endian(&self) -> bool {
        true
    }

    #[inline]
    fn is_64(&self) -> bool {
        self.has_memory64
    }

    fn kind(&self) -> ObjectKind {
        if self.has_linking {
            ObjectKind::Relocatable
        } else {
            ObjectKind::Executable
        }
    }

    fn segments(&self) -> Self::SegmentIterator<'_> {
        // Relocatable objects expose data segments as sections, not segments.
        let segments: &[WasmDataSegmentInternal<'data>] = if self.has_linking {
            &[]
        } else {
            &self.data_segments
        };
        WasmSegmentIterator {
            file: self,
            iter: segments.iter(),
        }
    }

    fn section_by_name_bytes<'file>(
        &'file self,
        section_name: &[u8],
    ) -> Option<WasmSection<'data, 'file, R>> {
        self.sections()
            .find(|section| section.name_bytes() == Ok(section_name))
    }

    fn section_by_index(&self, index: SectionIndex) -> Result<WasmSection<'data, '_, R>> {
        if let Some(segment_index) = WasmDataSegmentIndex::from_section_index(index) {
            if self.has_linking {
                let segment = self
                    .data_segments
                    .get(segment_index.0 as usize)
                    .read_error("Invalid Wasm section index")?;
                return Ok(WasmSection {
                    file: self,
                    inner: WasmSectionInner::DataSegment {
                        segment_index,
                        segment,
                    },
                });
            }
            return Err(Error("Invalid Wasm section index"));
        }
        let section_index = self
            .id_sections
            .get(index.0)
            .and_then(|x| *x)
            .read_error("Invalid Wasm section index")?;
        let section = &self.sections[section_index.0 as usize];
        if self.has_linking && section.id == SectionId::Data {
            return Err(Error("Invalid Wasm section index"));
        }
        Ok(WasmSection {
            file: self,
            inner: WasmSectionInner::Header {
                section_index,
                section,
            },
        })
    }

    fn sections(&self) -> Self::SectionIterator<'_> {
        WasmSectionIterator {
            file: self,
            sections: self.sections.iter().enumerate(),
            data_segments: self.data_segments.iter().enumerate(),
        }
    }

    fn comdats(&self) -> Self::ComdatIterator<'_> {
        WasmComdatIterator { file: self }
    }

    #[inline]
    fn symbol_by_index(&self, index: SymbolIndex) -> Result<WasmSymbol<'data, '_>> {
        let symbol = self
            .symbols
            .get(index.0)
            .read_error("Invalid Wasm symbol index")?;
        Ok(WasmSymbol { index, symbol })
    }

    fn symbols(&self) -> Self::SymbolIterator<'_> {
        WasmSymbolIterator {
            symbols: self.symbols.iter().enumerate(),
        }
    }

    fn symbol_table(&self) -> Option<WasmSymbolTable<'data, '_>> {
        Some(WasmSymbolTable {
            symbols: &self.symbols,
        })
    }

    fn dynamic_symbols(&self) -> Self::SymbolIterator<'_> {
        WasmSymbolIterator {
            symbols: [].iter().enumerate(),
        }
    }

    #[inline]
    fn dynamic_symbol_table(&self) -> Option<WasmSymbolTable<'data, '_>> {
        None
    }

    #[inline]
    fn dynamic_relocations(&self) -> Option<NoDynamicRelocationIterator> {
        None
    }

    fn import_libraries(&self) -> Result<Self::ImportLibraryIterator<'_>> {
        // TODO: return module names in the import section
        Ok(Default::default())
    }

    fn imports(&self) -> Result<Self::ImportIterator<'_>> {
        // TODO: return entries in the import section
        Ok(Default::default())
    }

    fn exports(&self) -> Result<Self::ExportIterator<'_>> {
        // TODO: return entries in the export section
        Ok(Default::default())
    }

    fn has_debug_symbols(&self) -> bool {
        self.has_debug_symbols
    }

    fn relative_address_base(&self) -> u64 {
        0
    }

    #[inline]
    fn entry(&self) -> u64 {
        self.entry
    }

    #[inline]
    fn flags(&self) -> FileFlags {
        FileFlags::None
    }
}

/// An iterator for the segments in a [`WasmFile`].
#[derive(Debug)]
pub struct WasmSegmentIterator<'data, 'file, R = &'data [u8]> {
    file: &'file WasmFile<'data, R>,
    iter: slice::Iter<'file, WasmDataSegmentInternal<'data>>,
}

impl<'data, 'file, R> Iterator for WasmSegmentIterator<'data, 'file, R> {
    type Item = WasmSegment<'data, 'file, R>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let segment = self.iter.next()?;
            // Passive segments are not loaded automatically.
            if segment.is_passive {
                continue;
            }
            return Some(WasmSegment {
                file: self.file,
                segment,
            });
        }
    }
}

/// A segment in a [`WasmFile`].
#[derive(Debug)]
pub struct WasmSegment<'data, 'file, R = &'data [u8]> {
    #[allow(unused)]
    file: &'file WasmFile<'data, R>,
    segment: &'file WasmDataSegmentInternal<'data>,
}

impl<'data, 'file, R> read::private::Sealed for WasmSegment<'data, 'file, R> {}

impl<'data, 'file, R> ObjectSegment<'data> for WasmSegment<'data, 'file, R> {
    #[inline]
    fn address(&self) -> u64 {
        self.segment.address
    }

    #[inline]
    fn size(&self) -> u64 {
        self.segment.data.len() as u64
    }

    #[inline]
    fn align(&self) -> u64 {
        self.segment.align()
    }

    #[inline]
    fn file_range(&self) -> (u64, u64) {
        (self.segment.file_offset, self.segment.data.len() as u64)
    }

    fn data(&self) -> Result<&'data [u8]> {
        Ok(self.segment.data)
    }

    fn data_range(&self, address: u64, size: u64) -> Result<Option<&'data [u8]>> {
        Ok(read::util::data_range(
            self.segment.data,
            self.segment.address,
            address,
            size,
        ))
    }

    #[inline]
    fn name_bytes(&self) -> Result<Option<&[u8]>> {
        Ok(None)
    }

    #[inline]
    fn name(&self) -> Result<Option<&str>> {
        Ok(None)
    }

    #[inline]
    fn flags(&self) -> SegmentFlags {
        SegmentFlags::None
    }

    #[inline]
    fn permissions(&self) -> Permissions {
        Permissions::new(true, true, false)
    }
}

/// An iterator for the sections in a [`WasmFile`].
#[derive(Debug)]
pub struct WasmSectionIterator<'data, 'file, R = &'data [u8]> {
    file: &'file WasmFile<'data, R>,
    sections: core::iter::Enumerate<slice::Iter<'file, SectionHeader<'data>>>,
    data_segments: core::iter::Enumerate<slice::Iter<'file, WasmDataSegmentInternal<'data>>>,
}

impl<'data, 'file, R> Iterator for WasmSectionIterator<'data, 'file, R> {
    type Item = WasmSection<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        for (index, section) in self.sections.by_ref() {
            if self.file.has_linking && section.id == SectionId::Data {
                continue;
            }
            return Some(WasmSection {
                file: self.file,
                inner: WasmSectionInner::Header {
                    section_index: WasmSectionIndex(index as u32),
                    section,
                },
            });
        }
        if self.file.has_linking {
            let (index, segment) = self.data_segments.next()?;
            return Some(WasmSection {
                file: self.file,
                inner: WasmSectionInner::DataSegment {
                    segment_index: WasmDataSegmentIndex(index as u32),
                    segment,
                },
            });
        }
        None
    }
}

/// A section in a [`WasmFile`].
///
/// Most functionality is provided by the [`ObjectSection`] trait implementation.
#[derive(Debug)]
pub struct WasmSection<'data, 'file, R = &'data [u8]> {
    file: &'file WasmFile<'data, R>,
    inner: WasmSectionInner<'data, 'file>,
}

#[derive(Debug, Clone, Copy)]
enum WasmSectionInner<'data, 'file> {
    Header {
        section_index: WasmSectionIndex,
        section: &'file SectionHeader<'data>,
    },
    DataSegment {
        segment_index: WasmDataSegmentIndex,
        segment: &'file WasmDataSegmentInternal<'data>,
    },
}

impl<'data, 'file, R> read::private::Sealed for WasmSection<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectSection<'data> for WasmSection<'data, 'file, R> {
    type RelocationIterator = WasmRelocationIterator<'data, 'file, R>;

    #[inline]
    fn index(&self) -> SectionIndex {
        match self.inner {
            // Note that we treat all custom and unknown sections as index 0.
            // This is ok because they are never looked up by index.
            WasmSectionInner::Header { section, .. } => {
                if section.id == SectionId::Custom || section.id == SectionId::Unknown {
                    SectionIndex(0)
                } else {
                    SectionIndex(section.id as usize)
                }
            }
            WasmSectionInner::DataSegment { segment_index, .. } => segment_index.section_index(),
        }
    }

    #[inline]
    fn address(&self) -> u64 {
        0
    }

    #[inline]
    fn size(&self) -> u64 {
        match self.inner {
            WasmSectionInner::Header { section, .. } => {
                (section.range.end - section.range.start) as u64
            }
            WasmSectionInner::DataSegment { segment, .. } => segment.data.len() as u64,
        }
    }

    #[inline]
    fn align(&self) -> u64 {
        match self.inner {
            WasmSectionInner::Header { .. } => 1,
            WasmSectionInner::DataSegment { segment, .. } => segment.align(),
        }
    }

    #[inline]
    fn file_range(&self) -> Option<(u64, u64)> {
        match self.inner {
            WasmSectionInner::Header { section, .. } => Some((
                section.range.start as u64,
                (section.range.end - section.range.start) as u64,
            )),
            WasmSectionInner::DataSegment { segment, .. } => {
                Some((segment.file_offset, segment.data.len() as u64))
            }
        }
    }

    #[inline]
    fn data(&self) -> Result<&'data [u8]> {
        match self.inner {
            WasmSectionInner::Header { section, .. } => self
                .file
                .data
                .read_bytes_at(
                    section.range.start as u64,
                    section.range.end as u64 - section.range.start as u64,
                )
                .read_error("Invalid Wasm section size or offset"),
            WasmSectionInner::DataSegment { segment, .. } => Ok(segment.data),
        }
    }

    fn data_range(&self, address: u64, size: u64) -> Result<Option<&'data [u8]>> {
        match self.inner {
            WasmSectionInner::Header { .. } => Ok(None),
            WasmSectionInner::DataSegment { segment, .. } => {
                Ok(read::util::data_range(segment.data, 0, address, size))
            }
        }
    }

    #[inline]
    fn compressed_file_range(&self) -> Result<CompressedFileRange> {
        Ok(CompressedFileRange::none(self.file_range()))
    }

    #[inline]
    fn compressed_data(&self) -> Result<CompressedData<'data>> {
        self.data().map(CompressedData::none)
    }

    #[inline]
    fn name_bytes(&self) -> Result<&'data [u8]> {
        self.name().map(str::as_bytes)
    }

    #[inline]
    fn name(&self) -> Result<&'data str> {
        Ok(match self.inner {
            WasmSectionInner::Header { section, .. } => match section.id {
                SectionId::Custom => section.name,
                SectionId::Type => "<type>",
                SectionId::Import => "<import>",
                SectionId::Function => "<function>",
                SectionId::Table => "<table>",
                SectionId::Memory => "<memory>",
                SectionId::Global => "<global>",
                SectionId::Export => "<export>",
                SectionId::Start => "<start>",
                SectionId::Element => "<element>",
                SectionId::Code => "<code>",
                SectionId::Data => "<data>",
                SectionId::DataCount => "<data_count>",
                SectionId::Tag => "<tag>",
                SectionId::Unknown => "<unknown>",
            },
            WasmSectionInner::DataSegment { segment, .. } => segment.name(),
        })
    }

    #[inline]
    fn segment_name_bytes(&self) -> Result<Option<&[u8]>> {
        Ok(None)
    }

    #[inline]
    fn segment_name(&self) -> Result<Option<&str>> {
        Ok(None)
    }

    #[inline]
    fn kind(&self) -> SectionKind {
        match self.inner {
            WasmSectionInner::Header { section, .. } => match section.id {
                SectionId::Custom => match section.name {
                    "linking" => SectionKind::Linker,
                    name if name.starts_with("reloc.") => SectionKind::Linker,
                    _ => SectionKind::Other,
                },
                SectionId::Type => SectionKind::Metadata,
                SectionId::Import => SectionKind::Linker,
                SectionId::Function => SectionKind::Metadata,
                SectionId::Table => SectionKind::UninitializedData,
                SectionId::Memory => SectionKind::UninitializedData,
                SectionId::Global => SectionKind::Data,
                SectionId::Export => SectionKind::Linker,
                SectionId::Start => SectionKind::Linker,
                SectionId::Element => SectionKind::Data,
                SectionId::Code => SectionKind::Text,
                SectionId::Data => SectionKind::Data,
                SectionId::DataCount => SectionKind::UninitializedData,
                SectionId::Tag => SectionKind::Data,
                SectionId::Unknown => SectionKind::Unknown,
            },
            WasmSectionInner::DataSegment { segment, .. } => segment.section_kind(),
        }
    }

    #[inline]
    fn relocations(&self) -> WasmRelocationIterator<'data, 'file, R> {
        let (target, offset_range) = match self.inner {
            WasmSectionInner::Header { section_index, .. } => (Some(section_index), 0..u64::MAX),
            WasmSectionInner::DataSegment { segment, .. } => (
                self.file.id_sections[SectionId::Data as usize],
                segment.section_offset..segment.section_offset + segment.data.len() as u64,
            ),
        };
        WasmRelocationIterator {
            target,
            offset_range,
            sections: self.file.relocations.iter(),
            entries: [].iter(),
            marker: PhantomData,
        }
    }

    fn relocation_map(&self) -> read::Result<RelocationMap> {
        RelocationMap::new(self.file, self)
    }

    #[inline]
    fn flags(&self) -> SectionFlags {
        match self.inner {
            WasmSectionInner::DataSegment { segment, .. } if segment.info.is_some() => {
                SectionFlags::Wasm {
                    flags: segment.flags(),
                }
            }
            _ => SectionFlags::None,
        }
    }
}

/// An iterator for the COMDAT section groups in a [`WasmFile`].
///
/// This is a stub that doesn't implement any functionality.
#[derive(Debug)]
pub struct WasmComdatIterator<'data, 'file, R = &'data [u8]> {
    #[allow(unused)]
    file: &'file WasmFile<'data, R>,
}

impl<'data, 'file, R> Iterator for WasmComdatIterator<'data, 'file, R> {
    type Item = WasmComdat<'data, 'file, R>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

/// A COMDAT section group in a [`WasmFile`].
///
/// This is a stub that doesn't implement any functionality.
#[derive(Debug)]
pub struct WasmComdat<'data, 'file, R = &'data [u8]> {
    #[allow(unused)]
    file: &'file WasmFile<'data, R>,
}

impl<'data, 'file, R> read::private::Sealed for WasmComdat<'data, 'file, R> {}

impl<'data, 'file, R> ObjectComdat<'data> for WasmComdat<'data, 'file, R> {
    type SectionIterator = WasmComdatSectionIterator<'data, 'file, R>;

    #[inline]
    fn kind(&self) -> ComdatKind {
        unreachable!();
    }

    #[inline]
    fn symbol(&self) -> SymbolIndex {
        unreachable!();
    }

    #[inline]
    fn name_bytes(&self) -> Result<&'data [u8]> {
        unreachable!();
    }

    #[inline]
    fn name(&self) -> Result<&'data str> {
        unreachable!();
    }

    #[inline]
    fn sections(&self) -> Self::SectionIterator {
        unreachable!();
    }
}

/// An iterator for the sections in a COMDAT section group in a [`WasmFile`].
///
/// This is a stub that doesn't implement any functionality.
#[derive(Debug)]
pub struct WasmComdatSectionIterator<'data, 'file, R = &'data [u8]> {
    #[allow(unused)]
    file: &'file WasmFile<'data, R>,
}

impl<'data, 'file, R> Iterator for WasmComdatSectionIterator<'data, 'file, R> {
    type Item = SectionIndex;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

/// A symbol table in a [`WasmFile`].
#[derive(Debug)]
pub struct WasmSymbolTable<'data, 'file> {
    symbols: &'file [WasmSymbolInternal<'data>],
}

impl<'data, 'file> read::private::Sealed for WasmSymbolTable<'data, 'file> {}

impl<'data, 'file> ObjectSymbolTable<'data> for WasmSymbolTable<'data, 'file> {
    type Symbol = WasmSymbol<'data, 'file>;
    type SymbolIterator = WasmSymbolIterator<'data, 'file>;

    fn symbols(&self) -> Self::SymbolIterator {
        WasmSymbolIterator {
            symbols: self.symbols.iter().enumerate(),
        }
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> Result<Self::Symbol> {
        let symbol = self
            .symbols
            .get(index.0)
            .read_error("Invalid Wasm symbol index")?;
        Ok(WasmSymbol { index, symbol })
    }
}

/// An iterator for the symbols in a [`WasmFile`].
#[derive(Debug)]
pub struct WasmSymbolIterator<'data, 'file> {
    symbols: core::iter::Enumerate<slice::Iter<'file, WasmSymbolInternal<'data>>>,
}

impl<'data, 'file> Iterator for WasmSymbolIterator<'data, 'file> {
    type Item = WasmSymbol<'data, 'file>;

    fn next(&mut self) -> Option<Self::Item> {
        let (index, symbol) = self.symbols.next()?;
        Some(WasmSymbol {
            index: SymbolIndex(index),
            symbol,
        })
    }
}

/// A symbol in a [`WasmFile`].
///
/// Most functionality is provided by the [`ObjectSymbol`] trait implementation.
#[derive(Clone, Copy, Debug)]
pub struct WasmSymbol<'data, 'file> {
    index: SymbolIndex,
    symbol: &'file WasmSymbolInternal<'data>,
}

#[derive(Clone, Debug)]
struct WasmSymbolInternal<'data> {
    name: &'data str,
    address: u64,
    size: u64,
    kind: SymbolKind,
    section: SymbolSection,
    scope: SymbolScope,
    weak: bool,
}

impl<'data, 'file> read::private::Sealed for WasmSymbol<'data, 'file> {}

impl<'data, 'file> ObjectSymbol<'data> for WasmSymbol<'data, 'file> {
    #[inline]
    fn index(&self) -> SymbolIndex {
        self.index
    }

    #[inline]
    fn name_bytes(&self) -> read::Result<&'data [u8]> {
        Ok(self.symbol.name.as_bytes())
    }

    #[inline]
    fn name(&self) -> read::Result<&'data str> {
        Ok(self.symbol.name)
    }

    #[inline]
    fn address(&self) -> u64 {
        self.symbol.address
    }

    #[inline]
    fn size(&self) -> u64 {
        self.symbol.size
    }

    #[inline]
    fn kind(&self) -> SymbolKind {
        self.symbol.kind
    }

    #[inline]
    fn section(&self) -> SymbolSection {
        self.symbol.section
    }

    #[inline]
    fn is_undefined(&self) -> bool {
        self.symbol.section == SymbolSection::Undefined
    }

    #[inline]
    fn is_definition(&self) -> bool {
        (self.symbol.kind == SymbolKind::Text || self.symbol.kind == SymbolKind::Data)
            && self.symbol.section != SymbolSection::Undefined
    }

    #[inline]
    fn is_common(&self) -> bool {
        self.symbol.section == SymbolSection::Common
    }

    #[inline]
    fn is_weak(&self) -> bool {
        self.symbol.weak
    }

    #[inline]
    fn scope(&self) -> SymbolScope {
        self.symbol.scope
    }

    #[inline]
    fn is_global(&self) -> bool {
        self.symbol.scope != SymbolScope::Compilation
    }

    #[inline]
    fn is_local(&self) -> bool {
        self.symbol.scope == SymbolScope::Compilation
    }

    #[inline]
    fn flags(&self) -> SymbolFlags<SectionIndex, SymbolIndex> {
        SymbolFlags::None
    }
}

/// An iterator for the relocations for a [`WasmSection`].
#[derive(Debug)]
pub struct WasmRelocationIterator<'data, 'file, R = &'data [u8]> {
    /// Binary index of the wasm section we are iterating relocations for.
    target: Option<WasmSectionIndex>,
    /// The offset range if this is a data segment, otherwise `0..u64::MAX`.
    offset_range: Range<u64>,
    /// Remaining `reloc.*` sections that may target this section.
    sections: slice::Iter<'file, RelocSection>,
    /// Remaining entries from the current matching `reloc.*` section.
    entries: slice::Iter<'file, wp::RelocationEntry>,
    marker: PhantomData<(&'data (), R)>,
}

impl<'data, 'file, R> Iterator for WasmRelocationIterator<'data, 'file, R> {
    type Item = (u64, Relocation);

    fn next(&mut self) -> Option<Self::Item> {
        let entry = loop {
            if let Some(entry) = self.entries.next() {
                break *entry;
            }
            let target = self.target?;
            let next = self.sections.find(|r| r.target == target)?;
            self.entries = next.entries_in_range(&self.offset_range).iter();
        };
        let r_type = entry.ty as u8;
        // Number of bits the relocation patches in the target section.
        let size = (entry.ty.extent() * 8) as u8;
        // For `R_WASM_TYPE_INDEX_LEB`, the `index` field refers to the type section, not the symbol table.
        let (target, addend) = if entry.ty == wp::RelocationType::TypeIndexLeb {
            (
                RelocationTarget::Section(SectionIndex(SectionId::Type as usize)),
                entry.index as i64,
            )
        } else {
            (
                RelocationTarget::Symbol(SymbolIndex(entry.index as usize)),
                entry.addend,
            )
        };
        let relocation = Relocation {
            kind: RelocationKind::Unknown,
            encoding: RelocationEncoding::Generic,
            size,
            target,
            subtractor: None,
            // Wasm relocation entries always carry an explicit addend.
            implicit_addend: false,
            addend,
            flags: RelocationFlags::Wasm { r_type },
        };
        let offset = u64::from(entry.offset) - self.offset_range.start;
        Some((offset, relocation))
    }
}
