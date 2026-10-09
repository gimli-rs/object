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
    self, Architecture, ComdatKind, CompressedData, CompressedFileRange, Error, Export,
    ExportFlags, ExportTarget, FileFlags, Import, ImportFlags, ImportLibrary, ImportLibraryFlags,
    NameOrOrdinal, NoDynamicRelocationIterator, Object, ObjectComdat, ObjectKind, ObjectSection,
    ObjectSegment, ObjectSymbol, ObjectSymbolTable, Permissions, ReadError, ReadRef, Relocation,
    RelocationMap, Result, SectionFlags, SectionIndex, SectionKind, SegmentFlags, SymbolFlags,
    SymbolIndex, SymbolKind, SymbolScope, SymbolSection,
};
use crate::wasm;
use crate::{RelocationEncoding, RelocationFlags, RelocationKind, RelocationTarget};

// Update this constant when adding new section id:
const MAX_SECTION_ID: usize = wasm::SEC_TAG.0 as usize;

/// The index of a segment in the data section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WasmDataSegmentIndex(u32);

/// A WebAssembly object file.
#[derive(Debug)]
pub struct WasmFile<'data, R = &'data [u8]> {
    data: SkipDebugList<&'data [u8]>,
    has_memory64: bool,
    // All sections, including custom sections, in file order.
    sections: Vec<SectionHeader<'data>>,
    // Map from `SectionId` to file-order `SectionIndex`.
    id_sections: Box<[Option<SectionIndex>; MAX_SECTION_ID + 1]>,
    // Parsed `reloc.*` custom sections, keyed by the binary index of the target section.
    relocations: Vec<RelocSection>,
    // Data segments parsed from the `data` section.
    data_segments: Vec<WasmDataSegmentInternal<'data>>,
    // Whether the file has a `dylink` or `dylink.0` custom section.
    has_dylink: bool,
    // Whether the file has a `linking` custom section (relocatable object).
    has_linking: bool,
    // Whether the file has DWARF information.
    has_debug_symbols: bool,
    // Symbols collected from `linking` and `name` custom sections.
    symbols: Vec<WasmSymbolInternal<'data>>,
    // Entries in `WASM_DYLINK_NEEDED` sub-section.
    needed: Vec<&'data str>,
    // Entries in the imports section.
    imports: Vec<WasmImportInternal<'data>>,
    // Entries in the exports section.
    exports: Vec<WasmExportInternal<'data>>,
    // Address of the function body for the entry point.
    entry: u64,
    marker: PhantomData<R>,
}

#[derive(Debug)]
struct RelocSection {
    target: SectionIndex,
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
        self.info.map(|info| info.name).unwrap_or("<data_segment>")
    }

    fn align(&self) -> u64 {
        match self.info {
            Some(info) => 1u64.checked_shl(info.alignment).unwrap_or(1),
            None => 1,
        }
    }

    fn flags(&self) -> wasm::SegmentFlags {
        wasm::SegmentFlags(self.info.map(|info| info.flags.bits()).unwrap_or(0))
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
    id: wasm::SectionId,
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
            has_dylink: false,
            has_linking: false,
            has_debug_symbols: false,
            symbols: Vec::new(),
            needed: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            entry: 0,
            marker: PhantomData,
        };

        let mut main_file_symbol = Some(WasmSymbolInternal::synthetic(
            "",
            0,
            0,
            SymbolKind::File,
            SymbolSection::None,
            SymbolScope::Compilation,
            false,
        ));

        let mut entry_func_id = None;
        let mut code_range_start = 0;
        let mut imports_section = None;
        let mut exports = None;
        let mut names = None;
        let mut symbols = None;
        let mut import_infos = Vec::new();
        let mut export_infos = Vec::new();
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
                    file.add_section(wasm::SEC_TYPE, section.range(), "");
                }
                wp::Payload::ImportSection(section) => {
                    file.add_section(wasm::SEC_IMPORT, section.range(), "");
                    imports_section = Some(section);
                }
                wp::Payload::FunctionSection(section) => {
                    file.add_section(wasm::SEC_FUNCTION, section.range(), "");
                    local_func_kinds =
                        vec![LocalFunctionKind::Unknown; section.into_iter().count()];
                }
                wp::Payload::TableSection(section) => {
                    file.add_section(wasm::SEC_TABLE, section.range(), "");
                }
                wp::Payload::MemorySection(section) => {
                    file.add_section(wasm::SEC_MEMORY, section.range(), "");
                    for memory in section {
                        let memory = memory.read_error("Couldn't read a memory item")?;
                        file.has_memory64 |= memory.memory64;
                    }
                }
                wp::Payload::GlobalSection(section) => {
                    file.add_section(wasm::SEC_GLOBAL, section.range(), "");
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
                    file.add_section(wasm::SEC_EXPORT, section.range(), "");
                    exports = Some(section);
                }
                wp::Payload::StartSection { func, range, .. } => {
                    file.add_section(wasm::SEC_START, range, "");
                    entry_func_id = Some(func);
                }
                wp::Payload::ElementSection(section) => {
                    file.add_section(wasm::SEC_ELEMENT, section.range(), "");
                }
                wp::Payload::CodeSectionStart { range, .. } => {
                    code_range_start = range.start;
                    file.add_section(wasm::SEC_CODE, range, "");
                }
                wp::Payload::CodeSectionEntry(body) => {
                    let range = body.range();
                    let address = range.start as u64 - code_range_start as u64;
                    let size = (range.end - range.start) as u64;
                    code_ranges.push((address, size));
                }
                wp::Payload::DataSection(section) => {
                    let section_range = section.range();
                    file.add_section(wasm::SEC_DATA, section_range.clone(), "");
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
                    file.add_section(wasm::SEC_DATA_COUNT, range, "");
                }
                wp::Payload::TagSection(section) => {
                    file.add_section(wasm::SEC_TAG, section.range(), "");
                }
                wp::Payload::UnknownSection { id, range, .. } => {
                    file.add_section(wasm::SectionId(id), range, "");
                }
                wp::Payload::CustomSection(section) => {
                    let name = section.name();
                    let size = section.data().len();
                    let mut range = section.range();
                    range.start = range.end - size;
                    file.add_section(wasm::SEC_CUSTOM, range, name);
                    if name == "name" {
                        let reader = wp::BinaryReader::new(section.data(), section.data_offset());
                        names = Some(wp::NameSectionReader::new(reader));
                    } else if name == "dylink" {
                        // Obsolete. Set the file kind but don't parse.
                        file.has_dylink = true;
                    } else if name == "dylink.0" {
                        // https://github.com/WebAssembly/tool-conventions/blob/main/DynamicLinking.md
                        file.has_dylink = true;
                        let reader = wp::BinaryReader::new(section.data(), section.data_offset());
                        for subsection in wp::Dylink0SectionReader::new(reader) {
                            let subsection =
                                subsection.read_error("Invalid Wasm dylink.0 subsection")?;
                            match subsection {
                                wp::Dylink0Subsection::Needed(names) => file.needed = names,
                                wp::Dylink0Subsection::ImportInfo(infos) => {
                                    import_infos = infos;
                                    // Sort so that the lookup for each import is a binary search.
                                    import_infos
                                        .sort_unstable_by_key(|info| (info.module, info.field));
                                }
                                wp::Dylink0Subsection::ExportInfo(infos) => {
                                    export_infos = infos;
                                    // Sort so that the lookup for each export is a binary search.
                                    export_infos.sort_unstable_by_key(|info| info.name);
                                }
                                _ => {}
                            }
                        }
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
                        let target = SectionIndex(reloc.section_index() as usize);
                        let mut entries = Vec::new();
                        for entry in reloc.entries() {
                            let entry = entry.read_error("Invalid Wasm reloc entry")?;
                            entries.push(entry);
                        }
                        if let Some(section) = file.sections.get(target.0 as usize) {
                            if section.id == wasm::SEC_DATA {
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

        // Index into `file.imports` for each imported item.
        let mut import_funcs = Vec::new();
        let mut import_globals = Vec::new();
        let mut import_tables = Vec::new();
        let mut import_tags = Vec::new();
        let mut import_memory_count = 0;

        if let Some(imports_section) = imports_section {
            let mut last_module_name = None;
            for imports in imports_section {
                let imports = imports.read_error("Couldn't read an imports item")?;
                let add_import = &mut |module, ty, name| {
                    let import_index = file.imports.len();
                    let (kind, index) = match ty {
                        wp::TypeRef::Func(_) => {
                            let index = import_funcs.len() as u32;
                            import_funcs.push(import_index);
                            (wasm::EXTERNAL_FUNCTION, index)
                        }
                        wp::TypeRef::FuncExact(_) => {
                            let index = import_funcs.len() as u32;
                            import_funcs.push(import_index);
                            (wasm::EXTERNAL_FUNCTION_EXACT, index)
                        }
                        wp::TypeRef::Memory(memory) => {
                            let index = import_memory_count;
                            import_memory_count += 1;
                            file.has_memory64 |= memory.memory64;
                            (wasm::EXTERNAL_MEMORY, index)
                        }
                        wp::TypeRef::Global(_) => {
                            let index = import_globals.len() as u32;
                            import_globals.push(import_index);
                            (wasm::EXTERNAL_GLOBAL, index)
                        }
                        wp::TypeRef::Table(_) => {
                            let index = import_tables.len() as u32;
                            import_tables.push(import_index);
                            (wasm::EXTERNAL_TABLE, index)
                        }
                        wp::TypeRef::Tag(_) => {
                            let index = import_tags.len() as u32;
                            import_tags.push(import_index);
                            (wasm::EXTERNAL_TAG, index)
                        }
                    };

                    let flags = import_infos
                        .binary_search_by_key(&(module, name), |info| (info.module, info.field))
                        .ok()
                        .map(|index| wasm::SymbolFlags(import_infos[index].flags.bits()));

                    file.imports.push(WasmImportInternal {
                        module,
                        name,
                        kind,
                        index,
                        flags,
                    });

                    if file.has_linking {
                        // Relocatable objects should have a symbol table, so we don't need to add
                        // symbols for imports.
                        return;
                    }

                    let symbol_kind = match ty {
                        wp::TypeRef::Func(_) | wp::TypeRef::FuncExact(_) => SymbolKind::Text,
                        wp::TypeRef::Memory(_) => SymbolKind::Data,
                        wp::TypeRef::Global(_) => SymbolKind::Data,
                        wp::TypeRef::Table(_) => SymbolKind::Data,
                        wp::TypeRef::Tag(_) => SymbolKind::Unknown,
                    };

                    if last_module_name != Some(module) {
                        file.symbols.push(WasmSymbolInternal::synthetic(
                            module,
                            0,
                            0,
                            SymbolKind::File,
                            SymbolSection::None,
                            SymbolScope::Dynamic,
                            false,
                        ));
                        last_module_name = Some(module);
                    }

                    // TODO: never add symbols for imports?
                    file.symbols.push(WasmSymbolInternal::synthetic(
                        name,
                        0,
                        0,
                        symbol_kind,
                        SymbolSection::Undefined,
                        SymbolScope::Dynamic,
                        false,
                    ));
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
        let local_func_base = import_funcs.len() as u32;
        // Bias to apply to global indices when accessing `global_values`.
        let local_global_base = import_globals.len() as u32;

        if let Some(entry_func_id) = entry_func_id {
            if let Some(local_func_index) = entry_func_id.checked_sub(local_func_base) {
                if let Some(range) = code_ranges.get(local_func_index as usize) {
                    file.entry = range.0;
                }
            }
        }

        let mut parsed_exports = Vec::new();
        if let Some(exports) = exports {
            for export in exports {
                parsed_exports.push(export.read_error("Couldn't read an export item")?);
            }
        }
        let mut export_names = Vec::new();
        if file.has_linking {
            for export in &parsed_exports {
                let kind = match export.kind {
                    wp::ExternalKind::Func | wp::ExternalKind::FuncExact => wasm::SYM_TYPE_FUNCTION,
                    wp::ExternalKind::Global => wasm::SYM_TYPE_GLOBAL,
                    wp::ExternalKind::Table => wasm::SYM_TYPE_TABLE,
                    wp::ExternalKind::Tag => wasm::SYM_TYPE_EVENT,
                    wp::ExternalKind::Memory => continue,
                };
                export_names.push((kind, export.index, export.name));
            }
            export_names.sort_by_key(|&(kind, index, _)| (kind, index));
        }

        if let Some(symbols) = symbols {
            for symbol in symbols {
                let symbol = symbol.read_error("Invalid Wasm linking symbol")?;
                if let wp::SymbolInfo::Data {
                    symbol: Some(data), ..
                } = symbol
                {
                    if (data.index as usize) >= file.data_segments.len() {
                        return Err(Error("Invalid Wasm data symbol segment index"));
                    }
                }
                let flags = match symbol {
                    wp::SymbolInfo::Func { flags, .. } => flags,
                    wp::SymbolInfo::Data { flags, .. } => flags,
                    wp::SymbolInfo::Global { flags, .. } => flags,
                    wp::SymbolInfo::Section { flags, .. } => flags,
                    wp::SymbolInfo::Event { flags, .. } => flags,
                    wp::SymbolInfo::Table { flags, .. } => flags,
                };
                let wasm_flags = wasm::SymbolFlags(flags.bits());
                let (wasm_kind, index) = match symbol {
                    wp::SymbolInfo::Func { index, .. } => (wasm::SYM_TYPE_FUNCTION, index),
                    wp::SymbolInfo::Data { symbol, .. } => (
                        wasm::SYM_TYPE_DATA,
                        symbol.map(|data| data.index).unwrap_or(0),
                    ),
                    wp::SymbolInfo::Global { index, .. } => (wasm::SYM_TYPE_GLOBAL, index),
                    wp::SymbolInfo::Section { section, .. } => (wasm::SYM_TYPE_SECTION, section),
                    wp::SymbolInfo::Event { index, .. } => (wasm::SYM_TYPE_EVENT, index),
                    wp::SymbolInfo::Table { index, .. } => (wasm::SYM_TYPE_TABLE, index),
                };
                let kind = if flags.contains(wp::SymbolFlags::TLS) {
                    SymbolKind::Tls
                } else {
                    match wasm_kind {
                        wasm::SYM_TYPE_FUNCTION => SymbolKind::Text,
                        wasm::SYM_TYPE_DATA | wasm::SYM_TYPE_GLOBAL | wasm::SYM_TYPE_TABLE => {
                            SymbolKind::Data
                        }
                        wasm::SYM_TYPE_SECTION => SymbolKind::Section,
                        _ => SymbolKind::Unknown,
                    }
                };
                let section = if flags.contains(wp::SymbolFlags::UNDEFINED) {
                    SymbolSection::Undefined
                } else if wasm_flags.binding() == wasm::SYM_BINDING_COMMON {
                    SymbolSection::Common
                } else if flags.contains(wp::SymbolFlags::ABSOLUTE) {
                    SymbolSection::Absolute
                } else {
                    match symbol {
                        wp::SymbolInfo::Func { .. } => {
                            match file.section_index_for_id(wasm::SEC_CODE) {
                                Some(index) => SymbolSection::Section(index),
                                None => SymbolSection::Unknown,
                            }
                        }
                        wp::SymbolInfo::Data {
                            symbol: Some(data), ..
                        } => SymbolSection::Section(
                            file.data_segment_section_index(WasmDataSegmentIndex(data.index)),
                        ),
                        wp::SymbolInfo::Section { section, .. } => {
                            let index = SectionIndex(section as usize);
                            if index.0 < file.sections.len() {
                                SymbolSection::Section(index)
                            } else {
                                SymbolSection::Unknown
                            }
                        }
                        _ => {
                            // TODO: anything that is defined should have a known section.
                            // Additionally, address and size should be within this section.
                            SymbolSection::Unknown
                        }
                    }
                };
                let scope = if wasm_flags.binding() == wasm::SYM_BINDING_LOCAL {
                    SymbolScope::Compilation
                } else if flags.contains(wp::SymbolFlags::VISIBILITY_HIDDEN) {
                    SymbolScope::Linkage
                } else {
                    SymbolScope::Dynamic
                };
                let weak = wasm_flags.binding() == wasm::SYM_BINDING_WEAK;

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
                            let import = &file.imports[import_funcs[index as usize]];
                            if !flags.contains(wp::SymbolFlags::EXPLICIT_NAME) {
                                name = Some(import.name);
                            }
                        }
                        name
                    }
                    wp::SymbolInfo::Data { name, symbol, .. } => {
                        if let Some(symbol) = symbol {
                            // Offset and size are within a data segment, which is exposed as a section.
                            let segment_address = file.data_segments[symbol.index as usize].address;
                            address = segment_address.wrapping_add(u64::from(symbol.offset));
                            size = symbol.size.into();
                        }
                        Some(name)
                    }
                    wp::SymbolInfo::Section { section, .. } => file
                        .sections
                        .get(section as usize)
                        .map(|header| header.name)
                        .filter(|name| !name.is_empty()),
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
                            let import = &file.imports[import_globals[index as usize]];
                            if !flags.contains(wp::SymbolFlags::EXPLICIT_NAME) {
                                name = Some(import.name);
                            }
                        }
                        name
                    }
                    wp::SymbolInfo::Event {
                        index, mut name, ..
                    } => {
                        if let Some(import_index) = import_tags.get(index as usize) {
                            let import = &file.imports[*import_index];
                            if !flags.contains(wp::SymbolFlags::EXPLICIT_NAME) {
                                name = Some(import.name);
                            }
                        }
                        name
                    }
                    wp::SymbolInfo::Table {
                        index, mut name, ..
                    } => {
                        if let Some(import_index) = import_tables.get(index as usize) {
                            let import = &file.imports[*import_index];
                            if !flags.contains(wp::SymbolFlags::EXPLICIT_NAME) {
                                name = Some(import.name);
                            }
                        }
                        name
                    }
                };

                let export_name = export_names
                    .binary_search_by_key(&(wasm_kind, index), |&(kind, idx, _)| (kind, idx))
                    .ok()
                    .map(|i| export_names[i].2);

                file.symbols.push(WasmSymbolInternal {
                    name: name.unwrap_or(""),
                    address,
                    size,
                    kind,
                    section,
                    scope,
                    weak,
                    flags: SymbolFlags::Wasm {
                        flags: wasm_flags,
                        kind: wasm_kind,
                        index,
                    },
                    export_name,
                });
            }
        }

        if !file.has_linking {
            if let Some(main_file_symbol) = main_file_symbol.take() {
                file.symbols.push(main_file_symbol);
            }

            for export in parsed_exports {
                let kind = match export.kind {
                    wp::ExternalKind::Func => wasm::EXTERNAL_FUNCTION,
                    wp::ExternalKind::Table => wasm::EXTERNAL_TABLE,
                    wp::ExternalKind::Memory => wasm::EXTERNAL_MEMORY,
                    wp::ExternalKind::Global => wasm::EXTERNAL_GLOBAL,
                    wp::ExternalKind::Tag => wasm::EXTERNAL_TAG,
                    // Shouldn't occur for exports.
                    wp::ExternalKind::FuncExact => wasm::EXTERNAL_FUNCTION_EXACT,
                };

                let flags = export_infos
                    .binary_search_by_key(&export.name, |info| info.name)
                    .ok()
                    .map(|index| wasm::SymbolFlags(export_infos[index].flags.bits()));

                let mut target = ExportTarget::Wasm;
                if export.kind == wp::ExternalKind::Global {
                    // Try to guess some special export targets. We can only reliably
                    // do this if we have symbol flags.
                    // We deliberately do not use `ExportTarget::Address` for globals,
                    // since that is a different address space from functions.
                    (|| {
                        let local_global_index = export.index.checked_sub(local_global_base)?;
                        let x = global_values.get(local_global_index as usize)?.as_ref()?;
                        let flags = flags?;
                        if flags.contains(wasm::SYM_TLS) {
                            target = ExportTarget::Tls { offset: *x };
                        } else if flags.contains(wasm::SYM_ABSOLUTE) {
                            target = ExportTarget::Absolute { value: *x };
                        }
                        Some(())
                    })();
                } else if export.kind == wp::ExternalKind::Func {
                    if let Some(local_func_index) = export.index.checked_sub(local_func_base) {
                        // We know the code address for local functions.
                        if let Some(range) = code_ranges.get(local_func_index as usize) {
                            target = ExportTarget::Address { address: range.0 };
                        }
                    }
                }

                file.exports.push(WasmExportInternal {
                    name: export.name,
                    kind,
                    index: export.index,
                    target,
                    flags,
                });

                let (symbol_kind, section_idx) = match export.kind {
                    wp::ExternalKind::Func | wp::ExternalKind::FuncExact => {
                        if let Some(local_func_index) = export.index.checked_sub(local_func_base) {
                            let local_func_kind = local_func_kinds
                                .get_mut(local_func_index as usize)
                                .read_error("Invalid Wasm export index")?;
                            *local_func_kind = LocalFunctionKind::Exported;
                        }
                        (SymbolKind::Text, wasm::SEC_CODE)
                    }
                    wp::ExternalKind::Table
                    | wp::ExternalKind::Memory
                    | wp::ExternalKind::Global => (SymbolKind::Data, wasm::SEC_DATA),
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

                // TODO: never add symbols for exports?
                file.symbols.push(WasmSymbolInternal::synthetic(
                    export.name,
                    address,
                    size,
                    symbol_kind,
                    match file.section_index_for_id(section_idx) {
                        Some(index) => SymbolSection::Section(index),
                        None => SymbolSection::Unknown,
                    },
                    SymbolScope::Dynamic,
                    false,
                ));
            }
        }

        // Create synthetic symbols from the "name" custom section so the symbol map contains them.
        // Not needed for relocatable object files (and shouldn't be present in them anyway).
        if let Some(names) = names.filter(|_| !file.has_linking) {
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
                    file.symbols.push(WasmSymbolInternal::synthetic(
                        naming.name,
                        address,
                        size,
                        SymbolKind::Text,
                        match file.section_index_for_id(wasm::SEC_CODE) {
                            Some(index) => SymbolSection::Section(index),
                            None => SymbolSection::Unknown,
                        },
                        SymbolScope::Compilation,
                        false,
                    ));
                }
            }
        }

        Ok(file)
    }

    fn add_section(&mut self, id: wasm::SectionId, range: Range<usize>, name: &'data str) {
        let section = SectionHeader { id, range, name };
        if id != wasm::SEC_CUSTOM && id.0 as usize <= MAX_SECTION_ID {
            self.id_sections[id.0 as usize] = Some(SectionIndex(self.sections.len()));
        }
        self.sections.push(section);
    }

    fn section_index_for_id(&self, id: wasm::SectionId) -> Option<SectionIndex> {
        self.id_sections.get(id.0 as usize).copied().flatten()
    }

    fn data_segment_section_index(&self, index: WasmDataSegmentIndex) -> SectionIndex {
        SectionIndex(self.sections.len() + index.0 as usize)
    }

    fn data_segment_from_section_index(&self, index: SectionIndex) -> Option<WasmDataSegmentIndex> {
        let i = index.0.checked_sub(self.sections.len())?;
        Some(WasmDataSegmentIndex(i.try_into().ok()?))
    }

    /// Return the Wasm section with the given standard section id.
    pub fn wasm_section_by_id(&self, id: wasm::SectionId) -> Option<WasmSection<'data, '_, R>>
    where
        R: ReadRef<'data>,
    {
        let index = *self.id_sections.get(id.0 as usize)?.as_ref()?;
        self.wasm_section_by_index(index).ok()
    }

    /// Return the Wasm section at the given file-order index.
    ///
    /// This does not include synthesized data-segment sections.
    pub fn wasm_section_by_index(&self, index: SectionIndex) -> Result<WasmSection<'data, '_, R>>
    where
        R: ReadRef<'data>,
    {
        let section = self
            .sections
            .get(index.0)
            .read_error("Invalid Wasm file section index")?;
        Ok(WasmSection {
            file: self,
            inner: WasmSectionInner::Header {
                section_index: index,
                section,
            },
        })
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
        = WasmImportLibraryIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type ImportIterator<'file>
        = WasmImportIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type ExportIterator<'file>
        = WasmExportIterator<'data, 'file, R>
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
        } else if self.has_dylink {
            ObjectKind::Dynamic
        } else {
            ObjectKind::Executable
        }
    }

    fn segments(&self) -> Self::SegmentIterator<'_> {
        // Relocatable objects only expose data segments as sections.
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
        if let Some(segment_index) = self.data_segment_from_section_index(index) {
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
        self.wasm_section_by_index(index)
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
        Ok(WasmImportLibraryIterator {
            needed: self.needed.iter(),
            marker: PhantomData,
        })
    }

    fn imports(&self) -> Result<Self::ImportIterator<'_>> {
        if self.has_linking {
            return Ok(WasmImportIterator {
                imports: [].iter(),
                marker: PhantomData,
            });
        }
        Ok(WasmImportIterator {
            imports: self.imports.iter(),
            marker: PhantomData,
        })
    }

    fn exports(&self) -> Result<Self::ExportIterator<'_>> {
        if self.has_linking {
            return Ok(WasmExportIterator {
                exports: [].iter(),
                marker: PhantomData,
            });
        }
        Ok(WasmExportIterator {
            exports: self.exports.iter(),
            marker: PhantomData,
        })
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
        if let Some((index, section)) = self.sections.next() {
            return Some(WasmSection {
                file: self.file,
                inner: WasmSectionInner::Header {
                    section_index: SectionIndex(index),
                    section,
                },
            });
        }
        let (index, segment) = self.data_segments.next()?;
        Some(WasmSection {
            file: self.file,
            inner: WasmSectionInner::DataSegment {
                segment_index: WasmDataSegmentIndex(index as u32),
                segment,
            },
        })
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
        section_index: SectionIndex,
        section: &'file SectionHeader<'data>,
    },
    DataSegment {
        segment_index: WasmDataSegmentIndex,
        segment: &'file WasmDataSegmentInternal<'data>,
    },
}

impl<'data, 'file, R> WasmSection<'data, 'file, R> {
    /// File-order index of this section.
    ///
    /// Returns `None` for synthesized data-segment sections, which are not present in the Wasm binary.
    pub fn wasm_index(&self) -> Option<SectionIndex> {
        match self.inner {
            WasmSectionInner::Header { section_index, .. } => Some(section_index),
            WasmSectionInner::DataSegment { .. } => None,
        }
    }

    /// Standard Wasm section id.
    ///
    /// Returns `None` for synthesized data-segment sections.
    pub fn wasm_id(&self) -> Option<wasm::SectionId> {
        match self.inner {
            WasmSectionInner::Header { section, .. } => Some(section.id),
            WasmSectionInner::DataSegment { .. } => None,
        }
    }
}

impl<'data, 'file, R> read::private::Sealed for WasmSection<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectSection<'data> for WasmSection<'data, 'file, R> {
    type RelocationIterator = WasmRelocationIterator<'data, 'file, R>;

    #[inline]
    fn index(&self) -> SectionIndex {
        match self.inner {
            WasmSectionInner::Header { section_index, .. } => section_index,
            WasmSectionInner::DataSegment { segment_index, .. } => {
                self.file.data_segment_section_index(segment_index)
            }
        }
    }

    #[inline]
    fn address(&self) -> u64 {
        match self.inner {
            WasmSectionInner::Header { .. } => 0,
            WasmSectionInner::DataSegment { segment, .. } => segment.address,
        }
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
        Ok(read::util::data_range(
            self.data()?,
            self.address(),
            address,
            size,
        ))
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
                wasm::SEC_CUSTOM => section.name,
                wasm::SEC_TYPE => "<type>",
                wasm::SEC_IMPORT => "<import>",
                wasm::SEC_FUNCTION => "<function>",
                wasm::SEC_TABLE => "<table>",
                wasm::SEC_MEMORY => "<memory>",
                wasm::SEC_GLOBAL => "<global>",
                wasm::SEC_EXPORT => "<export>",
                wasm::SEC_START => "<start>",
                wasm::SEC_ELEMENT => "<element>",
                wasm::SEC_CODE => "<code>",
                wasm::SEC_DATA => "<data>",
                wasm::SEC_DATA_COUNT => "<data_count>",
                wasm::SEC_TAG => "<tag>",
                _ => "<unknown>",
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
                wasm::SEC_CUSTOM => match section.name {
                    "linking" => SectionKind::Linker,
                    name if name.starts_with("reloc.") => SectionKind::Linker,
                    _ => SectionKind::Other,
                },
                wasm::SEC_TYPE => SectionKind::Metadata,
                wasm::SEC_IMPORT => SectionKind::Linker,
                wasm::SEC_FUNCTION => SectionKind::Metadata,
                wasm::SEC_TABLE => SectionKind::Metadata,
                wasm::SEC_MEMORY => SectionKind::Metadata,
                wasm::SEC_GLOBAL => SectionKind::Metadata,
                wasm::SEC_EXPORT => SectionKind::Linker,
                wasm::SEC_START => SectionKind::Metadata,
                wasm::SEC_ELEMENT => SectionKind::Metadata,
                wasm::SEC_CODE => SectionKind::Text,
                wasm::SEC_DATA => SectionKind::Metadata,
                wasm::SEC_DATA_COUNT => SectionKind::Metadata,
                wasm::SEC_TAG => SectionKind::Metadata,
                _ => SectionKind::Unknown,
            },
            WasmSectionInner::DataSegment { segment, .. } => segment.section_kind(),
        }
    }

    #[inline]
    fn relocations(&self) -> WasmRelocationIterator<'data, 'file, R> {
        let (target, offset_range) = match self.inner {
            WasmSectionInner::Header {
                section_index,
                section,
            } => {
                if section.id == wasm::SEC_DATA {
                    (None, 0..u64::MAX)
                } else {
                    (Some(section_index), 0..u64::MAX)
                }
            }
            WasmSectionInner::DataSegment { segment, .. } => (
                self.file.id_sections[wasm::SEC_DATA.0 as usize],
                segment.section_offset..segment.section_offset + segment.data.len() as u64,
            ),
        };
        WasmRelocationIterator {
            target,
            type_section_index: self.file.section_index_for_id(wasm::SEC_TYPE),
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
    flags: SymbolFlags<SectionIndex, SymbolIndex>,
    export_name: Option<&'data str>,
}

impl<'data> WasmSymbolInternal<'data> {
    fn synthetic(
        name: &'data str,
        address: u64,
        size: u64,
        kind: SymbolKind,
        section: SymbolSection,
        scope: SymbolScope,
        weak: bool,
    ) -> Self {
        Self {
            name,
            address,
            size,
            kind,
            section,
            scope,
            weak,
            flags: SymbolFlags::None,
            export_name: None,
        }
    }
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
        self.symbol.flags
    }

    fn export_name(&self) -> Option<&'data str> {
        self.symbol.export_name
    }
}

/// An iterator for the relocations for a [`WasmSection`].
#[derive(Debug)]
pub struct WasmRelocationIterator<'data, 'file, R = &'data [u8]> {
    /// Binary index of the wasm section we are iterating relocations for.
    target: Option<SectionIndex>,
    type_section_index: Option<SectionIndex>,
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
                RelocationTarget::Section(
                    self.type_section_index.unwrap_or(SectionIndex(usize::MAX)),
                ),
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

#[derive(Clone, Debug)]
struct WasmImportInternal<'data> {
    module: &'data str,
    name: &'data str,
    kind: wasm::ExternalKind,
    index: u32,
    flags: Option<wasm::SymbolFlags>,
}

#[derive(Clone, Debug)]
struct WasmExportInternal<'data> {
    name: &'data str,
    kind: wasm::ExternalKind,
    index: u32,
    target: ExportTarget<'data>,
    flags: Option<wasm::SymbolFlags>,
}

/// An iterator for the import libraries in a [`WasmFile`].
///
/// Yields the needed libraries from the `dylink.0` custom section.
#[derive(Debug)]
pub struct WasmImportLibraryIterator<'data, 'file, R = &'data [u8]> {
    needed: slice::Iter<'file, &'data str>,
    marker: PhantomData<R>,
}

impl<'data, 'file, R> Iterator for WasmImportLibraryIterator<'data, 'file, R> {
    type Item = Result<ImportLibrary<'data>>;

    fn next(&mut self) -> Option<Self::Item> {
        let needed = self.needed.next()?;
        Some(Ok(ImportLibrary {
            name: needed.as_bytes(),
            flags: ImportLibraryFlags::None,
        }))
    }
}

/// An iterator for the imports in a [`WasmFile`].
#[derive(Debug)]
pub struct WasmImportIterator<'data, 'file, R = &'data [u8]> {
    imports: slice::Iter<'file, WasmImportInternal<'data>>,
    marker: PhantomData<R>,
}

impl<'data, 'file, R> Iterator for WasmImportIterator<'data, 'file, R> {
    type Item = Result<Import<'data>>;

    fn next(&mut self) -> Option<Self::Item> {
        let import = self.imports.next()?;
        Some(Ok(Import {
            // We use `library` to mean the needed entries from the `dylink.0` custom section,
            // which are not specified per import.
            library: &[],
            name: NameOrOrdinal::Name(import.name.as_bytes()),
            weak: import.flags.map(|f| f.binding()) == Some(wasm::SYM_BINDING_WEAK),
            flags: ImportFlags::Wasm {
                module: import.module,
                kind: import.kind,
                index: import.index,
                flags: import.flags,
            },
        }))
    }
}

/// An iterator for the exports in a [`WasmFile`].
#[derive(Debug)]
pub struct WasmExportIterator<'data, 'file, R = &'data [u8]> {
    exports: slice::Iter<'file, WasmExportInternal<'data>>,
    marker: PhantomData<R>,
}

impl<'data, 'file, R> Iterator for WasmExportIterator<'data, 'file, R> {
    type Item = Result<Export<'data>>;

    fn next(&mut self) -> Option<Self::Item> {
        let export = self.exports.next()?;
        Some(Ok(Export {
            name: NameOrOrdinal::Name(export.name.as_bytes().into()),
            target: export.target,
            weak: export.flags.map(|f| f.binding()) == Some(wasm::SYM_BINDING_WEAK),
            flags: ExportFlags::Wasm {
                kind: export.kind,
                index: export.index,
                flags: export.flags,
            },
        }))
    }
}
