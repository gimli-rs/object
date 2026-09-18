//! Wasm definitions.
//!
//! These definitions are independent of read/write support.

#![allow(missing_docs)]

newtype!(
    /// Flags for a symbol, import or export.
    ///
    /// These appear in the symbol table subsection of the `linking` custom section,
    /// and the import info and export info subsections of the `dylink.0` custom section.
    struct SymbolFlags(u32);
);

impl SymbolFlags {
    /// Get the `binding` field.
    pub fn binding(self) -> SymbolBinding {
        SymbolBinding(self.0 & SYM_BINDING_MASK)
    }

    /// Set the `binding` field.
    pub fn with_binding(self, binding: SymbolBinding) -> Self {
        SymbolFlags(self.0 & !SYM_BINDING_MASK) | SymbolFlags::from(binding)
    }

    /// Get the `visibility` field.
    pub fn visibility(self) -> SymbolVisibility {
        SymbolVisibility(self.0 & SYM_VISIBILITY_MASK)
    }

    /// Set the `visibility` field.
    pub fn with_visibility(self, visibility: SymbolVisibility) -> Self {
        SymbolFlags(self.0 & !SYM_VISIBILITY_MASK) | SymbolFlags::from(visibility)
    }
}

// https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md#symbol-table-subsection
newtype_flag_names!(NAMES_SYM: SymbolFlags(u32) = {
    SYM_BINDING_MASK = 0x3 => NAMES_SYM_BINDING,
    SYM_VISIBILITY_MASK = 0xc => NAMES_SYM_VISIBILITY,
    /// This symbol is not defined.
    SYM_UNDEFINED = 0x10,
    /// The symbol is intended to be exported from the wasm module to the host environment.
    SYM_EXPORTED = 0x20,
    /// The symbol uses an explicit symbol name, rather than reusing the name from a wasm import.
    SYM_EXPLICIT_NAME = 0x40,
    /// The symbol is intended to be included in the linker output, regardless of whether it is used by the program.
    SYM_NO_STRIP = 0x80,
    /// The symbol resides in thread local storage.
    SYM_TLS = 0x100,
    /// The symbol represents an absolute address.
    SYM_ABSOLUTE = 0x200,
});

newtype!(
    /// Binding for a symbol, import or export.
    struct SymbolBinding(u32);
);

newtype_constant_names!(NAMES_SYM_BINDING: SymbolBinding(u32) = {
    /// This is a strong global symbol.
    SYM_BINDING_GLOBAL = 0,
    /// This is a weak symbol.
    SYM_BINDING_WEAK = 1,
    /// This is a local symbol.
    SYM_BINDING_LOCAL = 2,
    /// This is a common symbol (only valid for defined data symbols).
    SYM_BINDING_COMMON = 3,
});

impl From<SymbolBinding> for SymbolFlags {
    fn from(value: SymbolBinding) -> Self {
        SymbolFlags(value.0 & SYM_BINDING_MASK)
    }
}

impl From<SymbolFlags> for SymbolBinding {
    fn from(value: SymbolFlags) -> Self {
        value.binding()
    }
}

newtype!(
    /// Visibility for a symbol.
    struct SymbolVisibility(u32);
);

newtype_constant_names!(NAMES_SYM_VISIBILITY: SymbolVisibility(u32) = {
    SYM_VISIBILITY_DEFAULT = 0 << 2,
    /// This is a hidden symbol.
    SYM_VISIBILITY_HIDDEN = 1 << 2,
});

impl From<SymbolVisibility> for SymbolFlags {
    fn from(value: SymbolVisibility) -> Self {
        SymbolFlags(value.0 & SYM_VISIBILITY_MASK)
    }
}

impl From<SymbolFlags> for SymbolVisibility {
    fn from(value: SymbolFlags) -> Self {
        value.visibility()
    }
}

newtype!(
    /// Flags from the segment info subsection of the `linking` custom section.
    struct SegmentFlags(u32);
);

// https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md#segment-info-subsection
newtype_flag_names!(NAMES_SEG_FLAG: SegmentFlags(u32) = {
    /// The segment contains only null-terminated strings.
    SEG_FLAG_STRINGS = 0x1,
    /// The segment contains thread-local data.
    SEG_FLAG_TLS = 0x2,
    /// The segment should be retained in the output if its object is linked.
    SEG_FLAG_RETAIN = 0x4,
});

newtype!(
    /// The kind of an imported or exported item.
    struct ExternalKind(u8);
);

// https://webassembly.github.io/spec/core/binary/types.html#external-types
newtype_constant_names!(NAMES_EXTERNAL: ExternalKind(u8) = {
    EXTERNAL_FUNCTION = 0x00,
    EXTERNAL_TABLE = 0x01,
    EXTERNAL_MEMORY = 0x02,
    EXTERNAL_GLOBAL = 0x03,
    EXTERNAL_TAG = 0x04,
    EXTERNAL_FUNCTION_EXACT = 0x20,
});

/// The 4-byte magic number at the start of every Wasm module.
pub const MAGIC: [u8; 4] = [0x00, b'a', b's', b'm'];
/// The little-endian version number.
pub const VERSION: u32 = 1;
/// Version number at the start of the `linking` custom section.
///
/// <https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md#linking-metadata-section>
pub const LINKING_VERSION: u32 = 2;

pub const LINKING_SECTION_NAME: &str = "linking";
pub const RELOC_SECTION_PREFIX: &str = "reloc.";
pub const TARGET_FEATURES_SECTION_NAME: &str = "target_features";
pub const NAME_SECTION_NAME: &str = "name";
pub const DYLINK0_SECTION_NAME: &str = "dylink.0";
pub const DYLINK_SECTION_NAME: &str = "dylink";

/// Feature is used by this object (`+` in the `target_features` section).
pub const FEATURE_PREFIX_USED: u8 = b'+';
/// Feature must not appear in the output (`-` in the `target_features` section).
pub const FEATURE_PREFIX_DISALLOWED: u8 = b'-';

newtype!(
    /// A standard Wasm section id.
    struct SectionId(u8);
);

// https://webassembly.github.io/spec/core/binary/modules.html#sections
newtype_constant_names!(NAMES_SEC: SectionId(u8) = {
    /// A custom section.
    SEC_CUSTOM = 0,
    /// Function signature declarations.
    SEC_TYPE = 1,
    /// Import declarations.
    SEC_IMPORT = 2,
    /// Function declarations.
    SEC_FUNCTION = 3,
    /// Indirect function table and other tables.
    SEC_TABLE = 4,
    /// Memory attributes.
    SEC_MEMORY = 5,
    /// Global declarations.
    SEC_GLOBAL = 6,
    /// Exports.
    SEC_EXPORT = 7,
    /// Start function declaration.
    SEC_START = 8,
    /// Elements section.
    SEC_ELEMENT = 9,
    /// Function bodies.
    SEC_CODE = 10,
    /// Data segments.
    SEC_DATA = 11,
    /// Data count section.
    SEC_DATA_COUNT = 12,
    /// Tag / event declarations.
    SEC_TAG = 13,
});

newtype!(
    /// Kind of a symbol in the `linking` symbol table.
    struct SymbolKind(u8);
);

// https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md#symbol-table-subsection
newtype_constant_names!(NAMES_SYM_TYPE: SymbolKind(u8) = {
    SYM_TYPE_FUNCTION = 0,
    SYM_TYPE_DATA = 1,
    SYM_TYPE_GLOBAL = 2,
    SYM_TYPE_SECTION = 3,
    SYM_TYPE_EVENT = 4,
    SYM_TYPE_TABLE = 5,
});

newtype!(
    /// Kind of a member in the `linking` `ComdatInfo` subsection.
    struct ComdatKind(u8);
);

// https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md#comdat-info-subsection
newtype_constant_names!(NAMES_COMDAT: ComdatKind(u8) = {
    COMDAT_DATA = 0,
    COMDAT_FUNCTION = 1,
    COMDAT_GLOBAL = 2,
    COMDAT_EVENT = 3,
    COMDAT_TABLE = 4,
    COMDAT_SECTION = 5,
});

newtype!(
    /// Subsection type of the `linking` custom section.
    struct LinkingSubsection(u8);
);

// https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md#linking-metadata-section
newtype_constant_names!(NAMES_LINKING: LinkingSubsection(u8) = {
    LINKING_SEGMENT_INFO = 5,
    LINKING_INIT_FUNCS = 6,
    LINKING_COMDAT_INFO = 7,
    LINKING_SYMBOL_TABLE = 8,
});

newtype!(
    /// Subsection type of the `dylink.0` custom section.
    struct DylinkSubsection(u8);
);

// https://github.com/WebAssembly/tool-conventions/blob/main/DynamicLinking.md
newtype_constant_names!(NAMES_DYLINK: DylinkSubsection(u8) = {
    DYLINK_MEM_INFO = 1,
    DYLINK_NEEDED = 2,
    DYLINK_EXPORT_INFO = 3,
    DYLINK_IMPORT_INFO = 4,
    DYLINK_RUNTIME_PATH = 5,
});

newtype!(
    /// Subsection type of the `name` custom section.
    struct NameSubsection(u8);
);

// https://webassembly.github.io/spec/core/appendix/custom.html#name-section
newtype_constant_names!(NAMES_NAME: NameSubsection(u8) = {
    NAME_MODULE = 0,
    NAME_FUNCTION = 1,
    NAME_LOCAL = 2,
    NAME_LABELS = 3,
    NAME_TYPE = 4,
    NAME_TABLE = 5,
    NAME_MEMORY = 6,
    NAME_GLOBAL = 7,
    NAME_ELEM = 8,
    NAME_DATA = 9,
    NAME_FIELD = 10,
    NAME_TAG = 11,
});

newtype!(
    /// A Wasm relocation type (`R_WASM_*`).
    struct RelocationType(u8);
);

// https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md#relocation-sections
// PIC / TLS types are listed in: https://github.com/WebAssembly/tool-conventions/blob/main/DynamicLinking.md
newtype_constant_names!(NAMES_R: RelocationType(u8) = {
    R_WASM_FUNCTION_INDEX_LEB = 0,
    R_WASM_TABLE_INDEX_SLEB = 1,
    R_WASM_TABLE_INDEX_I32 = 2,
    R_WASM_MEMORY_ADDR_LEB = 3,
    R_WASM_MEMORY_ADDR_SLEB = 4,
    R_WASM_MEMORY_ADDR_I32 = 5,
    R_WASM_TYPE_INDEX_LEB = 6,
    R_WASM_GLOBAL_INDEX_LEB = 7,
    R_WASM_FUNCTION_OFFSET_I32 = 8,
    R_WASM_SECTION_OFFSET_I32 = 9,
    R_WASM_EVENT_INDEX_LEB = 10,
    R_WASM_MEMORY_ADDR_REL_SLEB = 11,
    R_WASM_TABLE_INDEX_REL_SLEB = 12,
    R_WASM_GLOBAL_INDEX_I32 = 13,
    R_WASM_MEMORY_ADDR_LEB64 = 14,
    R_WASM_MEMORY_ADDR_SLEB64 = 15,
    R_WASM_MEMORY_ADDR_I64 = 16,
    R_WASM_MEMORY_ADDR_REL_SLEB64 = 17,
    R_WASM_TABLE_INDEX_SLEB64 = 18,
    R_WASM_TABLE_INDEX_I64 = 19,
    R_WASM_TABLE_NUMBER_LEB = 20,
    R_WASM_MEMORY_ADDR_TLS_SLEB = 21,
    R_WASM_FUNCTION_OFFSET_I64 = 22,
    R_WASM_MEMORY_ADDR_LOCREL_I32 = 23,
    R_WASM_TABLE_INDEX_REL_SLEB64 = 24,
    R_WASM_MEMORY_ADDR_TLS_SLEB64 = 25,
    R_WASM_FUNCTION_INDEX_I32 = 26,
});

impl RelocationType {
    /// Number of bytes this relocation overwrites.
    pub const fn extent(self) -> Option<u8> {
        Some(match self {
            R_WASM_FUNCTION_INDEX_LEB
            | R_WASM_TABLE_INDEX_SLEB
            | R_WASM_MEMORY_ADDR_LEB
            | R_WASM_MEMORY_ADDR_SLEB
            | R_WASM_TYPE_INDEX_LEB
            | R_WASM_GLOBAL_INDEX_LEB
            | R_WASM_EVENT_INDEX_LEB
            | R_WASM_MEMORY_ADDR_REL_SLEB
            | R_WASM_TABLE_INDEX_REL_SLEB
            | R_WASM_TABLE_NUMBER_LEB
            | R_WASM_MEMORY_ADDR_TLS_SLEB => 5,
            R_WASM_TABLE_INDEX_I32
            | R_WASM_MEMORY_ADDR_I32
            | R_WASM_FUNCTION_OFFSET_I32
            | R_WASM_SECTION_OFFSET_I32
            | R_WASM_GLOBAL_INDEX_I32
            | R_WASM_MEMORY_ADDR_LOCREL_I32
            | R_WASM_FUNCTION_INDEX_I32 => 4,
            R_WASM_MEMORY_ADDR_LEB64
            | R_WASM_MEMORY_ADDR_SLEB64
            | R_WASM_TABLE_INDEX_SLEB64
            | R_WASM_TABLE_INDEX_REL_SLEB64
            | R_WASM_MEMORY_ADDR_REL_SLEB64
            | R_WASM_MEMORY_ADDR_TLS_SLEB64 => 10,
            R_WASM_MEMORY_ADDR_I64 | R_WASM_TABLE_INDEX_I64 | R_WASM_FUNCTION_OFFSET_I64 => 8,
            _ => return None,
        })
    }

    /// Whether a `reloc.*` entry of this type carries an explicit addend.
    pub const fn has_addend(self) -> bool {
        matches!(
            self,
            R_WASM_MEMORY_ADDR_LEB
                | R_WASM_MEMORY_ADDR_SLEB
                | R_WASM_MEMORY_ADDR_I32
                | R_WASM_FUNCTION_OFFSET_I32
                | R_WASM_SECTION_OFFSET_I32
                | R_WASM_MEMORY_ADDR_LOCREL_I32
                | R_WASM_MEMORY_ADDR_REL_SLEB
                | R_WASM_MEMORY_ADDR_TLS_SLEB
                | R_WASM_MEMORY_ADDR_REL_SLEB64
                | R_WASM_MEMORY_ADDR_TLS_SLEB64
                | R_WASM_MEMORY_ADDR_LEB64
                | R_WASM_MEMORY_ADDR_SLEB64
                | R_WASM_MEMORY_ADDR_I64
                | R_WASM_FUNCTION_OFFSET_I64
        )
    }
}
