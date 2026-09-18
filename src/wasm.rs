//! Wasm definitions.
//!
//! These definitions are independent of read/write support.

#![allow(missing_docs)]

// These were accidentally re-exported before this module existed.
#[deprecated]
#[doc(hidden)]
#[cfg(feature = "read_core")]
pub use crate::read::wasm::*;

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
