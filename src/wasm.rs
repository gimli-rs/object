//! Wasm definitions.
//!
//! These definitions are independent of read/write support.

#![allow(missing_docs)]

newtype!(
    /// Flags from the `SegmentInfo` subsection of the `linking` custom section.
    struct SegmentFlags(u32);
);

// https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md#segment-info-subsection
newtype_flag_names!(NAMES_WASM_SEG: SegmentFlags(u32) = {
    /// The segment contains only null-terminated strings.
    WASM_SEG_FLAG_STRINGS = 0x1,
    /// The segment contains thread-local data.
    WASM_SEG_FLAG_TLS = 0x2,
    /// The segment should be retained in the output if its object is linked.
    WASM_SEG_FLAG_RETAIN = 0x4,
});

newtype!(
    /// The kind of an imported or exported item.
    struct ExternalKind(u8);
);

// https://webassembly.github.io/spec/core/binary/types.html#external-types
newtype_constant_names!(NAMES_WASM_EXTERNAL: ExternalKind(u8) = {
    WASM_EXTERNAL_FUNCTION = 0x00,
    WASM_EXTERNAL_TABLE = 0x01,
    WASM_EXTERNAL_MEMORY = 0x02,
    WASM_EXTERNAL_GLOBAL = 0x03,
    WASM_EXTERNAL_TAG = 0x04,
    WASM_EXTERNAL_FUNCTION_EXACT = 0x20,
});
