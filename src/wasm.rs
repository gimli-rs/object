//! Wasm definitions.
//!
//! These definitions are independent of read/write support.

#![allow(missing_docs)]

newtype!(
    /// Flags from the `SegmentInfo` subsection of the `linking` custom section.
    struct SegmentFlags(u32);
);

newtype_flag_names!(NAMES_WASM_SEG: SegmentFlags(u32) = {
    /// The segment contains only null-terminated strings.
    WASM_SEG_FLAG_STRINGS = 0x1,
    /// The segment contains thread-local data.
    WASM_SEG_FLAG_TLS = 0x2,
    /// The segment should be retained in the output if its object is linked.
    WASM_SEG_FLAG_RETAIN = 0x4,
});
