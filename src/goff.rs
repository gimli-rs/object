//! GOFF definitions
//!
//! These definitions are independent of read/write support, although we do implement
//! some traits useful for those.
//!
//! This module is based of the official documentation for z/OS <https://www.ibm.com/docs/en/zos/3.2.0?topic=goff-record-formats>

#![allow(missing_docs)]

use crate::endian::{BigEndian as BE, U16, U32};
use crate::pod::Pod;

// Get bits using IBM bit numbering.
const fn get_bits(val: u8, index: u8, length: u8) -> u8 {
    let shift = 8 - index - length;
    let mask = u8::MAX >> (8 - length);
    (val >> shift) & mask
}

// Set bits using IBM bit numbering.
const fn set_bits(val: &mut u8, index: u8, length: u8, new_val: u8) {
    let shift = 8 - index - length;
    let mask = u8::MAX >> (8 - length);
    *val = (*val & !(mask << shift)) | ((new_val & mask) << shift);
}

/// Helper for implementing `Debug` for bit fields using getter and setter methods.
///
/// The setters are used to clear each field so that any remaining bits can be printed.
struct DebugBitFields<'a, 'b, T> {
    f: &'a mut core::fmt::Formatter<'b>,
    result: core::fmt::Result,
    sep: &'static str,
    value: T,
    unused: T,
}

impl<'a, 'b, T: Copy> DebugBitFields<'a, 'b, T> {
    fn new(f: &'a mut core::fmt::Formatter<'b>, value: T) -> Self {
        DebugBitFields {
            f,
            result: Ok(()),
            sep: "",
            value,
            unused: value,
        }
    }

    /// Always print the field.
    fn field<V: core::fmt::Debug + Default>(
        &mut self,
        get: fn(T) -> V,
        set: fn(T, V) -> T,
    ) -> &mut Self {
        if cfg!(feature = "names") && self.result.is_ok() {
            self.result = write!(self.f, "{}{:?}", self.sep, get(self.value));
            self.sep = " | ";
            self.unused = set(self.unused, V::default());
        }
        self
    }

    /// Print the name if the flag is set.
    fn flag(&mut self, name: &str, get: fn(T) -> bool, set: fn(T, bool) -> T) -> &mut Self {
        if cfg!(feature = "names") && self.result.is_ok() {
            if get(self.value) {
                self.result = write!(self.f, "{}{}", self.sep, name);
                self.sep = " | ";
            }
            self.unused = set(self.unused, false);
        }
        self
    }

    /// Print the name and value if the value is non-zero.
    fn value(&mut self, name: &str, get: fn(T) -> u8, set: fn(T, u8) -> T) -> &mut Self {
        if cfg!(feature = "names") && self.result.is_ok() {
            let val = get(self.value);
            if val != 0 {
                self.result = write!(self.f, "{}{}({})", self.sep, name, val);
                self.sep = " | ";
            }
            self.unused = set(self.unused, 0);
        }
        self
    }

    /// Print any remaining bits, using `bytes` to convert the value to bytes.
    fn finish<const N: usize>(&mut self, bytes: fn(T) -> [u8; N]) -> core::fmt::Result {
        self.result?;
        for (i, &val) in bytes(self.unused).iter().enumerate() {
            if val != 0 {
                write!(self.f, "{}B{}(0x{:02x})", self.sep, i, val)?;
                self.sep = " | ";
            }
        }
        if self.sep.is_empty() {
            self.f.write_str("0")?;
        }
        Ok(())
    }
}

/// The module header ("HDR") record at the start of every 64-bit GOFF file.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct HeaderRecord64 {
    /// Type of record. Must be 0x03F000.
    pub ptv: [u8; 3],
    /// Reserved. Must be 45 bytes of 0.
    pub reserved1: [u8; 45],
    /// Architecture Level. Must be 1.
    pub archlvl: U32<BE>,
    /// Reserved. Must be 28 bytes of 0.
    pub reserved2: [u8; 28],
}

/// ESD data has 8 bytes till the end of the record
/// (longer symbol names are finished in continuation records)
pub const SIZEOF_ESD_DATA: usize = 8;

/// The external symbol definition ("ESD") record.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SymbolRecord64 {
    /// Type of record. Must be 0x030000 or 0x030100.
    pub ptv: [u8; 3],
    /// Symbol Type.
    pub symbol_type: SymbolType,
    /// ESD Identifier (ESDID).
    pub esdid: U32<BE>,
    /// Parent of Owning ESDID
    pub parent_esdid: U32<BE>,
    /// Reserved. Must be 4 bytes of 0.
    pub reserved1: U32<BE>,
    /// Offset.
    pub offset: U32<BE>,
    /// Reserved. Must be 4 bytes of 0.
    pub reserved2: U32<BE>,
    /// Length (size of allocated memory of program element or section)
    pub length: U32<BE>,
    /// Extended Attribute ESDID
    pub ea_esdid: U32<BE>,
    /// Extended Attribute Data Offset
    pub ea_data_offset: U32<BE>,
    /// Reserved. Must be 4 bytes of 0.
    pub reserved3: U32<BE>,
    /// Name Space ID
    pub namespace_id: EsdNameSpace,
    /// Symbol Flags.
    pub sym_flags: u8,
    /// Fill Byte Value (the specific 1-byte value used to pad memory)
    pub fill_byte_value: u8,
    /// Reserved. Must be 1 bytes of 0.
    pub reserved4: u8,
    /// Associated data ID
    pub ada_esdid: U32<BE>,
    /// Priority
    pub priority: U32<BE>,
    /// Reserved. Must be 8 bytes of 0.
    pub reserved5: [u8; 8],
    /// Behavioral Attributes
    pub behavioral_attributes: BehavioralAttributes,
    /// Name Length
    pub name_length: U16<BE>,
    /// Name
    pub name: [u8; SIZEOF_ESD_DATA],
}

/// TXT data has 56 bytes till the end of the record,
/// can be finished in a continuation record
pub const SIZEOF_TXT_DATA: usize = 56;

/// The text ("TXT") record.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TextRecord64 {
    /// Type of record. Must be 0x031000 or 0x031100.
    pub ptv: [u8; 3],
    /// Text Record Style
    pub record_style: TextRecordStyle,
    /// Element ESDID
    pub element_esdid: U32<BE>,
    /// Reserved. Must be 4 bytes of 0.
    pub reserved1: U32<BE>,
    /// Offset.
    pub offset: U32<BE>,
    /// Text Field True Length
    pub true_length: U32<BE>,
    /// Text Encoding
    pub text_encoding: U16<BE>,
    /// Data Length
    pub data_length: U16<BE>,
    /// Data
    pub data: [u8; SIZEOF_TXT_DATA],
}

/// Each continuation record will have a payload of 77 bytes
pub const SIZEOF_RELOCATION_DATA: usize = 74;

/// A single relocation data item within an RLD record.
/// Size is variable (8-28 bytes) depending on which fields are present as determined by the Flags field.
/// The relocation directory ("RLD") record.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RelocationRecord64 {
    /// Type of record. Must be 0x032000 or 0x032100.
    pub ptv: [u8; 3],
    /// Reserved. Must be 1 byte of 0.
    pub reserved: u8,
    /// Length.
    pub length: U16<BE>,
    /// Relocation Data
    pub data: [u8; SIZEOF_RELOCATION_DATA],
}

/// Each continuation record will have a payload of 77 bytes
pub const SIZEOF_CONTINUATION_RECORD_DATA: usize = 77;

/// The generic continuation record.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ContinuationRecord64 {
    /// Type of record.
    pub ptv: [u8; 3],
    /// Payload.
    pub data: [u8; SIZEOF_CONTINUATION_RECORD_DATA],
}

/// Size of element length data is max 72 bytes
pub const SIZEOF_DEFERRED_LEN_DATA: usize = 72;

/// Deferred-length ("LEN") record
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct LenRecord64 {
    /// Type of record.
    pub ptv: [u8; 3],
    /// Reserved data.
    pub reserved: [u8; 3],
    /// Length of data (i.e. total bytes of data items in data)
    pub length: U16<BE>,
    /// Payload of [`LengthDataItem`]
    pub data: [u8; SIZEOF_DEFERRED_LEN_DATA],
}

/// Deferred element-length data item
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct LengthDataItem {
    /// ESDID of the element for which this length value is supplied.
    pub esdid: U32<BE>,
    /// Reserved data.
    pub reserved: [u8; 4],
    /// Length of element
    pub length: U32<BE>,
}

/// Each entry point name will have a size of 54 bytes
pub const SIZEOF_ENTRY_POINT_NAME: usize = 54;

/// The module end ("END") record at the end of every 64-bit GOFF file.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct EndRecord64 {
    /// Type of record. Must be 0x034000.
    pub ptv: [u8; 3],
    /// Flags.  Upper 6 bits are reserved to 0
    pub flags: u8,
    /// AMODE.
    pub amode: u8,
    /// Reserved. Must be 3 bytes of 0.
    pub reserved1: [u8; 3],
    /// Record Count.
    pub record_cnt: U32<BE>,
    /// ESDID
    pub esdid: U32<BE>,
    /// Reserved. Must be 4 bytes of 0.
    pub reserved2: [u8; 4],
    /// Translator-assigned offset of the module entry point.
    pub offset: U32<BE>,
    /// Entry point name length.
    pub name_length: U16<BE>,
    /// Entry point name (first 54 bytes)
    pub entry_name: [u8; SIZEOF_ENTRY_POINT_NAME],
}

/// Only fixed length records are supported (UNIX compatible file
/// systems only support fixed length records). Each record is exactly
/// 80 bytes, unused space must be padded
pub const RECORD_LEN: u64 = 80;

newtype!(
    /// Values for `FileEnd64::flags`.
    ///
    /// The lower 2 bits indicate entry point presence/type.
    /// Upper 6 bits are reserved and must be 0.
    #[repr(transparent)]
    struct FileFlags(u8);
);

newtype_constant_names!(NAMES_F_FLAGS: FileFlags(u8) = {
    /// No entry point is suggested or requested.
    /// No subsequent fields (other than Record Count) are valid.
    F_NO_ENTRY_POINT = 0x00,
    /// Entry point requested by internal offset and ESDID.
    /// ESDID can be EDID (within module) or ERID (external reference).
    F_ENTRY_BY_OFFSET = 0x01,
    /// Entry point requested by external name.
    /// ESDID and Offset fields must be zero.
    F_ENTRY_BY_NAME = 0x02,
    /// Reserved value.
    F_ENTRY_RESERVED = 0x03,
});

/// Mask for the entry point indicator bits (lower 2 bits)
pub const F_ENTRY_MASK: u8 = 0x03;

newtype!(
    /// GOFF record type values.
    ///
    /// These appear in the second byte of the `ptv` field (bits masked with 0xFC).
    #[repr(transparent)]
    struct RecordType(u8);
);

newtype_constant_names!(NAMES_RECORD_TYPE: RecordType(u8) = {
    /// External Symbol Dictionary record.
    RT_ESD = 0x00,
    /// Text (code/data) record.
    RT_TXT = 0x10,
    /// Relocation Dictionary record.
    RT_RLD = 0x20,
    /// Length record (continuation).
    RT_LEN = 0x30,
    /// End of module record.
    RT_END = 0x40,
    /// Module header record.
    RT_HDR = 0xF0,
});

// Values for `ptv`, the GOFF Record prefix
//
/// GOFF Record Prefix (every GOFF file begins with this)
pub const GOFF_PREFIX: u8 = 0x03;
/// GOFF Version (only supported version)
pub const GOFF_VERSION: u8 = 0x00;
/// The GOFF HDR Record Magic Number
pub const GOFF_HDR_BYTES: [u8; 3] = [GOFF_PREFIX, RT_HDR.0, GOFF_VERSION];
/// The GOFF ESD Record Magic Number
pub const GOFF_ESD_BYTES: [u8; 3] = [GOFF_PREFIX, RT_ESD.0, GOFF_VERSION];
/// The GOFF TXT Record Magic Number
pub const GOFF_TXT_BYTES: [u8; 3] = [GOFF_PREFIX, RT_TXT.0, GOFF_VERSION];
/// The GOFF RLD Record Magic Number
pub const GOFF_RLD_BYTES: [u8; 3] = [GOFF_PREFIX, RT_RLD.0, GOFF_VERSION];
/// The GOFF LEN Record Magic Number
pub const GOFF_LEN_BYTES: [u8; 3] = [GOFF_PREFIX, RT_LEN.0, GOFF_VERSION];
/// The GOFF END Record Magic Number
pub const GOFF_END_BYTES: [u8; 3] = [GOFF_PREFIX, RT_END.0, GOFF_VERSION];

newtype!(
    /// GOFF symbol type values from ESD records.
    #[repr(transparent)]
    struct SymbolType(u8);
);

newtype_constant_names!(NAMES_ESD_ST: SymbolType(u8) = {
    /// Section Definition (SD) - defines a control section.
    ESD_ST_SD = 0,
    /// Element Definition (ED) - defines an element (part/class).
    ESD_ST_ED = 1,
    /// Label Definition (LD) - defines a label within a section.
    ESD_ST_LD = 2,
    /// Part Reference (PR) - references a part of an element.
    ESD_ST_PR = 3,
    /// External Reference (ER) - references an external symbol.
    ESD_ST_ER = 4,
});

newtype!(
    /// ESD Namespace
    #[repr(transparent)]
    struct EsdNameSpace(u8);
);

newtype_constant_names!(NAMES_ESD_NAMESPACE: EsdNameSpace(u8) = {
    ESD_NS_PROGRAM_MANAGEMENT_BINDER = 0,
    ESD_NS_NORMAL_NAME = 1,
    ESD_NS_PSEUDO_REGISTER = 2,
    ESD_NS_PARTS = 3,
});

newtype!(
    /// Text Record Style
    #[repr(transparent)]
    struct TextRecordStyle(u8);
);

newtype_constant_names!(NAMES_TXT_RS: TextRecordStyle(u8) = {
    TXT_RS_BYTE = 0,
    TXT_RS_STRUCTURED = 1,
    TXT_RS_UNSTRUCTURED = 2,
});

/// All GOFF records have a 3-byte identifying prefix of the following form.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RecordPrefix {
    /// Magic Number Prefix, always 0x03 (distinguishes GOFF records from OBJ records)
    pub prefix: u8,
    /// The record type (first 4 bits) and continuation flags (last two bits)
    pub type_and_cont: u8,
    ///  The version number (always 0x00)
    pub version: u8,
}

impl RecordPrefix {
    /// Determines if the GOFF record prefix is valid
    pub fn is_valid(self) -> bool {
        self.prefix == GOFF_PREFIX && self.version == GOFF_VERSION
    }
    /// Returns the record type of a GOFF record
    pub fn record_type(self) -> RecordType {
        RecordType(self.type_and_cont & 0xFC)
    }
    /// Determines if the record is a continuation of the previous record
    pub fn is_continuation(self) -> bool {
        (self.type_and_cont & 0x02) == 0x02
    }
    /// Determines if the record will be continued on the succeeding record
    pub fn is_continued(self) -> bool {
        (self.type_and_cont & 0x01) == 0x01
    }
}

newtype!(
    /// GOFF Addressing Mode (AMODE) - Byte 0 of behavioral attributes
    #[repr(transparent)]
    struct Amode(u8);
);

newtype_constant_names!(NAMES_AMODE: Amode(u8) = {
    /// AMODE not specified (default=24)
    AMODE_UNSPEC = 0x00,
    /// AMODE(24)
    AMODE_24 = 0x01,
    /// AMODE(31)
    AMODE_31 = 0x02,
    /// AMODE(ANY) - either 24-bit or 31-bit
    AMODE_ANY = 0x03,
    /// AMODE(64)
    AMODE_64 = 0x04,
    /// AMODE(MIN) - binder can set to minimum AMODE
    AMODE_MIN = 0x10,
});

newtype!(
    /// GOFF Residence Mode (RMODE) - Byte 1 of behavioral attributes
    #[repr(transparent)]
    struct Rmode(u8);
);

newtype_constant_names!(NAMES_RMODE: Rmode(u8) = {
    /// RMODE not specified (default=24)
    RMODE_UNSPEC = 0x00,
    /// RMODE(24)
    RMODE_24 = 0x01,
    /// RMODE(31) - equivalent to OBJ RMODE(ANY)
    RMODE_31 = 0x03,
    /// RMODE(64)
    RMODE_64 = 0x04,
});

newtype!(
    /// GOFF Binding Algorithm - Byte 2 bits 4-7 of behavioral attributes
    #[repr(transparent)]
    struct BindingAlgorithm(u8);
);

newtype_constant_names!(NAMES_ESD_BA: BindingAlgorithm(u8) = {
    /// Concatenate - sections placed end to end
    ESD_BA_CONCATENATE = 0,
    /// Merge - identically named parts merged
    ESD_BA_MERGE = 1,
});

newtype!(
    /// GOFF Tasking Behavior - Byte 3 bits 0-2 of behavioral attributes
    #[repr(transparent)]
    struct TaskingBehavior(u8);
);

newtype_constant_names!(NAMES_TASK: TaskingBehavior(u8) = {
    /// Unspecified
    TASK_UNSPEC = 0x00,
    /// NON-REUS - Not serially reusable
    TASK_NON_REUS = 0x01,
    /// REUS - Serially reusable
    TASK_REUS = 0x02,
    /// RENT - Reentrant
    TASK_RENT = 0x03,
});

newtype!(
    /// GOFF Executable Indicator - Byte 3 bits 5-7 of behavioral attributes
    #[repr(transparent)]
    struct Executable(u8);
);

newtype_constant_names!(NAMES_EXEC: Executable(u8) = {
    /// Not specified
    EXEC_UNSPEC = 0,
    /// Not executable (data)
    EXEC_DATA = 1,
    /// Executable (code)
    EXEC_CODE = 2,
});

newtype!(
    /// GOFF Duplicate Symbol Severity - Byte 4 bits 2-3 of behavioral attributes
    #[repr(transparent)]
    struct DuplicateSymbolSeverity(u8);
);

newtype_constant_names!(NAMES_ESD_DSS: DuplicateSymbolSeverity(u8) = {
    /// Severity determined by the binder.
    ESD_DSS_NO_WARNING = 0,
    /// Severity should be at least 4 (warning).
    ESD_DSS_WARNING = 1,
    /// Severity should be at least 8 (error).
    ESD_DSS_ERROR = 2,
});

newtype!(
    /// GOFF Binding Strength - Byte 4 bits 4-7 of behavioral attributes
    #[repr(transparent)]
    struct BindingStrength(u8);
);

newtype_constant_names!(NAMES_ESD_BST: BindingStrength(u8) = {
    /// Strong reference/definition
    ESD_BST_STRONG = 0,
    /// Weak reference/definition
    ESD_BST_WEAK = 1,
});

newtype!(
    /// GOFF Loading Behavior - Byte 5 bits 0-1 of behavioral attributes
    #[repr(transparent)]
    struct LoadingBehavior(u8);
);

newtype_constant_names!(NAMES_LOAD: LoadingBehavior(u8) = {
    /// Load with module
    LOAD_INITIAL = 0x00,
    /// Deferred load
    LOAD_DEFERRED = 0x01,
    /// Do not load with module
    LOAD_NONE = 0x02,
});

newtype!(
    /// GOFF Binding Scope - Byte 5 bits 4-7 of behavioral attributes
    #[repr(transparent)]
    struct BindingScope(u8);
);

newtype_constant_names!(NAMES_ESD_BSC: BindingScope(u8) = {
    /// Unspecified
    ESD_BSC_UNSPEC = 0x00,
    /// Section (local)
    ESD_BSC_SECTION = 0x01,
    /// Module (global)
    ESD_BSC_MODULE = 0x02,
    /// Library
    ESD_BSC_LIBRARY = 0x03,
    /// Import-Export
    ESD_BSC_IMPORT_EXPORT = 0x04,
});

newtype!(
    /// GOFF Alignment - Byte 6 bits 3-7 of behavioral attributes
    #[repr(transparent)]
    struct Alignment(u8);
);

newtype_constant_names!(NAMES_ALIGN: Alignment(u8) = {
    /// Byte alignment
    ALIGN_BYTE = 0,
    /// Halfword alignment
    ALIGN_HALFWORD = 1,
    /// Fullword alignment
    ALIGN_FULLWORD = 2,
    /// Doubleword alignment
    ALIGN_DOUBLEWORD = 3,
    /// Quadword alignment
    ALIGN_QUADWORD = 4,
    /// 32 byte alignment
    ALIGN_32BYTE = 5,
    /// 64 byte alignment
    ALIGN_64BYTE = 6,
    /// 128 byte alignment
    ALIGN_128BYTE = 7,
    /// 256 byte alignment
    ALIGN_256BYTE = 8,
    /// 512 byte alignment
    ALIGN_512BYTE = 9,
    /// 1024 byte alignment
    ALIGN_1024BYTE = 10,
    /// 2KB alignment
    ALIGN_2KB = 11,
    /// 4KB page alignment
    ALIGN_4KB = 12,
});

/// GOFF Behavioral Attributes - complete 10-byte structure from ESD records
#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct BehavioralAttributes(pub [u8; 10]);

impl core::fmt::Debug for BehavioralAttributes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        DebugBitFields::new(f, *self)
            .field(Self::amode, Self::with_amode)
            .field(Self::rmode, Self::with_rmode)
            .field(Self::text_record_style, Self::with_text_record_style)
            .field(Self::binding_algorithm, Self::with_binding_algorithm)
            .field(Self::tasking_behavior, Self::with_tasking_behavior)
            .flag("READ_ONLY", Self::is_read_only, Self::with_read_only)
            .field(Self::executable, Self::with_executable)
            .field(Self::duplicate_severity, Self::with_duplicate_severity)
            .field(Self::binding_strength, Self::with_binding_strength)
            .field(Self::loading_behavior, Self::with_loading_behavior)
            .flag("COMMON", Self::is_common, Self::with_common)
            .flag("INDIRECT", Self::is_indirect, Self::with_indirect)
            .field(Self::binding_scope, Self::with_binding_scope)
            .flag("XPLINK", Self::is_xplink, Self::with_xplink)
            .field(Self::alignment, Self::with_alignment)
            .finish(|x| x.0)
    }
}

impl BehavioralAttributes {
    /// Get the addressing mode (byte 0)
    pub fn amode(self) -> Amode {
        Amode(self.0[0])
    }

    /// Set the addressing mode (byte 0)
    pub fn with_amode(mut self, val: Amode) -> Self {
        self.0[0] = val.0;
        self
    }

    /// Get the residence mode (byte 1)
    pub fn rmode(self) -> Rmode {
        Rmode(self.0[1])
    }

    /// Set the residence mode (byte 1)
    pub fn with_rmode(mut self, val: Rmode) -> Self {
        self.0[1] = val.0;
        self
    }

    /// Get the text record style (byte 2, bits 0-3)
    pub fn text_record_style(self) -> TextRecordStyle {
        TextRecordStyle(get_bits(self.0[2], 0, 4))
    }

    /// Set the text record style (byte 2, bits 0-3)
    pub fn with_text_record_style(mut self, val: TextRecordStyle) -> Self {
        set_bits(&mut self.0[2], 0, 4, val.0);
        self
    }

    /// Get the binding algorithm (byte 2, bits 4-7)
    pub fn binding_algorithm(self) -> BindingAlgorithm {
        BindingAlgorithm(get_bits(self.0[2], 4, 4))
    }

    /// Set the binding algorithm (byte 2, bits 4-7)
    pub fn with_binding_algorithm(mut self, val: BindingAlgorithm) -> Self {
        set_bits(&mut self.0[2], 4, 4, val.0);
        self
    }

    /// Get the tasking behavior (byte 3, bits 0-2)
    pub fn tasking_behavior(self) -> TaskingBehavior {
        TaskingBehavior(get_bits(self.0[3], 0, 3))
    }

    /// Set the tasking behavior (byte 3, bits 0-2)
    pub fn with_tasking_behavior(mut self, val: TaskingBehavior) -> Self {
        set_bits(&mut self.0[3], 0, 3, val.0);
        self
    }

    /// Check if read-only (byte 3, bit 4)
    pub fn is_read_only(self) -> bool {
        get_bits(self.0[3], 4, 1) != 0
    }

    /// Set the read-only flag (byte 3, bit 4)
    pub fn with_read_only(mut self, val: bool) -> Self {
        set_bits(&mut self.0[3], 4, 1, val as u8);
        self
    }

    /// Get executable flags (byte 3, bits 5-7)
    pub fn executable(self) -> Executable {
        Executable(get_bits(self.0[3], 5, 3))
    }

    /// Set executable flags (byte 3, bits 5-7)
    pub fn with_executable(mut self, val: Executable) -> Self {
        set_bits(&mut self.0[3], 5, 3, val.0);
        self
    }

    /// Get duplicate symbol severity (byte 4, bits 2-3)
    pub fn duplicate_severity(self) -> DuplicateSymbolSeverity {
        DuplicateSymbolSeverity(get_bits(self.0[4], 2, 2))
    }

    /// Set duplicate symbol severity (byte 4, bits 2-3)
    pub fn with_duplicate_severity(mut self, val: DuplicateSymbolSeverity) -> Self {
        set_bits(&mut self.0[4], 2, 2, val.0);
        self
    }

    /// Get binding strength (byte 4, bits 4-7)
    pub fn binding_strength(self) -> BindingStrength {
        BindingStrength(get_bits(self.0[4], 4, 4))
    }

    /// Set binding strength (byte 4, bits 4-7)
    pub fn with_binding_strength(mut self, val: BindingStrength) -> Self {
        set_bits(&mut self.0[4], 4, 4, val.0);
        self
    }

    /// Get loading behavior (byte 5, bits 0-1)
    pub fn loading_behavior(self) -> LoadingBehavior {
        LoadingBehavior(get_bits(self.0[5], 0, 2))
    }

    /// Set loading behavior (byte 5, bits 0-1)
    pub fn with_loading_behavior(mut self, val: LoadingBehavior) -> Self {
        set_bits(&mut self.0[5], 0, 2, val.0);
        self
    }

    /// Check if COMMON flag is set (byte 5, bit 2)
    pub fn is_common(self) -> bool {
        get_bits(self.0[5], 2, 1) != 0
    }

    /// Set the COMMON flag (byte 5, bit 2)
    pub fn with_common(mut self, val: bool) -> Self {
        set_bits(&mut self.0[5], 2, 1, val as u8);
        self
    }

    /// Check if indirect reference (byte 5, bit 3)
    pub fn is_indirect(self) -> bool {
        get_bits(self.0[5], 3, 1) != 0
    }

    /// Set the indirect reference flag (byte 5, bit 3)
    pub fn with_indirect(mut self, val: bool) -> Self {
        set_bits(&mut self.0[5], 3, 1, val as u8);
        self
    }

    /// Get binding scope (byte 5, bits 4-7)
    pub fn binding_scope(self) -> BindingScope {
        BindingScope(get_bits(self.0[5], 4, 4))
    }

    /// Set binding scope (byte 5, bits 4-7)
    pub fn with_binding_scope(mut self, val: BindingScope) -> Self {
        set_bits(&mut self.0[5], 4, 4, val.0);
        self
    }

    /// Check if XPLINK linkage (byte 6, bit 2)
    pub fn is_xplink(self) -> bool {
        get_bits(self.0[6], 2, 1) != 0
    }

    /// Set the XPLINK linkage flag (byte 6, bit 2)
    pub fn with_xplink(mut self, val: bool) -> Self {
        set_bits(&mut self.0[6], 2, 1, val as u8);
        self
    }

    /// Get alignment (byte 6, bits 3-7)
    pub fn alignment(self) -> Alignment {
        Alignment(get_bits(self.0[6], 3, 5))
    }

    /// Set alignment (byte 6, bits 3-7)
    pub fn with_alignment(mut self, val: Alignment) -> Self {
        set_bits(&mut self.0[6], 3, 5, val.0);
        self
    }
}

unsafe_impl_pod!(
    HeaderRecord64,
    SymbolRecord64,
    TextRecord64,
    RelocationRecord64,
    ContinuationRecord64,
    LenRecord64,
    LengthDataItem,
    EndRecord64,
    RecordPrefix,
    BehavioralAttributes,
);
