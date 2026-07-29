//! GOFF definitions
//!
//! These definitions are independent of read/write support, although we do implement
//! some traits useful for those.
//!
//! This module is based of the official documentation for z/OS <https://www.ibm.com/docs/en/zos/3.2.0?topic=goff-record-formats>

#![allow(missing_docs)]

use crate::endian::{BigEndian as BE, U16, U32};
use crate::pod::Pod;

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
    pub symboltype: SymbolType,
    /// ESD Identifier (ESDID).
    pub esdid: U32<BE>,
    /// Parent of Owning ESDID
    pub parentesdid: U32<BE>,
    /// Reserved. Must be 4 bytes of 0.
    pub reserved1: U32<BE>,
    /// Offset.
    pub offset: U32<BE>,
    /// Reserved. Must be 4 bytes of 0.
    pub reserved2: U32<BE>,
    /// Length (size of allocated memory of program element or section)
    pub length: U32<BE>,
    /// Extended Attribute ESDID
    pub eaesdid: U32<BE>,
    /// Extended Attribute Data Offset
    pub eadataoffset: U32<BE>,
    /// Reserved. Must be 4 bytes of 0.
    pub reserved3: U32<BE>,
    /// Name Space ID
    pub namespaceid: EsdNameSpace,
    /// Symbol Flags.
    pub symflags: u8,
    /// Fill Byte Value (the specific 1-byte value used to pad memory)
    pub fillbytevalue: u8,
    /// Reserved. Must be 1 bytes of 0.
    pub reserved4: u8,
    /// Associated data ID
    pub adaesdid: U32<BE>,
    /// Priority
    pub priority: U32<BE>,
    /// Reserved. Must be 8 bytes of 0.
    pub reserved5: [u8; 8],
    /// Behavioral Attributes
    pub behavioralattributes: [u8; 10],
    /// Name Length
    pub namelength: U16<BE>,
    /// Name
    pub name: [u8; SIZEOF_ESD_DATA],
}

impl SymbolRecord64 {
    /// Convert the behavioral attributes byte array to a structured SectionFlags
    pub fn behavioral_flags(&self) -> SectionFlags {
        SectionFlags {
            amode: AmodeFlags(self.behavioralattributes[0]),
            rmode: RmodeFlags(self.behavioralattributes[1]),
            text_and_binding: self.behavioralattributes[2],
            tasking_and_exec: self.behavioralattributes[3],
            dup_and_strength: self.behavioralattributes[4],
            loading_and_scope: self.behavioralattributes[5],
            linkage_and_align: self.behavioralattributes[6],
            reserved: [
                self.behavioralattributes[7],
                self.behavioralattributes[8],
                self.behavioralattributes[9],
            ],
        }
    }
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
    pub recordstyle: TxtRecordStyle,
    /// Element ESDID
    pub elementesdid: U32<BE>,
    /// Reserved. Must be 4 bytes of 0.
    pub reserved1: U32<BE>,
    /// Offset.
    pub offset: U32<BE>,
    /// Text Field True Length
    pub truelength: U32<BE>,
    /// Text Encoding
    pub textencoding: U16<BE>,
    /// Data Length
    pub datalength: U16<BE>,
    /// Data
    pub data: [u8; SIZEOF_TXT_DATA],
}

/// Each continuation record will have a payload of 77 bytes
pub const SIZEOF_RELOCATION_DATA: usize = 74;

/// A single relocation data item within an RLD record.
/// Size is variable (8-28 bytes) depending on which fields are present as determined by the Flags field.
/// Multiple relocation data items can be packed into a single RelocationRecord64.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RelocationItem64 {
    /// Flags describing this RLD item. The flags determine which fields are present or absent.
    pub flags: [u8; 6],
    /// Reserved field.
    pub reserved1: [u8; 2],
    /// ESDID of the ESD entry (ED or ER) which will be used as the basis for relocation.
    /// For internal references: ED ESDID defining the referenced element.
    /// For external references: ER or PR ESDID describing the referenced symbol.
    pub r_pointer: U32<BE>,
    /// ESDID of the element within which this address constant resides.
    pub p_pointer: U32<BE>,
    /// Offset within the element described by the P pointer where the adcon is located.
    /// This is the fixup target, relocation target, or target field to be updated.
    pub offset: U32<BE>,
    /// Reserved field.
    pub reserved2: U32<BE>,
    /// Reserved field.
    pub reserved3: U32<BE>,
}

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
    pub recordcnt: U32<BE>,
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
    struct FileFlags(u8);
);

newtype_flag_names!(NAMES_F_FLAGS: FileFlags(u8) = {
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
    struct RecordType(u8);
);

newtype_flag_names!(NAMES_RECORD_TYPE: RecordType(u8) = {
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
    struct SymbolType(u8);
);

newtype_flag_names!(NAMES_SYMBOL_TYPE: SymbolType(u8) = {
    /// Section Definition (SD) - defines a control section.
    ESD_SYMTYPE_SD = 0,
    /// Element Definition (ED) - defines an element (part/class).
    ESD_SYMTYPE_ED = 1,
    /// Label Definition (LD) - defines a label within a section.
    ESD_SYMTYPE_LD = 2,
    /// Part Reference (PR) - references a part of an element.
    ESD_SYMTYPE_PR = 3,
    /// External Reference (ER) - references an external symbol.
    ESD_SYMTYPE_ER = 4,
});

newtype!(
    /// ESD Namespace
    struct EsdNameSpace(u8);
);

newtype_flag_names!(NAMES_ESD_NAMSPACE: EsdNameSpace(u8) = {
    ESD_NS_PROGRAM_MANAGEMENT_BINDER = 0,
    ESD_NS_NORMAL_NAME = 1,
    ESD_NS_PSEUDO_REGISTER = 2,
    ESD_NS_PARTS = 3,
});

newtype!(
    /// TXT Record Style
    struct TxtRecordStyle(u8);
);

newtype_flag_names!(NAMES_TXT_RECORD: TxtRecordStyle(u8) = {
    TXT_RS_BYTE = 0,
    TXT_RS_STRUCTURED = 1,
    TXT_RS_UNSTRUCTURED = 2,
});

/// Symbol table entry
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Symbol64 {
    /// ESD Identifier (ESDID).
    pub esdid: u32,
    /// Symbol Type
    pub symboltype: SymbolType,
    /// Parent of Owning ESDID
    pub parentesdid: u32,
    /// Offset.
    pub offset: u32,
    /// Length
    pub length: u32,
    /// Name Space ID
    pub namespaceid: EsdNameSpace,
}

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
    struct AmodeFlags(u8);
);

newtype_flag_names!(NAMES_GOFF_AMODE: AmodeFlags(u8) = {
    /// AMODE not specified (default=24)
    GOFF_AMODE_UNSPEC = 0x00,
    /// AMODE(24)
    GOFF_AMODE_24 = 0x01,
    /// AMODE(31)
    GOFF_AMODE_31 = 0x02,
    /// AMODE(ANY) - either 24-bit or 31-bit
    GOFF_AMODE_ANY = 0x03,
    /// AMODE(64)
    GOFF_AMODE_64 = 0x04,
    /// AMODE(MIN) - binder can set to minimum AMODE
    GOFF_AMODE_MIN = 0x10,
});

newtype!(
    /// GOFF Residence Mode (RMODE) - Byte 1 of behavioral attributes
    struct RmodeFlags(u8);
);

newtype_flag_names!(NAMES_GOFF_RMODE: RmodeFlags(u8) = {
    /// RMODE not specified (default=24)
    GOFF_RMODE_UNSPEC = 0x00,
    /// RMODE(24)
    GOFF_RMODE_24 = 0x01,
    /// RMODE(31) - equivalent to OBJ RMODE(ANY)
    GOFF_RMODE_31 = 0x03,
    /// RMODE(64)
    GOFF_RMODE_64 = 0x04,
});

newtype!(
    /// GOFF Binding Algorithm - Byte 2 bits 4-7 of behavioral attributes
    struct BindingAlgorithm(u8);
);

newtype_flag_names!(NAMES_GOFF_BINDING_ALGORITHM: BindingAlgorithm(u8) = {
    /// Concatenate - sections placed end to end
    GOFF_BIND_CONCATENATE = 0x00,
    /// Merge - identically named parts merged
    GOFF_BIND_MERGE = 0x10,
});

newtype!(
    /// GOFF Tasking Behavior - Byte 3 bits 0-2 of behavioral attributes
    struct TaskingBehavior(u8);
);

newtype_flag_names!(NAMES_GOFF_TASKING: TaskingBehavior(u8) = {
    /// Unspecified
    GOFF_TASK_UNSPEC = 0x00,
    /// NON-REUS - Not serially reusable
    GOFF_TASK_NON_REUS = 0x01,
    /// REUS - Serially reusable
    GOFF_TASK_REUS = 0x02,
    /// RENT - Reentrant
    GOFF_TASK_RENT = 0x03,
});

newtype!(
    /// GOFF Executable Flags - Byte 3 bits 5-7 of behavioral attributes
    struct ExecutableFlags(u8);
);

newtype_flag_names!(NAMES_GOFF_EXECUTABLE: ExecutableFlags(u8) = {
    /// Not specified
    GOFF_EXEC_UNSPEC = 0x00,
    /// Not executable (data)
    GOFF_EXEC_DATA = 0x20,
    /// Executable (code)
    GOFF_EXEC_CODE = 0x40,
});

newtype!(
    /// GOFF Binding Strength - Byte 4 bits 4-7 of behavioral attributes
    struct BindingStrength(u8);
);

newtype_flag_names!(NAMES_GOFF_BINDING_STRENGTH: BindingStrength(u8) = {
    /// Strong reference/definition
    GOFF_BIND_STRONG = 0x00,
    /// Weak reference/definition
    GOFF_BIND_WEAK = 0x10,
});

newtype!(
    /// GOFF Loading Behavior - Byte 5 bits 0-1 of behavioral attributes
    struct LoadingBehavior(u8);
);

newtype_flag_names!(NAMES_GOFF_LOADING: LoadingBehavior(u8) = {
    /// Load with module
    GOFF_LOAD = 0x00,
    /// Deferred load
    GOFF_LOAD_DEFERRED = 0x01,
    /// Do not load with module
    GOFF_NOLOAD = 0x02,
});

newtype!(
    /// GOFF Binding Scope - Byte 5 bits 4-7 of behavioral attributes
    struct BindingScope(u8);
);

newtype_flag_names!(NAMES_GOFF_BINDING_SCOPE: BindingScope(u8) = {
    /// Unspecified
    GOFF_SCOPE_UNSPEC = 0x00,
    /// Section (local)
    GOFF_SCOPE_SECTION = 0x10,
    /// Module (global)
    GOFF_SCOPE_MODULE = 0x20,
    /// Library
    GOFF_SCOPE_LIBRARY = 0x30,
    /// Import-Export
    GOFF_SCOPE_IMPORT_EXPORT = 0x40,
});

newtype!(
    /// GOFF Alignment - Byte 6 bits 3-7 of behavioral attributes
    struct AlignmentFlags(u8);
);

newtype_flag_names!(NAMES_GOFF_ALIGNMENT: AlignmentFlags(u8) = {
    /// Byte alignment
    GOFF_ALIGN_BYTE = 0x00,
    /// Halfword alignment
    GOFF_ALIGN_HALFWORD = 0x08,
    /// Fullword alignment
    GOFF_ALIGN_FULLWORD = 0x10,
    /// Doubleword alignment
    GOFF_ALIGN_DOUBLEWORD = 0x18,
    /// Quadword alignment
    GOFF_ALIGN_QUADWORD = 0x20,
    /// 32 byte alignment
    GOFF_ALIGN_32BYTE = 0x28,
    /// 64 byte alignment
    GOFF_ALIGN_64BYTE = 0x30,
    /// 128 byte alignment
    GOFF_ALIGN_128BYTE = 0x38,
    /// 256 byte alignment
    GOFF_ALIGN_256BYTE = 0x40,
    /// 512 byte alignment
    GOFF_ALIGN_512BYTE = 0x48,
    /// 1024 byte alignment
    GOFF_ALIGN_1024BYTE = 0x50,
    /// 2KB alignment
    GOFF_ALIGN_2KB = 0x58,
    /// 4KB page alignment
    GOFF_ALIGN_4KB = 0x60,
});

/// Additional behavioral attribute flags (single-bit flags)
/// Read-only flag - Byte 3 bit 4
pub const GOFF_READ_ONLY: u8 = 0x10;
/// COMMON flag - Byte 5 bit 2
pub const GOFF_COMMON: u8 = 0x04;
/// Indirect reference flag - Byte 5 bit 3
pub const GOFF_INDIRECT: u8 = 0x08;
/// XPLINK linkage flag - Byte 6 bit 2
pub const GOFF_LINKAGE_XPLINK: u8 = 0x04;

/// GOFF Behavioral Attributes - complete 10-byte structure from ESD records
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SectionFlags {
    /// Byte 0: Addressing mode (AMODE)
    pub amode: AmodeFlags,
    /// Byte 1: Residence mode (RMODE)
    pub rmode: RmodeFlags,
    /// Byte 2: Text record style (bits 0-3) and binding algorithm (bits 4-7)
    pub text_and_binding: u8,
    /// Byte 3: Tasking behavior (bits 0-2), read-only (bit 4), executable (bits 5-7)
    pub tasking_and_exec: u8,
    /// Byte 4: Duplicate severity (bits 2-3) and binding strength (bits 4-7)
    pub dup_and_strength: u8,
    /// Byte 5: Loading behavior (bits 0-1), COMMON (bit 2), direct/indirect (bit 3), binding scope (bits 4-7)
    pub loading_and_scope: u8,
    /// Byte 6: Linkage type (bit 2) and alignment (bits 3-7)
    pub linkage_and_align: u8,
    /// Bytes 7-9: Reserved
    pub reserved: [u8; 3],
}

impl SectionFlags {
    /// Get the addressing mode
    pub fn amode(self) -> AmodeFlags {
        self.amode
    }

    /// Get the residence mode
    pub fn rmode(self) -> RmodeFlags {
        self.rmode
    }

    /// Get the binding algorithm
    pub fn binding_algorithm(self) -> BindingAlgorithm {
        BindingAlgorithm(self.text_and_binding & 0xF0)
    }

    /// Get the tasking behavior
    pub fn tasking_behavior(self) -> TaskingBehavior {
        TaskingBehavior(self.tasking_and_exec & 0x07)
    }

    /// Check if read-only
    pub fn is_read_only(self) -> bool {
        (self.tasking_and_exec & GOFF_READ_ONLY) != 0
    }

    /// Get executable flags
    pub fn executable(self) -> ExecutableFlags {
        ExecutableFlags(self.tasking_and_exec & 0xE0)
    }

    /// Get binding strength
    pub fn binding_strength(self) -> BindingStrength {
        BindingStrength(self.dup_and_strength & 0xF0)
    }

    /// Get loading behavior
    pub fn loading_behavior(self) -> LoadingBehavior {
        LoadingBehavior(self.loading_and_scope & 0x03)
    }

    /// Check if COMMON flag is set
    pub fn is_common(self) -> bool {
        (self.loading_and_scope & GOFF_COMMON) != 0
    }

    /// Check if indirect reference
    pub fn is_indirect(self) -> bool {
        (self.loading_and_scope & GOFF_INDIRECT) != 0
    }

    /// Get binding scope
    pub fn binding_scope(self) -> BindingScope {
        BindingScope(self.loading_and_scope & 0xF0)
    }

    /// Check if XPLINK linkage
    pub fn is_xplink(self) -> bool {
        (self.linkage_and_align & GOFF_LINKAGE_XPLINK) != 0
    }

    /// Get alignment
    pub fn alignment(self) -> AlignmentFlags {
        AlignmentFlags(self.linkage_and_align & 0xF8)
    }
}

unsafe_impl_pod!(
    HeaderRecord64,
    SymbolRecord64,
    TextRecord64,
    RelocationRecord64,
    RelocationItem64,
    ContinuationRecord64,
    LenRecord64,
    LengthDataItem,
    EndRecord64,
    Symbol64,
    RecordPrefix,
);
