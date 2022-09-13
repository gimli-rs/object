//! XCOFF definitions
//!
//! These definitions are independent of read/write support, although we do implement
//! some traits useful for those.
//!
//! This module is the equivalent of /usr/include/xcoff.h, and is based heavily on it.

use crate::endian::{BigEndian as BE, I16, U16, U32, U64};
use crate::pod::Pod;

/// The header at the start of every 32-bit XCOFF file.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FileHeader32 {
    /// Magic number. Must be 0x01DF.
    pub f_magic: U16<BE>,
    /// Number of sections.
    pub f_nscns: U16<BE>,
    /// Time and date of file creation.
    pub f_timdat: U32<BE>,
    /// Byte offset to symbol table start.
    pub f_symptr: U32<BE>,
    /// Number of entries in symbol table.
    pub f_nsyms: U32<BE>,
    /// Number of bytes in optional header
    pub f_opthdr: U16<BE>,
    /// Extra flags.
    pub f_flags: U16<BE>,
}

/// The header at the start of every 64-bit XCOFF file.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FileHeader64 {
    /// Magic number. Must be 0x01F7.
    pub f_magic: U16<BE>,
    /// Number of sections.
    pub f_nscns: U16<BE>,
    /// Time and date of file creation
    pub f_timdat: U32<BE>,
    /// Byte offset to symbol table start.
    pub f_symptr: U64<BE>,
    /// Number of bytes in optional header
    pub f_opthdr: U16<BE>,
    /// Extra flags.
    pub f_flags: U16<BE>,
    /// Number of entries in symbol table.
    pub f_nsyms: U32<BE>,
}

// Values for `f_magic`.
//
/// the 64-bit mach magic number
pub const MAGIC_64: u16 = 0x01F7;
/// the 32-bit mach magic number
pub const MAGIC_32: u16 = 0x01DF;

// Values for `f_flags`.
//
/// Indicates that the relocation information for binding has been removed from
/// the file.
pub const F_RELFLG: u16 = 0x0001;
/// Indicates that the file is executable. No unresolved external references exist.
pub const F_EXEC: u16 = 0x0002;
/// Indicates that line numbers have been stripped from the file by a utility program.
pub const F_LNNO: u16 = 0x0004;
/// Indicates that the file was profiled with the fdpr command.
pub const F_FDPR_PROF: u16 = 0x0010;
/// Indicates that the file was reordered with the fdpr command.
pub const F_FDPR_OPTI: u16 = 0x0020;
/// Indicates that the file uses Very Large Program Support.
pub const F_DSA: u16 = 0x0040;
/// Indicates that one of the members of the auxiliary header specifying the
/// medium page sizes is non-zero.
pub const F_VARPG: u16 = 0x0100;
/// Indicates the file is dynamically loadable and executable. External references
/// are resolved by way of imports, and the file might contain exports and loader
/// relocation.
pub const F_DYNLOAD: u16 = 0x1000;
/// Indicates the file is a shared object (shared library). The file is separately
/// loadable. That is, it is not normally bound with other objects, and its loader
/// exports symbols are used as automatic import symbols for other object files.
pub const F_SHROBJ: u16 = 0x2000;
/// If the object file is a member of an archive, it can be loaded by the system
/// loader, but the member is ignored by the binder. If the object file is not in
/// an archive, this flag has no effect.
pub const F_LOADONLY: u16 = 0x4000;

/// The auxiliary header immediately following file header. If the value of the
/// f_opthdr field in the file header is 0, the auxiliary header does not exist.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct AuxHeader32 {
    /// Flags.
    pub o_mflag: U16<BE>,
    /// Version.
    pub o_vstamp: U16<BE>,
    /// Text size in bytes.
    pub o_tsize: U32<BE>,
    /// Initialized data size in bytes.
    pub o_dsize: U32<BE>,
    /// Uninitialized data size in bytes.
    pub o_bsize: U32<BE>,
    /// Entry point descriptor (virtual address).
    pub o_entry: U32<BE>,
    /// Base address of text (virtual address).
    pub o_text_start: U32<BE>,
    /// Base address of data (virtual address).
    pub o_data_start: U32<BE>,
    /// Address of TOC anchor.
    pub o_toc: U32<BE>,
    /// Section number for entry point.
    pub o_snentry: U16<BE>,
    /// Section number for .text.
    pub o_sntext: U16<BE>,
    /// Section number for .data.
    pub o_sndata: U16<BE>,
    /// Section number for TOC.
    pub o_sntoc: U16<BE>,
    /// Section number for loader data.
    pub o_snloader: U16<BE>,
    /// Section number for .bss.
    pub o_snbss: U16<BE>,
    /// Maximum alignment for .text.
    pub o_algntext: U16<BE>,
    /// Maximum alignment for .data.
    pub o_algndata: U16<BE>,
    /// Module type field.
    pub o_modtype: U16<BE>,
    /// Bit flags - cpu types of objects.
    pub o_cpuflag: u8,
    /// Reserved for CPU type.
    pub o_cputype: u8,
    /// Maximum stack size allowed (bytes).
    pub o_maxstack: U32<BE>,
    /// Maximum data size allowed (bytes).
    pub o_maxdata: U32<BE>,
    /// Reserved for debuggers.
    pub o_debugger: U32<BE>,
    /// Requested text page size.
    pub o_textpsize: u8,
    /// Requested data page size.
    pub o_datapsize: u8,
    /// Requested stack page size.
    pub o_stackpsize: u8,
    /// Flags and thread-local storage alignment.
    pub o_flags: u8,
    /// Section number for .tdata.
    pub o_sntdata: U16<BE>,
    /// Section number for .tbss.
    pub o_sntbss: U16<BE>,
}

/// The auxiliary header immediately following file header. If the value of the
/// f_opthdr field in the file header is 0, the auxiliary header does not exist.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct AuxHeader64 {
    /// Flags.
    pub o_mflag: U16<BE>,
    /// Version.
    pub o_vstamp: U16<BE>,
    /// Reserved for debuggers.
    pub o_debugger: U32<BE>,
    /// Base address of text (virtual address).
    pub o_text_start: U64<BE>,
    /// Base address of data (virtual address).
    pub o_data_start: U64<BE>,
    /// Address of TOC anchor.
    pub o_toc: U64<BE>,
    /// Section number for entry point.
    pub o_snentry: U16<BE>,
    /// Section number for .text.
    pub o_sntext: U16<BE>,
    /// Section number for .data.
    pub o_sndata: U16<BE>,
    /// Section number for TOC.
    pub o_sntoc: U16<BE>,
    /// Section number for loader data.
    pub o_snloader: U16<BE>,
    /// Section number for .bss.
    pub o_snbss: U16<BE>,
    /// Maximum alignment for .text.
    pub o_algntext: U16<BE>,
    /// Maximum alignment for .data.
    pub o_algndata: U16<BE>,
    /// Module type field.
    pub o_modtype: U16<BE>,
    /// Bit flags - cpu types of objects.
    pub o_cpuflag: u8,
    /// Reserved for CPU type.
    pub o_cputype: u8,
    /// Requested text page size.
    pub o_textpsize: u8,
    /// Requested data page size.
    pub o_datapsize: u8,
    /// Requested stack page size.
    pub o_stackpsize: u8,
    /// Flags and thread-local storage alignment.
    pub o_flags: u8,
    /// Text size in bytes.
    pub o_tsize: U64<BE>,
    /// Initialized data size in bytes.
    pub o_dsize: U64<BE>,
    /// Uninitialized data size in bytes.
    pub o_bsize: U64<BE>,
    /// Entry point descriptor (virtual address).
    pub o_entry: U64<BE>,
    /// Maximum stack size allowed (bytes).
    pub o_maxstack: U64<BE>,
    /// Maximum data size allowed (bytes).
    pub o_maxdata: U64<BE>,
    /// Section number for .tdata.
    pub o_sntdata: U16<BE>,
    /// Section number for .tbss.
    pub o_sntbss: U16<BE>,
    /// XCOFF64 flags.
    pub o_x64flags: U16<BE>,
    /// Reserved.
    pub o_resv3a: U16<BE>,
    /// Reserved.
    pub o_resv3: [U32<BE>; 2],
}

/// Section header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SectionHeader32 {
    /// Section name.
    pub s_name: [u8; 8],
    /// Physical address.
    pub s_paddr: U32<BE>,
    /// Virtual address (same as physical address).
    pub s_vaddr: U32<BE>,
    /// Section size.
    pub s_size: U32<BE>,
    /// Offset in file to raw data for section.
    pub s_scnptr: U32<BE>,
    /// Offset in file to relocation entries for section.
    pub s_relptr: U32<BE>,
    /// Offset in file to line number entries for section.
    pub s_lnnoptr: U32<BE>,
    /// Number of relocation entries.
    pub s_nreloc: U16<BE>,
    /// Number of line number entries.
    pub s_nlnno: U16<BE>,
    /// Flags to define the section type.
    pub s_flags: U16<BE>,
}

/// Section header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SectionHeader64 {
    /// Section name.
    pub s_name: [u8; 8],
    /// Physical address.
    pub s_paddr: U64<BE>,
    /// Virtual address (same as physical address).
    pub s_vaddr: U64<BE>,
    /// Section size.
    pub s_size: U64<BE>,
    /// Offset in file to raw data for section.
    pub s_scnptr: U64<BE>,
    /// Offset in file to relocation entries for section.
    pub s_relptr: U64<BE>,
    /// Offset in file to line number entries for section.
    pub s_lnnoptr: U64<BE>,
    /// Number of relocation entries.
    pub s_nreloc: U32<BE>,
    /// Number of line number entries.
    pub s_nlnno: U32<BE>,
    /// Flags to define the section type.
    pub s_flags: U32<BE>,
    /// Reserved.
    pub s_reserve: U32<BE>,
}

// Values for `s_flags`.
//
/// "regular" section
pub const STYP_REG: u16 = 0x00;
/// Specifies a pad section. A section of this type is used to provide alignment
/// padding between sections within an XCOFF executable object file. This section
/// header type is obsolete since padding is allowed in an XCOFF file without a
/// corresponding pad section header.
pub const STYP_PAD: u16 = 0x08;
/// Specifies a DWARF debugging section, which provide source file and symbol
/// information for the symbolic debugger.
pub const STYP_DWARF: u16 = 0x10;
/// Specifies an executable text (code) section. A section of this type contains
/// the executable instructions of a program.
pub const STYP_TEXT: u16 = 0x20;
/// Specifies an initialized data section. A section of this type contains the
/// initialized data and the TOC of a program.
pub const STYP_DATA: u16 = 0x40;
/// Specifies an uninitialized data section. A section header of this type
/// defines the uninitialized data of a program.
pub const STYP_BSS: u16 = 0x80;
/// Specifies an exception section. A section of this type provides information
/// to identify the reason that a trap or exception occurred within an executable
/// object program.
pub const STYP_EXCEPT: u16 = 0x0100;
/// Specifies a comment section. A section of this type provides comments or data
/// to special processing utility programs.
pub const STYP_INFO: u16 = 0x0200;
/// Specifies an initialized thread-local data section.
pub const STYP_TDATA: u16 = 0x0400;
/// Specifies an uninitialized thread-local data section.
pub const STYP_TBSS: u16 = 0x0800;
/// Specifies a loader section. A section of this type contains object file
/// information for the system loader to load an XCOFF executable. The information
/// includes imported symbols, exported symbols, relocation data, type-check
/// information, and shared object names.
pub const STYP_LOADER: u16 = 0x1000;
/// Specifies a debug section. A section of this type contains stabstring
/// information used by the symbolic debugger.
pub const STYP_DEBUG: u16 = 0x2000;
/// Specifies a type-check section. A section of this type contains
/// parameter/argument type-check strings used by the binder.
pub const STYP_TYPCHK: u16 = 0x4000;
/// Specifies a relocation or line-number field overflow section. A section
/// header of this type contains the count of relocation entries and line
/// number entries for some other section. This section header is required
/// when either of the counts exceeds 65,534.
pub const STYP_OVRFLO: u16 = 0x8000;

/// Symbol table entry.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Symbol32 {
    /// Symbol name.
    ///
    /// If first 4 bytes are 0, then second 4 bytes are offset into string table.
    pub n_name: [u8; 8],
    /// Symbol value; storage class-dependent.
    pub n_value: U32<BE>,
    /// Section number of symbol.
    pub n_scnum: U16<BE>,
    /// Basic and derived type specification.
    pub n_type: U16<BE>,
    /// Storage class of symbol.
    pub n_sclass: u8,
    /// Number of auxiliary entries.
    pub n_numaux: u8,
}

/// Symbol table entry.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Symbol64 {
    /// Symbol value; storage class-dependent.
    pub n_value: U64<BE>,
    /// Offset of the name in string table or .debug section.
    pub n_offset: U32<BE>,
    /// Section number of symbol.
    pub n_scnum: I16<BE>,
    /// Basic and derived type specification.
    pub n_type: U16<BE>,
    /// Storage class of symbol.
    pub n_sclass: u8,
    /// Number of auxiliary entries.
    pub n_numaux: u8,
}

// Values for `n_scnum`.
//
/// A special symbolic debugging symbol.
pub const N_DEBUG: i16 = -2;
/// An absolute symbol. The symbol has a value but is not relocatable.
pub const N_ABS: i16 = -1;
/// An undefined external symbol.
pub const N_UNDEF: i16 = 0;

// Vlaues for `n_type`.
//
/// External reference.
pub const XTY_ER: u8 = 0;
/// Csect definition for initialized storage.
pub const XTY_SD: u8 = 1;
/// Label definition. Defines an entry point to an initialized csect.
pub const XTY_LD: u8 = 2;
/// Common csect definition. For uninitialized storage.
pub const XTY_CM: u8 = 3;

// Values for `n_sclass`.
//
// Storage classes used for symbolic debugging symbols.
//
/// Source file name and compiler information.
pub const C_FILE: u8 = 103;
/// Beginning of include file.
pub const C_BINCL: u8 = 108;
/// Ending of include file.
pub const C_EINCL: u8 = 109;
/// Global variable.
pub const C_GSYM: u8 = 128;
/// Statically allocated symbol.
pub const C_STSYM: u8 = 133;
/// Beginning of common block.
pub const C_BCOMM: u8 = 135;
/// End of common block.
pub const C_ECOMM: u8 = 137;
/// Alternate entry.
pub const C_ENTRY: u8 = 141;
/// Beginning of static block.
pub const C_BSTAT: u8 = 143;
/// End of static block.
pub const C_ESTAT: u8 = 144;
/// Global thread-local variable.
pub const C_GTLS: u8 = 145;
/// Static thread-local variable.
pub const C_STTLS: u8 = 146;
/// DWARF section symbol.
pub const C_DWARF: u8 = 112;
//
// Storage classes used for absolute symbols.
//
/// Automatic variable allocated on stack.
pub const C_LSYM: u8 = 129;
/// Argument to subroutine allocated on stack.
pub const C_PSYM: u8 = 130;
/// Register variable.
pub const C_RSYM: u8 = 131;
/// Argument to function or procedure stored in register.
pub const C_RPSYM: u8 = 132;
/// Local member of common block.
pub const C_ECOML: u8 = 136;
/// Function or procedure.
pub const C_FUN: u8 = 142;
//
// Storage classes used for undefined external symbols or symbols of general sections.
//
/// External symbol.
pub const C_EXT: u8 = 2;
/// Weak external symbol.
pub const C_WEAKEXT: u8 = 111;
//
// Storage classes used for symbols of general sections.
//
/// Symbol table entry marked for deletion.
pub const C_NULL: u8 = 0;
/// Static.
pub const C_STAT: u8 = 3;
/// Beginning or end of inner block.
pub const C_BLOCK: u8 = 100;
/// Beginning or end of function.
pub const C_FCN: u8 = 101;
/// Un-named external symbol.
pub const C_HIDEXTL: u8 = 107;
/// Comment string in .info section.
pub const C_INFO: u8 = 110;
/// Declaration of object (type).
pub const C_DECL: u8 = 140;
//
// Storage classes - Obsolete/Undocumented.
//
/// Automatic variable.
pub const C_AUTO: u8 = 1;
/// Register variable.
pub const C_REG: u8 = 4;
/// External definition.
pub const C_EXTDEF: u8 = 5;
/// Label.
pub const C_LABEL: u8 = 6;
/// Undefined label.
pub const C_ULABEL: u8 = 7;
/// Member of structure.
pub const C_MOS: u8 = 8;
/// Function argument.
pub const C_ARG: u8 = 9;
/// Structure tag.
pub const C_STRTAG: u8 = 10;
/// Member of union.
pub const C_MOU: u8 = 11;
/// Union tag.
pub const C_UNTAG: u8 = 12;
/// Type definition.
pub const C_TPDEF: u8 = 13;
/// Undefined static.
pub const C_USTATIC: u8 = 14;
/// Enumeration tag.
pub const C_ENTAG: u8 = 15;
/// Member of enumeration.
pub const C_MOE: u8 = 16;
/// Register parameter.
pub const C_REGPARM: u8 = 17;
/// Bit field.
pub const C_FIELD: u8 = 18;
/// End of structure.
pub const C_EOS: u8 = 102;
/// Duplicate tag.
pub const C_ALIAS: u8 = 105;
/// Special storage class for external.
pub const C_HIDDEN: u8 = 106;
/// Physical end of function.
pub const C_EFCN: u8 = 255;
/// Reserved.
pub const C_TCSYM: u8 = 134;

/// Relocation table entry
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Rel32 {
    /// Virtual address (position) in section to be relocated.
    pub r_vaddr: U32<BE>,
    /// Symbol table index of item that is referenced.
    pub r_symndx: U32<BE>,
    /// Relocation size and information.
    pub r_rsize: u8,
    /// Relocation type.
    pub r_rtype: u8,
}

/// Relocation table entry
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Rel64 {
    /// Virtual address (position) in section to be relocated.
    pub r_vaddr: U64<BE>,
    /// Symbol table index of item that is referenced.
    pub r_symndx: U32<BE>,
    /// Relocation size and information.
    pub r_rsize: u8,
    /// Relocation type.
    pub r_rtype: u8,
}

// Values for `r_rtype`.
//
/// Positive relocation.
pub const R_POS: u8 = 0x00;
/// Positive indirect load relocation.
pub const R_RL: u8 = 0x0c;
/// Positive load address relocation. Modifiable instruction.
pub const R_RLA: u8 = 0x0d;
/// Negative relocation.
pub const R_NEG: u8 = 0x01;
/// Relative to self relocation.
pub const R_REL: u8 = 0x02;
/// Relative to the TOC relocation.
pub const R_TOC: u8 = 0x03;
/// TOC relative indirect load relocation.
pub const R_TRL: u8 = 0x12;
/// Relative to the TOC or to the thread-local storage base relocation.
pub const R_TRLA: u8 = 0x13;
/// Global linkage-external TOC address relocation.
pub const R_GL: u8 = 0x05;
/// Local object TOC address relocation.
pub const R_TCL: u8 = 0x06;
/// A non-relocating relocation.
pub const R_REF: u8 = 0x0f;
/// Branch absolute relocation. References a non-modifiable instruction.
pub const R_BA: u8 = 0x08;
/// Branch relative to self relocation. References a non-modifiable instruction.
pub const R_BR: u8 = 0x0a;
/// Branch absolute relocation. References a modifiable instruction.
pub const R_RBA: u8 = 0x18;
/// Branch relative to self relocation. References a modifiable instruction.
pub const R_RBR: u8 = 0x1a;
/// General-dynamic reference to TLS symbol.
pub const R_TLS: u8 = 0x20;
/// Initial-exec reference to TLS symbol.
pub const R_TLS_IE: u8 = 0x21;
/// Local-dynamic reference to TLS symbol.
pub const R_TLS_LD: u8 = 0x22;
/// Local-exec reference to TLS symbol.
pub const R_TLS_LE: u8 = 0x23;
/// Module reference to TLS.
pub const R_TLSM: u8 = 0x24;
/// Module reference to the local TLS storage.
pub const R_TLSML: u8 = 0x25;
/// Relative to TOC upper.
pub const R_TOCU: u8 = 0x30;
/// Relative to TOC lower.
pub const R_TOCL: u8 = 0x31;

unsafe_impl_pod!(
    FileHeader32,
    FileHeader64,
    AuxHeader32,
    AuxHeader64,
    SectionHeader32,
    SectionHeader64,
    Symbol32,
    Symbol64,
    Rel32,
    Rel64,
);
