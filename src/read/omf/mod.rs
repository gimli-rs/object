//! Support for reading OMF (Relocatable Object Module Format) files.
//!
//! OMF is the object file format used by most DOS and early Windows
//! compilers, such as Borland C++ and Open Watcom. Both 16-bit and 32-bit
//! variants are supported, including vendor extensions such as COMDAT
//! records and Borland virtual segments.
//!
//! [`OmfFile`] implements the [`Object`](crate::read::Object) trait for
//! OMF files.
//!
//! OMF doesn't have a notion of sections; instead, data is contributed to
//! segments (`SEGDEF`) and COMDATs. This implementation maps both to
//! sections in the unified read API.

mod comdat;
pub use comdat::*;

mod file;
pub use file::*;

mod relocation;
pub use relocation::*;

mod section;
pub use section::*;

mod segment;
pub use segment::*;

mod symbol;
pub use symbol::*;
