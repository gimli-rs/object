//! Support for reading z/OS GOFF files.
//!
//! Provides `GoffFile` and related types which implement the `Object` trait.

//FIXME_GOFF: need to update the following based on that's used
mod file;
pub use file::*;

mod section;
pub use section::*;

mod symbol;
pub use symbol::*;

mod relocation;
pub use relocation::*;

mod comdat;
pub use comdat::*;

mod segment;
pub use segment::*;
