//! # `object`
//!
//! The `object` crate provides a unified interface to working with object files
//! across platforms. It supports reading object files and executable files,
//! and writing object files.
//!
//! See the [`File` struct](./read/struct.File.html) for details.

#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![no_std]

#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
#[allow(unused_imports)]
#[macro_use]
extern crate std;

// Re-export since these are used in public signatures.
pub use target_lexicon;
pub use uuid;

mod common;
pub use common::*;

#[macro_use]
pub mod endian;

#[macro_use]
mod pod;
// This isn't really intended for users yet, but other traits required it.
#[doc(hidden)]
pub use pod::Pod;

#[cfg(feature = "read_core")]
pub mod read;
#[cfg(feature = "read_core")]
pub use read::*;

#[cfg(feature = "write_core")]
pub mod write;

#[cfg(feature = "elf")]
pub mod elf;
#[cfg(feature = "macho")]
pub mod macho;
#[cfg(any(feature = "coff", feature = "pe"))]
pub mod pe;
