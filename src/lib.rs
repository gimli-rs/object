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
#![cfg_attr(not(feature = "std"), feature(alloc))]

#[cfg(feature = "std")]
#[allow(unused_imports)]
#[macro_use]
extern crate std;

#[cfg(all(not(feature = "std"), feature = "compression"))]
#[macro_use]
extern crate alloc;
#[cfg(all(not(feature = "std"), not(feature = "compression")))]
extern crate alloc;
#[cfg(not(feature = "std"))]
extern crate core as std;

#[cfg(feature = "std")]
mod alloc {
    pub use std::borrow;
    pub use std::fmt;
    pub use std::vec;
}

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

#[cfg(feature = "read")]
pub mod read;
#[cfg(feature = "read")]
pub use read::*;

#[cfg(feature = "write")]
pub mod write;

pub mod elf;
pub mod macho;
