//! # `object`
//!
//! The `object` crate provides a unified interface to working with object files
//! across platforms.
//!
//! See the [`File` struct](./struct.File.html) for details.

#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![no_std]
#![cfg_attr(not(feature = "std"), feature(alloc))]

#[cfg(feature = "std")]
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

// Re-export since this is used in public signatures.
pub use uuid::Uuid;

pub mod read;
pub use read::*;
