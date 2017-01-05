//! # `object`
//!
//! The `object` crate provides a unified interface to working with object files
//! across platforms.
//!
//! See the [`Object` trait](./trait.Object.html) for details.

#![deny(missing_docs)]

mod object_trait;
pub use object_trait::Object;

// The xmas-elf crate will work on all platforms, even if that platform doesn't
// use elf files.
mod elf;
pub use elf::*;

// The mach_o crate uses the OSX mach-o system library, so will only build on
// OSX.
#[cfg(target_os="macos")]
mod macho;
#[cfg(target_os="macos")]
pub use macho::*;

/// A type alias for the current target platform's object file format type.
#[cfg(target_os="linux")]
pub type File<'a> = Elf<'a>;

/// A type alias for the current target platform's object file format type.
#[cfg(target_os="macos")]
pub type File<'a> = MachO<'a>;
