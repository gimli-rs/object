//! A library for rewriting object and executable files.
//!
//! Use the [`Rewriter`] struct to read a file, modify it, and write it back.
//! Modifications can be performed using methods on the [`Rewriter`] struct, or
//! by passing an [`Options`] struct to the [`Rewriter::modify`] method.
//!
//! Currently, only ELF files are supported, and not many modifications are
//! possible yet.
//!
//! # Example
//! ```no_run
//! use object_rewrite::{Options, Rewriter};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!   let mut options = Options::default();
//!   options.delete_symbols.insert(b"main".to_vec());
//!
//!   let input = std::fs::read("path/to/input")?;
//!   let mut rewriter = Rewriter::read(&input)?;
//!   rewriter.modify(options)?;
//!   let mut output = std::fs::File::create("path/to/output")?;
//!   rewriter.write(&mut output)?;
//!   Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

mod error;
pub use error::{Error, ErrorKind, Result};

mod rewriter;
pub use rewriter::{Options, Rewriter};

mod elf;
pub use elf::ElfOptions;
