use std::collections::{HashMap, HashSet};

use object::build;

use super::{Error, Result};

/// Options for modifying a file.
///
/// This is used as an argument to the [`Rewriter::modify`] method.
///
/// The options are listed in the order they are processed.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Options {
    /// Delete symbols from the symbol table.
    ///
    /// See [`Rewriter::delete_symbols`].
    pub delete_symbols: HashSet<Vec<u8>>,
    /// Rename symbols in the symbol table.
    ///
    /// See [`Rewriter::rename_symbols`].
    pub rename_symbols: HashMap<Vec<u8>, Vec<u8>>,
    /// Delete sections from the file.
    ///
    /// See [`Rewriter::delete_sections`].
    pub delete_sections: HashSet<Vec<u8>>,
    /// Rename sections in the file.
    ///
    /// See [`Rewriter::rename_sections`].
    pub rename_sections: HashMap<Vec<u8>, Vec<u8>>,
    /// Options that are specific to ELF files.
    pub elf: super::ElfOptions,
}

/// A rewriter for object and executable files.
///
/// This struct provides a way to read a file, modify it, and write it back.
#[derive(Debug)]
pub struct Rewriter<'data> {
    pub(crate) builder: build::elf::Builder<'data>,
    pub(crate) modified: bool,
}

impl<'data> Rewriter<'data> {
    /// Read a file and create a new rewriter.
    pub fn read(data: &'data [u8]) -> Result<Self> {
        let builder = build::elf::Builder::read(data).map_err(Error::parse)?;
        Ok(Self {
            builder,
            modified: false,
        })
    }

    /// Write the file to an output stream.
    pub fn write<W: std::io::Write>(mut self, w: W) -> Result<()> {
        self.elf_finalize()?;
        let mut buffer = object::write::StreamingBuffer::new(w);
        self.builder.write(&mut buffer).map_err(Error::write)?;
        buffer.result().map_err(Error::io)
    }

    /// Modify the file according to the given options.
    pub fn modify(&mut self, options: Options) -> Result<()> {
        if !options.delete_symbols.is_empty() {
            self.delete_symbols(&options.delete_symbols);
        }
        if !options.rename_symbols.is_empty() {
            self.rename_symbols(&options.rename_symbols);
        }
        if !options.delete_sections.is_empty() {
            self.delete_sections(&options.delete_sections);
        }
        if !options.rename_sections.is_empty() {
            self.rename_sections(&options.rename_sections);
        }
        self.elf_modify(options.elf)?;
        Ok(())
    }

    /// Delete symbols from the symbol table.
    ///
    /// For ELF files, this deletes symbols from both the symbol table and the
    /// dynamic symbol table.
    pub fn delete_symbols(&mut self, names: &HashSet<Vec<u8>>) {
        self.elf_delete_symbols(names);
        self.elf_delete_dynamic_symbols(names);
    }

    /// Rename symbols in the symbol table.
    ///
    /// For ELF files, this renames symbols in both the symbol table and the
    /// dynamic symbol table.
    ///
    /// The `names` map is from old names to new names.
    pub fn rename_symbols(&mut self, names: &HashMap<Vec<u8>, Vec<u8>>) {
        self.elf_rename_symbols(names);
        self.elf_rename_dynamic_symbols(names);
    }

    /// Delete sections from the file.
    pub fn delete_sections(&mut self, names: &HashSet<Vec<u8>>) {
        self.elf_delete_sections(names);
    }

    /// Rename sections in the file.
    ///
    /// The `names` map is from old names to new names.
    pub fn rename_sections(&mut self, names: &HashMap<Vec<u8>, Vec<u8>>) {
        self.elf_rename_sections(names);
    }
}
