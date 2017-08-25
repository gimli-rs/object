//! # `object`
//!
//! The `object` crate provides a unified interface to working with object files
//! across platforms.
//!
//! See the [`File` struct](./struct.File.html) for details.

#![deny(missing_docs)]

extern crate goblin;

use goblin::{elf, mach};
use std::io::Cursor;

/// An object file.
pub struct File<'a> {
    kind: ObjectKind<'a>,
    data: &'a [u8],
}

enum ObjectKind<'a> {
    Elf(elf::Elf<'a>),
    MachO(mach::MachO<'a>),
}

impl<'a> File<'a> {
    /// Parse the raw object file data.
    pub fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        let mut cursor = Cursor::new(data);
        let kind = match goblin::peek(&mut cursor)
                  .map_err(|_| "Could not parse file magic")? {
            goblin::Hint::Elf(_) => {
                let elf = elf::Elf::parse(data)
                    .map_err(|_| "Could not parse ELF header")?;
                ObjectKind::Elf(elf)
            }
            goblin::Hint::Mach(_) => {
                let macho = mach::MachO::parse(data, 0)
                    .map_err(|_| "Could not parse Mach-O header")?;
                ObjectKind::MachO(macho)
            }
            _ => return Err("Unknown file magic"),
        };
        Ok(File { kind, data })
    }

    /// Get the contents of the section named `section_name`, if such
    /// a section exists.
    pub fn get_section(&self, section_name: &str) -> Option<&'a [u8]> {
        match self.kind {
            ObjectKind::Elf(ref elf) => elf_get_section(elf, section_name, self.data),
            ObjectKind::MachO(ref macho) => macho_get_section(macho, section_name),
        }
    }

    /// Return true if the file is little endian, false if it is big endian.
    pub fn is_little_endian(&self) -> bool {
        match self.kind {
            ObjectKind::Elf(ref elf) => elf.little_endian,
            ObjectKind::MachO(ref macho) => macho.header.is_little_endian(),
        }
    }
}

fn elf_get_section<'a>(elf: &elf::Elf<'a>, section_name: &str, data: &'a [u8]) -> Option<&'a [u8]> {
    for header in &elf.section_headers {
        if let Some(Ok(name)) = elf.shdr_strtab.get(header.sh_name) {
            if name == section_name {
                return Some(&data[header.sh_offset as usize..][..header.sh_size as usize]);
            }
        }
    }
    None
}

fn macho_get_section<'a>(macho: &mach::MachO<'a>, section_name: &str) -> Option<&'a [u8]> {
    let segment_name = "__DWARF";
    let section_name = macho_translate_section_name(section_name);

    for segment in &macho.segments {
        if let Ok(name) = segment.name() {
            if name == segment_name {
                for section in segment {
                    if let Ok((section, data)) = section {
                        if let Ok(name) = section.name() {
                            if name.as_bytes() == &*section_name {
                                return Some(data);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

// Translate the "." prefix to the "__" prefix used by OSX/Mach-O, eg
// ".debug_info" to "__debug_info".
fn macho_translate_section_name(section_name: &str) -> Vec<u8> {
    let mut name = Vec::with_capacity(section_name.len() + 1);
    name.push(b'_');
    name.push(b'_');
    for ch in &section_name.as_bytes()[1..] {
        name.push(*ch);
    }
    name
}

#[doc(hidden)]
#[deprecated]
pub trait Object {}
