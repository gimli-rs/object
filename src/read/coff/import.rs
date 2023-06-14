//! Support for reading short import files.
//!
//! These are used by some Windows linkers as a more compact way to describe
//! dynamically imported symbols.

use crate::read::{Architecture, Error, ReadError, ReadRef, Result};
use crate::{pe, ByteString, Bytes, LittleEndian as LE};

/// A Windows short form description of a symbol to import.
/// Used in Windows import libraries. This is not an object file.
#[derive(Debug, Clone)]
pub struct CoffImportFile<'data> {
    header: &'data pe::ImportObjectHeader,
    dll: ByteString<'data>,
    symbol: ByteString<'data>,
    kind: ImportType,
    import: Option<ByteString<'data>>,
}
impl<'data> CoffImportFile<'data> {
    /// Parse it.
    pub fn parse<R: ReadRef<'data>>(data: R) -> Result<Self> {
        let mut offset = 0;
        let header = pe::ImportObjectHeader::parse(data, &mut offset)?;
        let data_size = header.size_of_data.get(LE);
        let mut strings = Bytes(
            data.read_bytes(&mut offset, data_size as u64)
                .read_error("Invalid COFF import library data size")?,
        );
        let symbol = strings
            .read_string()
            .read_error("Could not read COFF import library symbol name")?;
        let dll = strings
            .read_string()
            .read_error("Could not read COFF import library DLL name")?;

        // Unmangles a name by removing a `?`, `@` or `_` prefix.
        fn strip_prefix(s: &[u8]) -> &[u8] {
            match s.split_first() {
                Some((b, rest)) if [b'?', b'@', b'_'].contains(b) => rest,
                _ => s,
            }
        }
        Ok(Self {
            header,
            dll: ByteString(dll),
            symbol: ByteString(symbol),
            kind: match header.name_type.get(LE) & 0b11 {
                pe::IMPORT_OBJECT_CODE => ImportType::Code,
                pe::IMPORT_OBJECT_DATA => ImportType::Data,
                pe::IMPORT_OBJECT_CONST => ImportType::Const,
                0b11 => return Err(Error("Invalid COFF import library import type")),
                _ => unreachable!("COFF import library ImportType must be a two bit number"),
            },
            import: match (header.name_type.get(LE) >> 2) & 0b111 {
                pe::IMPORT_OBJECT_ORDINAL => None,
                pe::IMPORT_OBJECT_NAME => Some(symbol),
                pe::IMPORT_OBJECT_NAME_NO_PREFIX => Some(strip_prefix(symbol)),
                pe::IMPORT_OBJECT_NAME_UNDECORATE => {
                    Some(strip_prefix(symbol).split(|&b| b == b'@').next().unwrap())
                }
                pe::IMPORT_OBJECT_NAME_EXPORTAS => Some(
                    strings
                        .read_string()
                        .read_error("Could not read COFF import library export name")?,
                ),
                5..=7 => return Err(Error("Unknown COFF import library name type")),
                _ => unreachable!("COFF import library name type must be a three bit number"),
            }
            .map(ByteString),
        })
    }

    /// Get the machine type.
    pub fn architecture(&self) -> Architecture {
        match self.header.machine.get(LE) {
            pe::IMAGE_FILE_MACHINE_ARMNT => Architecture::Arm,
            pe::IMAGE_FILE_MACHINE_ARM64 => Architecture::Aarch64,
            pe::IMAGE_FILE_MACHINE_I386 => Architecture::I386,
            pe::IMAGE_FILE_MACHINE_AMD64 => Architecture::X86_64,
            _ => Architecture::Unknown,
        }
    }

    /// The name of the DLL to import the symbol from.
    pub fn dll(&self) -> &'data [u8] {
        self.dll.0
    }

    /// The name exported from the DLL.
    pub fn import(&self) -> ImportName<'data> {
        match self.import {
            Some(name) => ImportName::Name(name.0),
            None => ImportName::Ordinal(self.header.ordinal_or_hint.get(LE)),
        }
    }

    /// The type of import. Usually either a function or data.
    pub fn import_type(&self) -> ImportType {
        self.kind
    }

    /// The public symbol name
    pub fn symbol(&self) -> &'data [u8] {
        self.symbol.0
    }
}

/// The name or ordinal to import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportName<'data> {
    /// Import by ordinal. Ordinarily this is a 1-based index.
    Ordinal(u16),
    /// Import by name.
    Name(&'data [u8]),
}

/// The kind of import.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImportType {
    /// Executable code
    Code,
    /// Some data
    Data,
    /// A constant value.
    Const,
}

impl pe::ImportObjectHeader {
    /// Read the short import header.
    ///
    /// Also checks that the signature and version are valid.
    /// Directly following this header will be the string data.
    pub fn parse<'data, R: ReadRef<'data>>(data: R, offset: &mut u64) -> Result<&'data Self> {
        let header = data
            .read::<crate::pe::ImportObjectHeader>(offset)
            .read_error("Invalid COFF import library header size")?;
        if header.sig1.get(LE) != 0 || header.sig2.get(LE) != pe::IMPORT_OBJECT_HDR_SIG2 {
            Err(Error("Invalid COFF import library header"))
        } else if header.version.get(LE) != 0 {
            Err(Error("Unknown COFF import library header version"))
        } else {
            Ok(header)
        }
    }
}
