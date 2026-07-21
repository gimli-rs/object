use alloc::fmt;

use crate::elf;
use crate::endian::Endianness;
use crate::read::{self, Import, ImportFlags, NameOrOrdinal, ReadRef, SymbolIndex};

use super::{FileHeader, Sym, SymbolTable, VersionTable};

/// An iterator for the imports in an [`ElfFile32`](super::ElfFile32).
pub type ElfImportIterator32<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    ElfImportIterator<'data, 'file, elf::FileHeader32<Endian>, R>;
/// An iterator for the imports in an [`ElfFile64`](super::ElfFile64).
pub type ElfImportIterator64<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    ElfImportIterator<'data, 'file, elf::FileHeader64<Endian>, R>;

/// An iterator for the imports in an [`ElfFile`](super::ElfFile).
pub struct ElfImportIterator<'data, 'file, Elf, R = &'data [u8]>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
{
    endian: Elf::Endian,
    versions: Option<VersionTable<'data, Elf>>,
    symbols: &'file SymbolTable<'data, Elf, R>,
    index: SymbolIndex,
}

impl<'data, 'file, Elf, R> ElfImportIterator<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
{
    pub(super) fn new(
        endian: Elf::Endian,
        versions: Option<VersionTable<'data, Elf>>,
        symbols: &'file SymbolTable<'data, Elf, R>,
    ) -> Self {
        ElfImportIterator {
            endian,
            versions,
            symbols,
            index: SymbolIndex(1),
        }
    }

    fn next(&mut self) -> read::Result<Option<Import<'data>>> {
        loop {
            let index = self.index;
            let Some(symbol) = self.symbols.symbols().get(index.0) else {
                return Ok(None);
            };
            // Ensure progress is made, so errors after here don't need to terminate iteration.
            self.index.0 += 1;

            if !symbol.is_undefined(self.endian) {
                continue;
            }
            let name = symbol.name(self.endian, self.symbols.strings())?;
            if name.is_empty() {
                continue;
            }
            let version = if let Some(versions) = self.versions.as_ref() {
                let vi = versions.version_index(self.endian, index).index();
                versions.version(vi)?
            } else {
                None
            };
            return Ok(Some(Import {
                library: version.and_then(|v| v.file()).unwrap_or(&[]),
                name: NameOrOrdinal::Name(name),
                weak: symbol.st_bind() == elf::STB_WEAK,
                flags: ImportFlags::Elf {
                    st_info: symbol.st_info(),
                    st_other: symbol.st_other(),
                    version: version.map(|v| v.name()),
                },
            }));
        }
    }
}

impl<'data, 'file, Elf: FileHeader, R: ReadRef<'data>> fmt::Debug
    for ElfImportIterator<'data, 'file, Elf, R>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ElfImportIterator").finish()
    }
}

impl<'data, 'file, Elf: FileHeader, R: ReadRef<'data>> Iterator
    for ElfImportIterator<'data, 'file, Elf, R>
{
    type Item = read::Result<Import<'data>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next().transpose()
    }
}
