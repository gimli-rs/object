use alloc::fmt;

use crate::elf;
use crate::endian::Endianness;
use crate::read::{self, ByteString, Export, ReadRef, SymbolIndex};

use super::{FileHeader, Sym, SymbolTable};

/// An iterator for the exports in an [`ElfFile32`](super::ElfFile32).
pub type ElfExportIterator32<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    ElfExportIterator<'data, 'file, elf::FileHeader32<Endian>, R>;
/// An iterator for the exports in an [`ElfFile64`](super::ElfFile64).
pub type ElfExportIterator64<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    ElfExportIterator<'data, 'file, elf::FileHeader64<Endian>, R>;

/// An iterator for the exports in an [`ElfFile`](super::ElfFile).
pub struct ElfExportIterator<'data, 'file, Elf, R = &'data [u8]>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
{
    endian: Elf::Endian,
    symbols: &'file SymbolTable<'data, Elf, R>,
    index: SymbolIndex,
}

impl<'data, 'file, Elf, R> ElfExportIterator<'data, 'file, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
{
    pub(super) fn new(endian: Elf::Endian, symbols: &'file SymbolTable<'data, Elf, R>) -> Self {
        ElfExportIterator {
            endian,
            symbols,
            index: SymbolIndex(1),
        }
    }

    fn next(&mut self) -> read::Result<Option<Export<'data>>> {
        loop {
            let index = self.index;
            let Some(symbol) = self.symbols.symbols().get(index.0) else {
                return Ok(None);
            };
            // Ensure progress is made, so errors after here don't need to terminate iteration.
            self.index.0 += 1;

            if !symbol.is_definition(self.endian, self.symbols.strings()) {
                continue;
            }
            let name = symbol.name(self.endian, self.symbols.strings())?;
            let address = symbol.st_value(self.endian).into();
            return Ok(Some(Export {
                name: ByteString(name),
                address,
            }));
        }
    }
}

impl<'data, 'file, Elf: FileHeader, R: ReadRef<'data>> fmt::Debug
    for ElfExportIterator<'data, 'file, Elf, R>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ElfExportIterator").finish()
    }
}

impl<'data, 'file, Elf: FileHeader, R: ReadRef<'data>> Iterator
    for ElfExportIterator<'data, 'file, Elf, R>
{
    type Item = read::Result<Export<'data>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next().transpose()
    }
}
