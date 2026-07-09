use alloc::fmt;
use core::slice;

use crate::Endianness;
use crate::macho;
use crate::read::{ByteString, Export, ReadError, ReadRef, Result};

use super::{MachHeader, MachOFile, Nlist, SymbolTable};

/// An iterator for the exports in a [`MachOFile32`](super::MachOFile32).
pub type MachOExportIterator32<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    MachOExportIterator<'data, 'file, macho::MachHeader32<Endian>, R>;
/// An iterator for the exports in a [`MachOFile64`](super::MachOFile64).
pub type MachOExportIterator64<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    MachOExportIterator<'data, 'file, macho::MachHeader64<Endian>, R>;

/// An iterator for the exports in a [`MachOFile`].
pub struct MachOExportIterator<'data, 'file, Mach, R = &'data [u8]>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    endian: Mach::Endian,
    symbols: &'file SymbolTable<'data, Mach, R>,
    iter: slice::Iter<'data, Mach::Nlist>,
}

impl<'data, 'file, Mach, R> fmt::Debug for MachOExportIterator<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachOExportIterator").finish()
    }
}

impl<'data, 'file, Mach, R> MachOExportIterator<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    pub(super) fn new(file: &'file MachOFile<'data, Mach, R>) -> Result<Self> {
        let endian = file.endian;
        let mut iter = slice::Iter::default();
        let mut commands = file.macho_load_commands()?;
        while let Some(command) = commands.next()? {
            if let Some(dysymtab) = command.dysymtab()? {
                let symbols = file.symbols.symbols();
                let symbols = symbols
                    .get(dysymtab.iextdefsym.get(endian) as usize..)
                    .read_error("Invalid Mach-O dysymtab iextdefsym")?;
                let symbols = symbols
                    .get(..dysymtab.nextdefsym.get(endian) as usize)
                    .read_error("Invalid Mach-O dysymtab nextdefsym")?;
                iter = symbols.iter();
                break;
            }
        }
        Ok(MachOExportIterator {
            endian,
            symbols: &file.symbols,
            iter,
        })
    }

    fn next(&mut self) -> Result<Option<Export<'data>>> {
        let Some(symbol) = self.iter.next() else {
            return Ok(None);
        };
        // The above iterator has made progress, so errors after here don't need to
        // terminate iteration.

        let name = symbol.name(self.endian, self.symbols.strings())?;
        let address = symbol.n_value(self.endian).into();
        Ok(Some(Export {
            name: ByteString(name),
            address,
        }))
    }
}

impl<'data, 'file, Mach, R> Iterator for MachOExportIterator<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    type Item = Result<Export<'data>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next().transpose()
    }
}
