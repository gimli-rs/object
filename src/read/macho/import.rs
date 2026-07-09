use alloc::fmt;
use alloc::vec::Vec;
use core::slice;

use crate::Endianness;
use crate::macho;
use crate::read::{ByteString, Import, ReadError, ReadRef, Result};

use super::{MachHeader, MachOFile, Nlist, SymbolTable};

/// An iterator for the imports in a [`MachOFile32`](super::MachOFile32).
pub type MachOImportIterator32<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    MachOImportIterator<'data, 'file, macho::MachHeader32<Endian>, R>;
/// An iterator for the imports in a [`MachOFile64`](super::MachOFile64).
pub type MachOImportIterator64<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    MachOImportIterator<'data, 'file, macho::MachHeader64<Endian>, R>;

/// An iterator for the imports in a [`MachOFile`].
pub struct MachOImportIterator<'data, 'file, Mach, R = &'data [u8]>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    endian: Mach::Endian,
    libraries: Vec<&'data [u8]>,
    twolevel: bool,
    symbols: &'file SymbolTable<'data, Mach, R>,
    iter: slice::Iter<'data, Mach::Nlist>,
}

impl<'data, 'file, Mach, R> fmt::Debug for MachOImportIterator<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachOImportIterator").finish()
    }
}

impl<'data, 'file, Mach, R> MachOImportIterator<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    pub(super) fn new(file: &'file MachOFile<'data, Mach, R>) -> Result<Self> {
        let endian = file.endian;
        let mut iter = slice::Iter::default();
        let mut libraries = Vec::new();
        let twolevel = file.header.flags(endian).contains(macho::MH_TWOLEVEL);
        if twolevel {
            libraries.push(&[][..]);
        }
        let mut commands = file.macho_load_commands()?;
        while let Some(command) = commands.next()? {
            if let Some(dysymtab) = command.dysymtab()? {
                let symbols = file.symbols.symbols();
                let symbols = symbols
                    .get(dysymtab.iundefsym.get(endian) as usize..)
                    .read_error("Invalid Mach-O dysymtab iundefsym")?;
                let symbols = symbols
                    .get(..dysymtab.nundefsym.get(endian) as usize)
                    .read_error("Invalid Mach-O dysymtab nundefsym")?;
                iter = symbols.iter();
            }
            if twolevel {
                if let Some(dylib) = command.dylib()? {
                    libraries.push(command.string(endian, dylib.dylib.name)?);
                }
            }
        }
        Ok(MachOImportIterator {
            endian,
            libraries,
            twolevel,
            symbols: &file.symbols,
            iter,
        })
    }

    fn next(&mut self) -> Result<Option<Import<'data>>> {
        let Some(symbol) = self.iter.next() else {
            return Ok(None);
        };
        // The above iterator has made progress, so errors after here don't need to
        // terminate iteration.

        let name = symbol.name(self.endian, self.symbols.strings())?;
        let library = if self.twolevel {
            if let Some(index) = symbol.library_ordinal(self.endian).index() {
                self.libraries
                    .get(index as usize)
                    .copied()
                    .read_error("Invalid Mach-O symbol library ordinal")?
            } else {
                // Don't currently distinguish between self/executable/flat.
                &[]
            }
        } else {
            // Flat namespace.
            &[]
        };
        Ok(Some(Import {
            name: ByteString(name),
            library: ByteString(library),
        }))
    }
}

impl<'data, 'file, Mach, R> Iterator for MachOImportIterator<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    type Item = Result<Import<'data>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next().transpose()
    }
}
