use alloc::fmt;
use alloc::vec::Vec;
use core::slice;

use crate::Endianness;
use crate::macho;
use crate::read::{Import, ImportFlags, NameOrOrdinal, ReadError, ReadRef, Result};

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
        let twolevel = file.header.flags(endian).contains(macho::MH_TWOLEVEL);
        let libraries = if twolevel {
            file.libraries()?
        } else {
            Vec::new()
        };
        // `LC_DYSYMTAB` is not required, so use the symbol table directly.
        let iter = file.symbols.symbols().iter();
        Ok(MachOImportIterator {
            endian,
            libraries,
            twolevel,
            symbols: &file.symbols,
            iter,
        })
    }

    fn next(&mut self) -> Result<Option<Import<'data>>> {
        let Some(symbol) = self.iter.find(|s| s.is_undefined()) else {
            return Ok(None);
        };
        // The above iterator has made progress, so errors after here don't need to
        // terminate iteration.

        let name = symbol.name(self.endian, self.symbols.strings())?;
        let n_desc = symbol.n_desc(self.endian);
        let library = if self.twolevel {
            if let Some(index) = n_desc.library().index() {
                self.libraries
                    .get(index as usize)
                    .copied()
                    .read_error("Invalid Mach-O symbol library ordinal")?
            } else {
                // Reserved ordinal; caller can use `n_desc.library()` from `flags`.
                &[]
            }
        } else {
            // Flat namespace.
            &[]
        };
        Ok(Some(Import {
            library,
            name: NameOrOrdinal::Name(name),
            weak: n_desc.contains(macho::N_WEAK_REF),
            flags: ImportFlags::MachO {
                n_type: symbol.n_type(),
                n_desc,
            },
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
