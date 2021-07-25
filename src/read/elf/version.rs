use crate::elf;
use crate::read::{Bytes, ReadError, Result};

use super::FileHeader;

/// An iterator over the entries in an ELF `SHT_GNU_verdef` section.
#[derive(Debug, Clone)]
pub struct VerdefIterator<'data, Elf: FileHeader> {
    endian: Elf::Endian,
    data: Bytes<'data>,
}

impl<'data, Elf: FileHeader> VerdefIterator<'data, Elf> {
    pub(super) fn new(endian: Elf::Endian, data: &'data [u8]) -> Self {
        VerdefIterator {
            endian,
            data: Bytes(data),
        }
    }

    /// Return the next `Verdef` entry.
    pub fn next(
        &mut self,
    ) -> Result<Option<(&'data elf::Verdef<Elf::Endian>, VerdauxIterator<'data, Elf>)>> {
        if self.data.is_empty() {
            return Ok(None);
        }

        let verdef = self
            .data
            .read_at::<elf::Verdef<_>>(0)
            .read_error("ELF verdef is too short")?;

        let mut verdaux_data = self.data;
        verdaux_data
            .skip(verdef.vd_aux.get(self.endian) as usize)
            .read_error("Invalid ELF vd_aux")?;
        let verdaux =
            VerdauxIterator::new(self.endian, verdaux_data.0, verdef.vd_cnt.get(self.endian));

        let next = verdef.vd_next.get(self.endian);
        if next != 0 {
            self.data
                .skip(next as usize)
                .read_error("Invalid ELF vd_next")?;
        } else {
            self.data = Bytes(&[]);
        }
        Ok(Some((verdef, verdaux)))
    }
}

/// An iterator over the auxiliary records for an entry in an ELF `SHT_GNU_verdef` section.
#[derive(Debug, Clone)]
pub struct VerdauxIterator<'data, Elf: FileHeader> {
    endian: Elf::Endian,
    data: Bytes<'data>,
    count: u16,
}

impl<'data, Elf: FileHeader> VerdauxIterator<'data, Elf> {
    pub(super) fn new(endian: Elf::Endian, data: &'data [u8], count: u16) -> Self {
        VerdauxIterator {
            endian,
            data: Bytes(data),
            count,
        }
    }

    /// Return the next `Verdaux` entry.
    pub fn next(&mut self) -> Result<Option<&'data elf::Verdaux<Elf::Endian>>> {
        if self.count == 0 {
            return Ok(None);
        }

        let verdaux = self
            .data
            .read_at::<elf::Verdaux<_>>(0)
            .read_error("ELF verdaux is too short")?;

        self.data
            .skip(verdaux.vda_next.get(self.endian) as usize)
            .read_error("Invalid ELF vda_next")?;
        self.count -= 1;
        Ok(Some(verdaux))
    }
}

/// An iterator over the entries in an ELF `SHT_GNU_verneed` section.
#[derive(Debug, Clone)]
pub struct VerneedIterator<'data, Elf: FileHeader> {
    endian: Elf::Endian,
    data: Bytes<'data>,
}

impl<'data, Elf: FileHeader> VerneedIterator<'data, Elf> {
    pub(super) fn new(endian: Elf::Endian, data: &'data [u8]) -> Self {
        VerneedIterator {
            endian,
            data: Bytes(data),
        }
    }

    /// Return the next `Verneed` entry.
    pub fn next(
        &mut self,
    ) -> Result<
        Option<(
            &'data elf::Verneed<Elf::Endian>,
            VernauxIterator<'data, Elf>,
        )>,
    > {
        if self.data.is_empty() {
            return Ok(None);
        }

        let verneed = self
            .data
            .read_at::<elf::Verneed<_>>(0)
            .read_error("ELF verneed is too short")?;

        let mut vernaux_data = self.data;
        vernaux_data
            .skip(verneed.vn_aux.get(self.endian) as usize)
            .read_error("Invalid ELF vn_aux")?;
        let vernaux =
            VernauxIterator::new(self.endian, vernaux_data.0, verneed.vn_cnt.get(self.endian));

        let next = verneed.vn_next.get(self.endian);
        if next != 0 {
            self.data
                .skip(next as usize)
                .read_error("Invalid ELF vn_next")?;
        } else {
            self.data = Bytes(&[]);
        }
        Ok(Some((verneed, vernaux)))
    }
}

/// An iterator over the auxiliary records for an entry in an ELF `SHT_GNU_verneed` section.
#[derive(Debug, Clone)]
pub struct VernauxIterator<'data, Elf: FileHeader> {
    endian: Elf::Endian,
    data: Bytes<'data>,
    count: u16,
}

impl<'data, Elf: FileHeader> VernauxIterator<'data, Elf> {
    pub(super) fn new(endian: Elf::Endian, data: &'data [u8], count: u16) -> Self {
        VernauxIterator {
            endian,
            data: Bytes(data),
            count,
        }
    }

    /// Return the next `Vernaux` entry.
    pub fn next(&mut self) -> Result<Option<&'data elf::Vernaux<Elf::Endian>>> {
        if self.count == 0 {
            return Ok(None);
        }

        let vernaux = self
            .data
            .read_at::<elf::Vernaux<_>>(0)
            .read_error("ELF vernaux is too short")?;

        self.data
            .skip(vernaux.vna_next.get(self.endian) as usize)
            .read_error("Invalid ELF vna_next")?;
        self.count -= 1;
        Ok(Some(vernaux))
    }
}
