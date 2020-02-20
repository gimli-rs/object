use core::fmt::Debug;

use crate::elf;
use crate::endian::{self, RunTimeEndian};
use crate::pod::{Bytes, Pod};
use crate::read::util;
use crate::read::{self, Error, ReadError};

use super::FileHeader;

/// An iterator over the notes in an `ElfSegment` or `ElfSection`.
#[derive(Debug)]
pub struct ElfNoteIterator<'data, Elf>
where
    Elf: FileHeader,
{
    endian: Elf::Endian,
    align: usize,
    data: Bytes<'data>,
}

impl<'data, Elf> ElfNoteIterator<'data, Elf>
where
    Elf: FileHeader,
{
    /// Returns `Err` if `align` is invalid.
    pub(super) fn new(
        endian: Elf::Endian,
        align: Elf::Word,
        data: Bytes<'data>,
    ) -> read::Result<Self> {
        let align = match align.into() {
            0u64..=4 => 4,
            8 => 8,
            _ => return Err(Error("Invalid ELF note alignment")),
        };
        // TODO: check data alignment?
        Ok(ElfNoteIterator {
            endian,
            align,
            data,
        })
    }

    /// Returns the next note.
    pub(super) fn next(&mut self) -> read::Result<Option<ElfNote<'data, Elf>>> {
        let mut data = self.data;
        if data.is_empty() {
            return Ok(None);
        }

        let header = data
            .read::<Elf::NoteHeader>()
            .read_error("ELF note is too short")?;

        let namesz = header.n_namesz(self.endian) as usize;
        let name = data
            .read_bytes_at(0, namesz)
            .read_error("Invalid ELF note namesz")?
            .0;

        // Skip both the name and the alignment padding.
        data.skip(util::align(namesz, self.align))
            .read_error("ELF note is too short")?;

        let descsz = header.n_descsz(self.endian) as usize;
        let desc = data
            .read_bytes_at(0, descsz)
            .read_error("Invalid ELF note descsz")?
            .0;

        // Skip both the descriptor and the alignment padding (if any).
        if data.skip(util::align(descsz, self.align)).is_err() {
            data = Bytes(&[]);
        }
        self.data = data;

        Ok(Some(ElfNote { header, name, desc }))
    }
}

/// A parsed `NoteHeader32`.
pub type ElfNote32<'data, Endian = RunTimeEndian> = ElfNote<'data, elf::FileHeader32<Endian>>;
/// A parsed `NoteHeader64`.
pub type ElfNote64<'data, Endian = RunTimeEndian> = ElfNote<'data, elf::FileHeader64<Endian>>;

/// A parsed `NoteHeader`.
#[derive(Debug)]
pub struct ElfNote<'data, Elf>
where
    Elf: FileHeader,
{
    header: &'data Elf::NoteHeader,
    name: &'data [u8],
    desc: &'data [u8],
}

impl<'data, Elf: FileHeader> ElfNote<'data, Elf> {
    /// Return the `n_type` field of the `NoteHeader`.
    ///
    /// The meaning of this field is determined by `name`.
    pub fn n_type(&self, endian: Elf::Endian) -> u32 {
        self.header.n_type(endian)
    }

    /// Return the `n_namesz` field of the `NoteHeader`.
    pub fn n_namesz(&self, endian: Elf::Endian) -> u32 {
        self.header.n_namesz(endian)
    }

    /// Return the `n_descsz` field of the `NoteHeader`.
    pub fn n_descsz(&self, endian: Elf::Endian) -> u32 {
        self.header.n_descsz(endian)
    }

    /// Return the bytes for the name field following the `NoteHeader`.
    ///
    /// The length of this field is given by `n_namesz`. This field is usually a
    /// string including a null terminator (but it is not required to be).
    pub fn name(&self) -> &'data [u8] {
        self.name
    }

    /// Return the bytes for the desc field following the `NoteHeader`.
    ///
    /// The length of this field is given by `n_descsz`. The meaning
    /// of this field is determined by `name` and `n_type`.
    pub fn desc(&self) -> &'data [u8] {
        self.desc
    }
}

/// A trait for generic access to `NoteHeader32` and `NoteHeader64`.
#[allow(missing_docs)]
pub trait NoteHeader: Debug + Pod {
    type Endian: endian::Endian;

    fn n_namesz(&self, endian: Self::Endian) -> u32;
    fn n_descsz(&self, endian: Self::Endian) -> u32;
    fn n_type(&self, endian: Self::Endian) -> u32;
}

impl<Endian: endian::Endian> NoteHeader for elf::NoteHeader32<Endian> {
    type Endian = Endian;

    #[inline]
    fn n_namesz(&self, endian: Self::Endian) -> u32 {
        self.n_namesz.get(endian)
    }

    #[inline]
    fn n_descsz(&self, endian: Self::Endian) -> u32 {
        self.n_descsz.get(endian)
    }

    #[inline]
    fn n_type(&self, endian: Self::Endian) -> u32 {
        self.n_type.get(endian)
    }
}

impl<Endian: endian::Endian> NoteHeader for elf::NoteHeader64<Endian> {
    type Endian = Endian;

    #[inline]
    fn n_namesz(&self, endian: Self::Endian) -> u32 {
        self.n_namesz.get(endian)
    }

    #[inline]
    fn n_descsz(&self, endian: Self::Endian) -> u32 {
        self.n_descsz.get(endian)
    }

    #[inline]
    fn n_type(&self, endian: Self::Endian) -> u32 {
        self.n_type.get(endian)
    }
}
