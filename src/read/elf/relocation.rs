use alloc::fmt;
use core::fmt::Debug;
use core::slice;

use crate::elf;
use crate::endian::{self, RunTimeEndian};
use crate::pod::Pod;
use crate::read::{Relocation, RelocationEncoding, RelocationKind, RelocationTarget, SymbolIndex};

use super::{ElfFile, FileHeader, SectionHeader};

pub(super) enum ElfRelaIterator<'data, Elf: FileHeader> {
    Rel(slice::Iter<'data, Elf::Rel>),
    Rela(slice::Iter<'data, Elf::Rela>),
}

impl<'data, Elf: FileHeader> ElfRelaIterator<'data, Elf> {
    fn is_rel(&self) -> bool {
        match self {
            ElfRelaIterator::Rel(_) => true,
            ElfRelaIterator::Rela(_) => false,
        }
    }
}

impl<'data, Elf: FileHeader> Iterator for ElfRelaIterator<'data, Elf> {
    type Item = Elf::Rela;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ElfRelaIterator::Rel(ref mut i) => i.next().cloned().map(Self::Item::from),
            ElfRelaIterator::Rela(ref mut i) => i.next().cloned(),
        }
    }
}

/// An iterator over the relocations for an `ElfSection32`.
pub type ElfRelocationIterator32<'data, 'file, Endian = RunTimeEndian> =
    ElfRelocationIterator<'data, 'file, elf::FileHeader32<Endian>>;
/// An iterator over the relocations for an `ElfSection64`.
pub type ElfRelocationIterator64<'data, 'file, Endian = RunTimeEndian> =
    ElfRelocationIterator<'data, 'file, elf::FileHeader64<Endian>>;

/// An iterator over the relocations for an `ElfSection`.
pub struct ElfRelocationIterator<'data, 'file, Elf>
where
    'data: 'file,
    Elf: FileHeader,
{
    /// The current pointer in the chain of relocation sections.
    pub(super) section_index: usize,
    pub(super) file: &'file ElfFile<'data, Elf>,
    pub(super) relocations: Option<ElfRelaIterator<'data, Elf>>,
}

impl<'data, 'file, Elf: FileHeader> Iterator for ElfRelocationIterator<'data, 'file, Elf> {
    type Item = (u64, Relocation);

    fn next(&mut self) -> Option<Self::Item> {
        let endian = self.file.endian;
        loop {
            if let Some(ref mut relocations) = self.relocations {
                if let Some(reloc) = relocations.next() {
                    let mut encoding = RelocationEncoding::Generic;
                    let (kind, size) = match self.file.header.e_machine(endian) {
                        elf::EM_ARM => match reloc.r_type(endian) {
                            elf::R_ARM_ABS32 => (RelocationKind::Absolute, 32),
                            r_type => (RelocationKind::Elf(r_type), 0),
                        },
                        elf::EM_AARCH64 => match reloc.r_type(endian) {
                            elf::R_AARCH64_ABS64 => (RelocationKind::Absolute, 64),
                            elf::R_AARCH64_ABS32 => (RelocationKind::Absolute, 32),
                            elf::R_AARCH64_ABS16 => (RelocationKind::Absolute, 16),
                            elf::R_AARCH64_PREL64 => (RelocationKind::Relative, 64),
                            elf::R_AARCH64_PREL32 => (RelocationKind::Relative, 32),
                            elf::R_AARCH64_PREL16 => (RelocationKind::Relative, 16),
                            r_type => (RelocationKind::Elf(r_type), 0),
                        },
                        elf::EM_386 => match reloc.r_type(endian) {
                            elf::R_386_32 => (RelocationKind::Absolute, 32),
                            elf::R_386_PC32 => (RelocationKind::Relative, 32),
                            elf::R_386_GOT32 => (RelocationKind::Got, 32),
                            elf::R_386_PLT32 => (RelocationKind::PltRelative, 32),
                            elf::R_386_GOTOFF => (RelocationKind::GotBaseOffset, 32),
                            elf::R_386_GOTPC => (RelocationKind::GotBaseRelative, 32),
                            elf::R_386_16 => (RelocationKind::Absolute, 16),
                            elf::R_386_PC16 => (RelocationKind::Relative, 16),
                            elf::R_386_8 => (RelocationKind::Absolute, 8),
                            elf::R_386_PC8 => (RelocationKind::Relative, 8),
                            r_type => (RelocationKind::Elf(r_type), 0),
                        },
                        elf::EM_X86_64 => match reloc.r_type(endian) {
                            elf::R_X86_64_64 => (RelocationKind::Absolute, 64),
                            elf::R_X86_64_PC32 => (RelocationKind::Relative, 32),
                            elf::R_X86_64_GOT32 => (RelocationKind::Got, 32),
                            elf::R_X86_64_PLT32 => (RelocationKind::PltRelative, 32),
                            elf::R_X86_64_GOTPCREL => (RelocationKind::GotRelative, 32),
                            elf::R_X86_64_32 => (RelocationKind::Absolute, 32),
                            elf::R_X86_64_32S => {
                                encoding = RelocationEncoding::X86Signed;
                                (RelocationKind::Absolute, 32)
                            }
                            elf::R_X86_64_16 => (RelocationKind::Absolute, 16),
                            elf::R_X86_64_PC16 => (RelocationKind::Relative, 16),
                            elf::R_X86_64_8 => (RelocationKind::Absolute, 8),
                            elf::R_X86_64_PC8 => (RelocationKind::Relative, 8),
                            r_type => (RelocationKind::Elf(r_type), 0),
                        },
                        _ => (RelocationKind::Elf(reloc.r_type(endian)), 0),
                    };
                    let target =
                        RelocationTarget::Symbol(SymbolIndex(reloc.r_sym(endian) as usize));
                    return Some((
                        reloc.r_offset(endian).into(),
                        Relocation {
                            kind,
                            encoding,
                            size,
                            target,
                            addend: reloc.r_addend(endian).into(),
                            implicit_addend: relocations.is_rel(),
                        },
                    ));
                }
            }
            // End of the relocation section chain?
            if self.section_index == 0 {
                return None;
            }
            let section = self.file.sections.section(self.section_index).ok()?;
            match section.sh_type(endian) {
                elf::SHT_REL => {
                    if let Ok(relocations) = section.data_as_array(endian, self.file.data) {
                        self.relocations = Some(ElfRelaIterator::Rel(relocations.iter()));
                    }
                }
                elf::SHT_RELA => {
                    if let Ok(relocations) = section.data_as_array(endian, self.file.data) {
                        self.relocations = Some(ElfRelaIterator::Rela(relocations.iter()));
                    }
                }
                _ => {}
            }
            // Get the next relocation section in the chain.
            self.section_index = self.file.relocations[self.section_index];
        }
    }
}

impl<'data, 'file, Elf: FileHeader> fmt::Debug for ElfRelocationIterator<'data, 'file, Elf> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ElfRelocationIterator").finish()
    }
}

/// A trait for generic access to `Rela32` and `Rela64`.
#[allow(missing_docs)]
pub trait Rela: Debug + Pod + Clone {
    type Word: Into<u64>;
    type Sword: Into<i64>;
    type Endian: endian::Endian;

    fn r_offset(&self, endian: Self::Endian) -> Self::Word;
    fn r_info(&self, endian: Self::Endian) -> Self::Word;
    fn r_addend(&self, endian: Self::Endian) -> Self::Sword;
    fn r_sym(&self, endian: Self::Endian) -> u32;
    fn r_type(&self, endian: Self::Endian) -> u32;
}

impl<Endian: endian::Endian> Rela for elf::Rela32<Endian> {
    type Word = u32;
    type Sword = i32;
    type Endian = Endian;

    #[inline]
    fn r_offset(&self, endian: Self::Endian) -> Self::Word {
        self.r_offset.get(endian)
    }

    #[inline]
    fn r_info(&self, endian: Self::Endian) -> Self::Word {
        self.r_info.get(endian)
    }

    #[inline]
    fn r_addend(&self, endian: Self::Endian) -> Self::Sword {
        self.r_addend.get(endian)
    }

    #[inline]
    fn r_sym(&self, endian: Self::Endian) -> u32 {
        self.r_sym(endian)
    }

    #[inline]
    fn r_type(&self, endian: Self::Endian) -> u32 {
        self.r_type(endian)
    }
}

impl<Endian: endian::Endian> Rela for elf::Rela64<Endian> {
    type Word = u64;
    type Sword = i64;
    type Endian = Endian;

    #[inline]
    fn r_offset(&self, endian: Self::Endian) -> Self::Word {
        self.r_offset.get(endian)
    }

    #[inline]
    fn r_info(&self, endian: Self::Endian) -> Self::Word {
        self.r_info.get(endian)
    }

    #[inline]
    fn r_addend(&self, endian: Self::Endian) -> Self::Sword {
        self.r_addend.get(endian)
    }

    #[inline]
    fn r_sym(&self, endian: Self::Endian) -> u32 {
        self.r_sym(endian)
    }

    #[inline]
    fn r_type(&self, endian: Self::Endian) -> u32 {
        self.r_type(endian)
    }
}
