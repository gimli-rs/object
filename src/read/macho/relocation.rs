use core::{fmt, slice};

use crate::endian::RunTimeEndian;
use crate::macho;
use crate::read::{
    Relocation, RelocationEncoding, RelocationKind, RelocationTarget, SectionIndex, SymbolIndex,
};

use super::{MachHeader, MachOFile};

/// An iterator over the relocations in a `MachOSection32`.
pub type MachORelocationIterator32<'data, 'file, Endian = RunTimeEndian> =
    MachORelocationIterator<'data, 'file, macho::MachHeader32<Endian>>;
/// An iterator over the relocations in a `MachOSection64`.
pub type MachORelocationIterator64<'data, 'file, Endian = RunTimeEndian> =
    MachORelocationIterator<'data, 'file, macho::MachHeader64<Endian>>;

/// An iterator over the relocations in a `MachOSection`.
pub struct MachORelocationIterator<'data, 'file, Mach>
where
    'data: 'file,
    Mach: MachHeader,
{
    pub(super) file: &'file MachOFile<'data, Mach>,
    pub(super) relocations: slice::Iter<'data, macho::Relocation<Mach::Endian>>,
}

impl<'data, 'file, Mach: MachHeader> Iterator for MachORelocationIterator<'data, 'file, Mach> {
    type Item = (u64, Relocation);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let reloc = self.relocations.next()?;
            let endian = self.file.endian;
            let cputype = self.file.header.cputype(endian);
            if reloc.r_scattered(endian, cputype) {
                // FIXME: handle scattered relocations
                // We need to add `RelocationTarget::Address` for this.
                continue;
            }
            let reloc = reloc.info(self.file.endian);
            let mut encoding = RelocationEncoding::Generic;
            let kind = match cputype {
                macho::CPU_TYPE_ARM => match (reloc.r_type, reloc.r_pcrel) {
                    (macho::ARM_RELOC_VANILLA, false) => RelocationKind::Absolute,
                    _ => RelocationKind::MachO {
                        value: reloc.r_type,
                        relative: reloc.r_pcrel,
                    },
                },
                macho::CPU_TYPE_ARM64 => match (reloc.r_type, reloc.r_pcrel) {
                    (macho::ARM64_RELOC_UNSIGNED, false) => RelocationKind::Absolute,
                    _ => RelocationKind::MachO {
                        value: reloc.r_type,
                        relative: reloc.r_pcrel,
                    },
                },
                macho::CPU_TYPE_X86 => match (reloc.r_type, reloc.r_pcrel) {
                    (macho::GENERIC_RELOC_VANILLA, false) => RelocationKind::Absolute,
                    _ => RelocationKind::MachO {
                        value: reloc.r_type,
                        relative: reloc.r_pcrel,
                    },
                },
                macho::CPU_TYPE_X86_64 => match (reloc.r_type, reloc.r_pcrel) {
                    (macho::X86_64_RELOC_UNSIGNED, false) => RelocationKind::Absolute,
                    (macho::X86_64_RELOC_SIGNED, true) => {
                        encoding = RelocationEncoding::X86RipRelative;
                        RelocationKind::Relative
                    }
                    (macho::X86_64_RELOC_BRANCH, true) => {
                        encoding = RelocationEncoding::X86Branch;
                        RelocationKind::Relative
                    }
                    (macho::X86_64_RELOC_GOT, true) => RelocationKind::GotRelative,
                    (macho::X86_64_RELOC_GOT_LOAD, true) => {
                        encoding = RelocationEncoding::X86RipRelativeMovq;
                        RelocationKind::GotRelative
                    }
                    _ => RelocationKind::MachO {
                        value: reloc.r_type,
                        relative: reloc.r_pcrel,
                    },
                },
                _ => RelocationKind::MachO {
                    value: reloc.r_type,
                    relative: reloc.r_pcrel,
                },
            };
            let size = 8 << reloc.r_length;
            let target = if reloc.r_extern {
                RelocationTarget::Symbol(SymbolIndex(reloc.r_symbolnum as usize))
            } else {
                RelocationTarget::Section(SectionIndex(reloc.r_symbolnum as usize))
            };
            let addend = if reloc.r_pcrel { -4 } else { 0 };
            return Some((
                reloc.r_address as u64,
                Relocation {
                    kind,
                    encoding,
                    size,
                    target,
                    addend,
                    implicit_addend: true,
                },
            ));
        }
    }
}

impl<'data, 'file, Mach: MachHeader> fmt::Debug for MachORelocationIterator<'data, 'file, Mach> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachORelocationIterator").finish()
    }
}
