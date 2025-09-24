use crate::{omf, read, Relocation, SectionIndex};

use super::OmfFile;

/// An iterator over OMF relocations.
#[derive(Debug)]
pub struct OmfRelocationIterator<'data, 'file, R: read::ReadRef<'data>> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) segment_index: usize,
    pub(super) index: usize,
}

impl<'data, 'file, R: read::ReadRef<'data>> Iterator for OmfRelocationIterator<'data, 'file, R> {
    type Item = (u64, Relocation);

    fn next(&mut self) -> Option<Self::Item> {
        let relocations = &self.file.segments[self.segment_index].relocations;
        if self.index >= relocations.len() {
            return None;
        }

        let reloc = &relocations[self.index];
        self.index += 1;

        // Convert OMF relocation to generic relocation
        let (kind, size, addend) = match reloc.location {
            omf::FixupLocation::LowByte => (read::RelocationKind::Absolute, 8, 0),
            omf::FixupLocation::HighByte => (read::RelocationKind::Absolute, 8, 0),
            omf::FixupLocation::Offset | omf::FixupLocation::LoaderOffset => {
                if reloc.is_segment_relative {
                    // M=1: Segment-relative
                    (read::RelocationKind::Absolute, 16, 0)
                } else {
                    // M=0: PC-relative (self-relative)
                    (read::RelocationKind::Relative, 16, -2)
                }
            }
            omf::FixupLocation::Offset32 | omf::FixupLocation::LoaderOffset32 => {
                if reloc.is_segment_relative {
                    // M=1: Segment-relative
                    (read::RelocationKind::Absolute, 32, 0)
                } else {
                    // M=0: PC-relative (self-relative)
                    (read::RelocationKind::Relative, 32, -4)
                }
            }
            omf::FixupLocation::Base => (read::RelocationKind::Absolute, 16, 0),
            omf::FixupLocation::Pointer => (read::RelocationKind::Absolute, 32, 0),
            omf::FixupLocation::Pointer48 => (read::RelocationKind::Absolute, 48, 0),
        };

        let relocation = Relocation {
            kind,
            encoding: read::RelocationEncoding::Generic,
            size,
            target: match reloc.target_method {
                omf::TargetMethod::SegmentIndex => {
                    read::RelocationTarget::Section(SectionIndex(reloc.target_index as usize))
                }
                omf::TargetMethod::ExternalIndex => {
                    // External indices in OMF are 1-based indices into the EXTDEF table
                    // Our symbol table has publics first, then externals
                    // So we need to adjust: symbol_index = publics.len() + (external_idx - 1)
                    if reloc.target_index > 0 {
                        let symbol_idx =
                            self.file.publics.len() + (reloc.target_index as usize - 1);
                        read::RelocationTarget::Symbol(read::SymbolIndex(symbol_idx))
                    } else {
                        // Invalid external index
                        read::RelocationTarget::Absolute
                    }
                }
                _ => read::RelocationTarget::Absolute,
            },
            addend: reloc.target_displacement as i64 + addend,
            implicit_addend: false,
            flags: read::RelocationFlags::Generic {
                kind,
                encoding: read::RelocationEncoding::Generic,
                size,
            },
        };

        Some((reloc.offset as u64, relocation))
    }
}
