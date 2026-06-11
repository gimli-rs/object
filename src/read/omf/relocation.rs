use crate::read::ReadRef;
use crate::{
    omf, Relocation, RelocationEncoding, RelocationFlags, RelocationKind, RelocationTarget,
    SectionIndex,
};

use super::{FrameMethod, OmfFile, TargetMethod};

/// An OMF fixup (relocation entry).
#[derive(Debug, Clone)]
pub(super) struct OmfFixup {
    /// Offset in the section where the fixup is applied
    pub(super) offset: u32,
    /// Location type (what to patch)
    pub(super) location: omf::FixupLocation,
    /// Frame method
    pub(super) frame_method: FrameMethod,
    /// Target method
    pub(super) target_method: TargetMethod,
    /// Frame index (meaning depends on frame_method)
    pub(super) frame_index: u16,
    /// Target index (meaning depends on target_method)
    pub(super) target_index: u16,
    /// Target displacement
    pub(super) target_displacement: u32,
    /// M-bit: true for segment-relative, false for self-relative
    pub(super) is_segment_relative: bool,
}

impl omf::FixupLocation {
    /// The size in bytes of the location being fixed up.
    fn byte_size(self) -> u8 {
        match self {
            omf::FixupLocation::LowByte | omf::FixupLocation::HighByte => 1,
            omf::FixupLocation::Offset
            | omf::FixupLocation::LoaderOffset
            | omf::FixupLocation::Base => 2,
            omf::FixupLocation::Pointer
            | omf::FixupLocation::Offset32
            | omf::FixupLocation::LoaderOffset32 => 4,
            omf::FixupLocation::Pointer48 => 6,
        }
    }
}

/// An iterator for the relocations in an [`OmfSection`](super::OmfSection).
#[derive(Debug)]
pub struct OmfRelocationIterator<'data, 'file, R: ReadRef<'data>> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) section_index: usize,
    pub(super) index: usize,
}

impl<'data, 'file, R: ReadRef<'data>> OmfRelocationIterator<'data, 'file, R> {
    /// Resolve a 1-based segment index to a section index.
    fn target_section(&self, segment_index: u16) -> Option<SectionIndex> {
        let section = self.file.segdef_section(segment_index).ok()?;
        Some(SectionIndex(section + 1))
    }

    /// Return true if the frame of the fixup is the FLAT group, in which case
    /// segment-relative fixups resolve to linear addresses.
    fn frame_is_flat(&self, reloc: &OmfFixup) -> bool {
        reloc.frame_method == FrameMethod::GroupIndex
            && self.file.group_name(reloc.frame_index) == Some(b"FLAT")
    }
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfRelocationIterator<'data, 'file, R> {
    type Item = (u64, Relocation);

    fn next(&mut self) -> Option<Self::Item> {
        let relocations = &self.file.sections[self.section_index].relocations;
        let reloc = relocations.get(self.index)?;
        self.index += 1;

        let size = reloc.location.byte_size() * 8;

        let target = match reloc.target_method {
            TargetMethod::SegmentIndex => match self.target_section(reloc.target_index) {
                Some(section) => RelocationTarget::Section(section),
                None => RelocationTarget::Absolute,
            },
            TargetMethod::ExternalIndex => {
                // External indices are 1-based indices into the external-name table
                match self.file.external_symbol(reloc.target_index) {
                    Some(symbol) => RelocationTarget::Symbol(symbol.index),
                    None => RelocationTarget::Absolute,
                }
            }
            TargetMethod::GroupIndex | TargetMethod::FrameNumber => RelocationTarget::Absolute,
        };

        let mut addend = reloc.target_displacement as i64;
        let kind = if !reloc.is_segment_relative {
            // Self-relative fixups are relative to the end of the location.
            addend -= reloc.location.byte_size() as i64;
            RelocationKind::Relative
        } else {
            match reloc.location {
                // The segment portion of the target's address.
                omf::FixupLocation::Base => {
                    if reloc.target_method == TargetMethod::SegmentIndex {
                        RelocationKind::SectionIndex
                    } else {
                        RelocationKind::Unknown
                    }
                }
                // Far pointers hold a complete segment:offset address.
                omf::FixupLocation::Pointer | omf::FixupLocation::Pointer48 => {
                    RelocationKind::Absolute
                }
                // The offset portion of the target's address, relative to the
                // frame.
                omf::FixupLocation::LowByte
                | omf::FixupLocation::Offset
                | omf::FixupLocation::LoaderOffset
                | omf::FixupLocation::Offset32
                | omf::FixupLocation::LoaderOffset32 => {
                    if self.frame_is_flat(reloc) {
                        // The FLAT group has a base address of 0, so the
                        // offset is a linear address.
                        RelocationKind::Absolute
                    } else if reloc.frame_method == FrameMethod::Target
                        || (reloc.frame_method == FrameMethod::SegmentIndex
                            && reloc.target_method == TargetMethod::SegmentIndex
                            && reloc.frame_index == reloc.target_index)
                    {
                        // The frame is the section containing the target, so
                        // the offset is a section offset.
                        RelocationKind::SectionOffset
                    } else {
                        RelocationKind::Unknown
                    }
                }
                // The high byte of an offset can't be expressed generically.
                omf::FixupLocation::HighByte => RelocationKind::Unknown,
            }
        };

        let frame = match reloc.frame_method {
            FrameMethod::SegmentIndex => omf::FixupFrame::Segment(reloc.frame_index),
            FrameMethod::GroupIndex => omf::FixupFrame::Group(reloc.frame_index),
            FrameMethod::ExternalIndex => omf::FixupFrame::External(reloc.frame_index),
            FrameMethod::FrameNumber => omf::FixupFrame::FrameNumber(reloc.frame_index),
            FrameMethod::Location => omf::FixupFrame::Location,
            FrameMethod::Target => omf::FixupFrame::Target,
        };

        let fixup_target = match reloc.target_method {
            TargetMethod::SegmentIndex => omf::FixupTarget::Segment(reloc.target_index),
            TargetMethod::GroupIndex => omf::FixupTarget::Group(reloc.target_index),
            TargetMethod::ExternalIndex => omf::FixupTarget::External(reloc.target_index),
            TargetMethod::FrameNumber => omf::FixupTarget::FrameNumber(reloc.target_index),
        };

        let relocation = Relocation {
            kind,
            encoding: RelocationEncoding::Generic,
            size,
            target,
            addend,
            implicit_addend: false,
            subtractor: None,
            flags: RelocationFlags::Omf {
                location: reloc.location,
                mode: if reloc.is_segment_relative {
                    omf::FixupMode::SegmentRelative
                } else {
                    omf::FixupMode::SelfRelative
                },
                frame,
                target: fixup_target,
            },
        };

        Some((reloc.offset as u64, relocation))
    }
}
