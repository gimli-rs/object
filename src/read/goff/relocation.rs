use alloc::borrow::Cow;
use alloc::fmt;
use core::slice;

use crate::goff;
use crate::read::{
    Bytes, ReadError, ReadRef, Relocation, RelocationEncoding, RelocationKind, RelocationTarget,
    Result, SymbolIndex,
};
use crate::{BigEndian as BE, U32, U64};

use super::{GoffFile, GoffSubsectionIndex, LogicalRecord};

/// An iterator for the relocations in a [`GoffSection`](super::GoffSection).
pub struct GoffRelocationIterator<'data, 'file, R = &'data [u8]>
where
    R: ReadRef<'data>,
{
    file: &'file GoffFile<'data, R>,
    offset: u32,
    relocations: slice::Iter<'file, goff::Relocation>,
    prs: slice::Iter<'file, GoffSubsectionIndex>,
}

impl<'data, 'file, R> GoffRelocationIterator<'data, 'file, R>
where
    R: ReadRef<'data>,
{
    pub(super) fn new(
        file: &'file GoffFile<'data, R>,
        ed: GoffSubsectionIndex,
        prs: &'file [GoffSubsectionIndex],
    ) -> Self {
        let mut iter = GoffRelocationIterator {
            file,
            offset: 0,
            relocations: [].iter(),
            prs: prs.iter(),
        };
        iter.set_subsection(ed);
        iter
    }

    fn set_subsection(&mut self, index: GoffSubsectionIndex) {
        let (offset, relocations) = self.file.sections.relocations(index);
        self.offset = offset;
        self.relocations = relocations.iter();
    }

    fn map_kind(
        &self,
        flags: &goff::RelocationFlags,
        subtractor: bool,
    ) -> (RelocationKind, RelocationEncoding) {
        use RelocationEncoding as E;
        use RelocationKind as K;

        let unknown = (K::Unknown, E::Unknown);
        // Can only represent addition or subtraction pairs and
        // fields that start on a byte boundary.
        if flags.action() != goff::RLD_ACT_ADD && !subtractor || flags.bit_offset() != 0 {
            return unknown;
        }
        match flags.reference_type() {
            goff::RLD_RT_ADDRESS => (K::Absolute, E::Generic),
            goff::RLD_RT_OFFSET => (K::SectionOffset, E::Generic),
            // The value is a halfword count.
            // TODO: does addend need adjusting for instructions size?
            goff::RLD_RT_RELATIVE_IMMEDIATE => (K::Relative, E::S390xDbl),
            _ => unknown,
        }
    }

    fn is_subtractor_pair(a: &goff::Relocation, b: &goff::Relocation) -> bool {
        let actions = (a.flags.action(), b.flags.action());
        (actions == (goff::RLD_ACT_ADD, goff::RLD_ACT_SUBTRACT)
            || actions == (goff::RLD_ACT_SUBTRACT, goff::RLD_ACT_ADD))
            && b.flags.fetch_store() == goff::RLD_FS_FETCH
            && a.offset == b.offset
            && a.flags.reference_type() == b.flags.reference_type()
            && a.flags.byte_length() == b.flags.byte_length()
            && a.flags.bit_length() == b.flags.bit_length()
            && a.flags.bit_offset() == b.flags.bit_offset()
    }
}

impl<'data, 'file, R> Iterator for GoffRelocationIterator<'data, 'file, R>
where
    R: ReadRef<'data>,
{
    type Item = (u64, Relocation);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let Some(goff_reloc) = self.relocations.next() else {
                let pr = self.prs.next()?;
                self.set_subsection(*pr);
                continue;
            };

            let mut target = SymbolIndex(goff_reloc.r_pointer as usize);
            let mut subtractor = None;
            if let Some(next) = self.relocations.as_slice().first() {
                if Self::is_subtractor_pair(goff_reloc, next) {
                    self.relocations.next();
                    if goff_reloc.flags.action() == goff::RLD_ACT_SUBTRACT {
                        subtractor = Some(target);
                        target = SymbolIndex(next.r_pointer as usize);
                    } else {
                        subtractor = Some(SymbolIndex(next.r_pointer as usize));
                    }
                }
            }

            let offset = u64::from(self.offset).wrapping_add(goff_reloc.offset);
            let (kind, encoding) = self.map_kind(&goff_reloc.flags, subtractor.is_some());
            let size = goff_reloc.flags.total_bit_width().unwrap_or(0);
            let implicit_addend = goff_reloc.flags.fetch_store() == goff::RLD_FS_FETCH;

            let relocation = Relocation {
                kind,
                encoding,
                size,
                target: RelocationTarget::Symbol(target),
                subtractor,
                addend: 0,
                implicit_addend,
                flags: crate::read::RelocationFlags::Goff {
                    flags: goff_reloc.flags,
                },
            };

            return Some((offset, relocation));
        }
    }
}

impl<'data, 'file, R> fmt::Debug for GoffRelocationIterator<'data, 'file, R>
where
    R: ReadRef<'data>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoffRelocationIterator")
            .finish_non_exhaustive()
    }
}

impl<'data> LogicalRecord<'data, goff::RelocationRecord> {
    /// Iterate over the relocations in the initial record and the continuation records.
    pub fn rld_items(&self) -> Result<RelocationIterator<'data>> {
        Ok(RelocationIterator {
            data: self.rld_data()?,
            offset: 0,
            r_pointer: None,
            p_pointer: None,
            p_offset: None,
        })
    }
}

/// An iterator over the relocations in a RLD record.
///
/// Returned by [`LogicalRecord::rld_items`].
#[derive(Debug)]
pub struct RelocationIterator<'data> {
    // TODO: this could avoid allocation
    data: Cow<'data, [u8]>,
    offset: usize,
    r_pointer: Option<u32>,
    p_pointer: Option<u32>,
    p_offset: Option<u64>,
}

impl<'data> RelocationIterator<'data> {
    /// Return the next relocation data item.
    pub fn next(&mut self) -> Result<Option<goff::Relocation>> {
        if self.offset >= self.data.len() {
            return Ok(None);
        }
        let result = self.parse().map(Some);
        if result.is_err() {
            self.offset = self.data.len();
        }
        result
    }

    fn parse(&mut self) -> Result<goff::Relocation> {
        let mut data = Bytes(&self.data[self.offset..]);
        let len = data.len();

        let flags = *data
            .read::<goff::RelocationFlags>()
            .read_error("Invalid GOFF relocation data item")?;
        data.skip(2)
            .read_error("Invalid GOFF relocation data item")?;

        // Parse R-pointer (conditionally)
        let r_pointer = if flags.is_same_r_id() {
            self.r_pointer
                .read_error("GOFF R-pointer compression without previous value")?
        } else {
            data.read::<U32<_>>()
                .read_error("Invalid GOFF relocation R-pointer")?
                .get(BE)
        };

        // Parse P-pointer (conditionally)
        let p_pointer = if flags.is_same_p_id() {
            self.p_pointer
                .read_error("GOFF P-pointer compression without previous value")?
        } else {
            data.read::<U32<_>>()
                .read_error("Invalid GOFF relocation P-pointer")?
                .get(BE)
        };

        // Parse Offset (conditionally)
        let p_offset = if flags.is_same_offset() {
            self.p_offset
                .read_error("GOFF offset compression without previous value")?
        } else if flags.is_offset64() {
            data.read::<U64<_>>()
                .read_error("Invalid GOFF relocation offset")?
                .get(BE)
        } else {
            u64::from(
                data.read::<U32<_>>()
                    .read_error("Invalid GOFF relocation offset")?
                    .get(BE),
            )
        };

        // Update previous values for next iteration
        self.r_pointer = Some(r_pointer);
        self.p_pointer = Some(p_pointer);
        self.p_offset = Some(p_offset);

        self.offset += len - data.len();

        // Create and store relocation
        Ok(goff::Relocation {
            flags,
            r_pointer,
            p_pointer,
            offset: p_offset,
        })
    }
}

impl<'data> Iterator for RelocationIterator<'data> {
    type Item = Result<goff::Relocation>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next().transpose()
    }
}
