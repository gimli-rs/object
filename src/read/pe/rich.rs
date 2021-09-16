//! PE rich header handling

use alloc::vec::Vec;

use crate::{pe, ReadRef, LittleEndian as LE, U32};

/// Extracted infos about a possible Rich Header
#[derive(Debug, Clone, Copy)]
pub struct RichHeaderInfos<'data> {
    /// The offset at which the rich header starts
    pub start: usize,
    /// The length (in bytes) of the rich header
    pub length: usize,
    /// The data used to mask the rich header.
    /// Unless the file has been tampered with, it should be equal to a checksum of the file header
    pub mask: u32,
    masked_entries: &'data [pe::MaskedRichHeaderEntry],
}

/// A PE rich header entry after it has been unmasked.
///
/// See [`crate::pe::MaskedRichHeaderEntry`]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RichHeaderEntry {
    /// ID of the component
    pub comp_id: u32,
    /// Number of times this component has been used when building this PE
    pub count: u32,
}

impl<'data> RichHeaderInfos<'data> {
    /// Try to detect a rich header in the current PE file, and locate its [`MaskedRichHeaderEntry`s]
    pub fn parse<R: ReadRef<'data>>(data: R, nt_header_offset: u64) -> Option<Self> {
        const RICH_SEQUENCE: &[u8] = &[0x52, 0x69, 0x63, 0x68]; // "Rich"
        const CLEARTEXT_MARKER: u32 = 0x536e6144; // little-endian "DanS"

        // Locate the rich header, if any
        // It ends with the ASCII 'Rich' string, before the NT header
        // It starts at the start marker (a masked ASCII 'DanS' string)
        let all_headers = data.read_bytes_at(0, nt_header_offset).ok()?;

        let dos_and_rich_header =
            read_bytes_until_sequence(all_headers, RICH_SEQUENCE, nt_header_offset as usize)
                .ok()?;

        let xor_key = data
            .read_at::<U32<LE>>(dos_and_rich_header.len() as u64 + 4)
            .ok()?;

        let marker = U32::new(LE, CLEARTEXT_MARKER ^ xor_key.get(LE));
        let mut start_sequence: Vec<u8> = Vec::with_capacity(16);
        start_sequence.extend_from_slice(crate::pod::bytes_of(&marker));
        start_sequence.extend_from_slice(crate::pod::bytes_of(xor_key));
        start_sequence.extend_from_slice(crate::pod::bytes_of(xor_key));
        start_sequence.extend_from_slice(crate::pod::bytes_of(xor_key));

        let rich_header_start =
            match read_bytes_until_sequence(all_headers, &start_sequence, nt_header_offset as usize) {
                Err(()) => return None,
                Ok(slice) => slice.len(),
            };
        let rh_len = dos_and_rich_header.len() - rich_header_start;

        // Extract the contents of the rich header
        let items_start = rich_header_start + 16;
        let items_len = rh_len - 16;
        let item_count = items_len / std::mem::size_of::<pe::MaskedRichHeaderEntry>();
        let items =
            match data.read_slice_at::<pe::MaskedRichHeaderEntry>(items_start as u64, item_count) {
                Err(()) => return None,
                Ok(items) => items,
            };
        Some(RichHeaderInfos {
            start: rich_header_start,
            length: rh_len,
            mask: xor_key.get(LE),
            masked_entries: items,
        })
    }

    /// Creates a new vector of unmasked entries
    pub fn unmasked_entries(&self) -> Vec<RichHeaderEntry> {
        self.masked_entries
            .iter()
            .map(|entry| RichHeaderEntry {
                comp_id: entry.masked_comp_id.get(LE) ^ self.mask,
                count: entry.masked_count.get(LE) ^ self.mask,
            })
            .collect()
    }
}

fn read_bytes_until_sequence<'a>(
    data: &'a [u8],
    needle: &[u8],
    max_end: usize,
) -> Result<&'a [u8], ()> {
    let sub: &[u8] = data.get(0..max_end).ok_or(())?;

    sub.windows(needle.len())
        .position(|window| window == needle)
        .ok_or(())
        .and_then(|end| data.read_bytes_at(0, end as u64))
}
