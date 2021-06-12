use core::{convert::TryInto, marker::PhantomData};

use crate::ReadRef;

#[allow(dead_code)]
#[inline]
pub(crate) fn align(offset: usize, size: usize) -> usize {
    (offset + (size - 1)) & !(size - 1)
}

#[allow(dead_code)]
pub(crate) fn data_range(
    data: &[u8],
    data_address: u64,
    range_address: u64,
    size: u64,
) -> Option<&[u8]> {
    let offset = range_address.checked_sub(data_address)?;
    data.get(offset.try_into().ok()?..)?
        .get(..size.try_into().ok()?)
}

/// A table of zero-terminated strings.
///
/// This is used for most file formats.
#[derive(Debug, Clone, Copy)]
pub struct StringTable<'data, R = &'data [u8]>
where
    R: ReadRef<'data>,
{
    data: Option<R>,
    start: u64,
    end: u64,
    marker: PhantomData<&'data ()>,
}

impl<'data, R: ReadRef<'data>> StringTable<'data, R> {
    /// Interpret the given data as a string table.
    pub fn new(data: R, start: u64, end: u64) -> Self {
        StringTable {
            data: Some(data),
            start,
            end,
            marker: PhantomData,
        }
    }

    /// Return the string at the given offset.
    pub fn get(&self, offset: u32) -> Result<&'data [u8], ()> {
        match self.data {
            Some(data) => {
                let r_start = self.start.checked_add(offset.into()).ok_or(())?;
                data.read_bytes_at_until(r_start..self.end, 0)
            }
            None => Err(()),
        }
    }
}

impl<'data, R: ReadRef<'data>> Default for StringTable<'data, R> {
    fn default() -> Self {
        StringTable {
            data: None,
            start: 0,
            end: 0,
            marker: PhantomData,
        }
    }
}
