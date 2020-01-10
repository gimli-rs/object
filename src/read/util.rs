use bytemuck;
use std::mem;

pub(crate) fn align(offset: usize, size: usize) -> usize {
    (offset + (size - 1)) & !(size - 1)
}

pub(crate) fn try_from_bytes_prefix<T: bytemuck::Pod>(data: &[u8]) -> Option<(&T, &[u8])> {
    let size = mem::size_of::<T>();
    let prefix = bytemuck::try_from_bytes(data.get(..size)?).ok()?;
    let rest = data.get(size..)?;
    Some((prefix, rest))
}

pub(crate) fn try_cast_slice_count<T: bytemuck::Pod>(
    data: &[u8],
    offset: usize,
    count: usize,
) -> Option<&[T]> {
    let size = count.checked_mul(mem::size_of::<T>())?;
    bytemuck::try_cast_slice(data.get(offset..)?.get(..size)?).ok()
}
