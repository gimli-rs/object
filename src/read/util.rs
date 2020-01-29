#[inline]
pub(crate) fn align(offset: usize, size: usize) -> usize {
    (offset + (size - 1)) & !(size - 1)
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct StringTable<'data> {
    pub data: &'data [u8],
}

impl<'data> StringTable<'data> {
    pub fn get(&self, offset: u32) -> Option<&'data [u8]> {
        self.data
            .get(offset as usize..)
            .and_then(|data| data.iter().position(|&x| x == 0).map(|end| &data[..end]))
    }
}
