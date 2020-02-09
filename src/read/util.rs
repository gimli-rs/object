use crate::pod::Bytes;

#[inline]
pub(crate) fn align(offset: usize, size: usize) -> usize {
    (offset + (size - 1)) & !(size - 1)
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct StringTable<'data> {
    pub data: Bytes<'data>,
}

impl<'data> StringTable<'data> {
    pub fn get(&self, offset: u32) -> Result<&'data [u8], ()> {
        self.data.read_string_at(offset as usize)
    }
}
