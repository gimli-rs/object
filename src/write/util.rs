use std::vec::Vec;

use crate::pod::{bytes_of, bytes_of_slice, Pod};

/// Trait for writable buffer.
#[allow(clippy::len_without_is_empty)]
pub trait WritableBuffer {
    /// Returns position/offset for data to be written at.
    fn len(&self) -> usize;

    /// Reserves specified number of bytes in the buffer.
    fn reserve(&mut self, additional: usize) -> Result<(), ()>;

    /// Writes the specified value at the end of the buffer
    /// until the buffer has the specified length.
    fn resize(&mut self, new_len: usize, value: u8);

    /// Writes the specified slice of bytes at the end of the buffer.
    fn write_bytes(&mut self, val: &[u8]);

    /// Writes the specified `Pod` type at the end of the buffer.
    fn write_pod<T: Pod>(&mut self, val: &T)
    where
        Self: Sized,
    {
        self.write_bytes(bytes_of(val))
    }

    /// Writes the specified `Pod` slice at the end of the buffer.
    fn write_pod_slice<T: Pod>(&mut self, val: &[T])
    where
        Self: Sized,
    {
        self.write_bytes(bytes_of_slice(val))
    }
}

impl<'a> dyn WritableBuffer + 'a {
    /// Writes the specified `Pod` type at the end of the buffer.
    pub fn write<T: Pod>(&mut self, val: &T) {
        self.write_bytes(bytes_of(val))
    }

    /// Writes the specified `Pod` slice at the end of the buffer.
    pub fn write_slice<T: Pod>(&mut self, val: &[T]) {
        self.write_bytes(bytes_of_slice(val))
    }
}

impl WritableBuffer for Vec<u8> {
    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn reserve(&mut self, additional: usize) -> Result<(), ()> {
        self.reserve(additional);
        Ok(())
    }

    #[inline]
    fn resize(&mut self, new_len: usize, value: u8) {
        self.resize(new_len, value);
    }

    #[inline]
    fn write_bytes(&mut self, val: &[u8]) {
        self.extend_from_slice(val)
    }
}

/// A trait for mutable byte slices.
///
/// It provides convenience methods for `Pod` types.
pub(crate) trait BytesMut {
    fn write_at<T: Pod>(self, offset: usize, val: &T) -> Result<(), ()>;
}

impl<'a> BytesMut for &'a mut [u8] {
    #[inline]
    fn write_at<T: Pod>(self, offset: usize, val: &T) -> Result<(), ()> {
        let src = bytes_of(val);
        let dest = self.get_mut(offset..).ok_or(())?;
        let dest = dest.get_mut(..src.len()).ok_or(())?;
        dest.copy_from_slice(src);
        Ok(())
    }
}

pub(crate) fn align(offset: usize, size: usize) -> usize {
    (offset + (size - 1)) & !(size - 1)
}

#[allow(dead_code)]
pub(crate) fn align_u64(offset: u64, size: u64) -> u64 {
    (offset + (size - 1)) & !(size - 1)
}

pub(crate) fn write_align(buffer: &mut dyn WritableBuffer, size: usize) {
    let new_len = align(buffer.len(), size);
    buffer.resize(new_len, 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_mut() {
        let data = vec![0x01, 0x23, 0x45, 0x67];

        let mut bytes = data.clone();
        bytes.extend_from_slice(bytes_of(&u16::to_be(0x89ab)));
        assert_eq!(bytes, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab]);

        let mut bytes = data.clone();
        assert_eq!(bytes.write_at(0, &u16::to_be(0x89ab)), Ok(()));
        assert_eq!(bytes, [0x89, 0xab, 0x45, 0x67]);

        let mut bytes = data.clone();
        assert_eq!(bytes.write_at(2, &u16::to_be(0x89ab)), Ok(()));
        assert_eq!(bytes, [0x01, 0x23, 0x89, 0xab]);

        assert_eq!(bytes.write_at(3, &u16::to_be(0x89ab)), Err(()));
        assert_eq!(bytes.write_at(4, &u16::to_be(0x89ab)), Err(()));
        assert_eq!(vec![].write_at(0, &u32::to_be(0x89ab)), Err(()));
    }
}
