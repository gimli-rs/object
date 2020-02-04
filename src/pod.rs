//! Tools for converting file format structures to and from bytes.
//!
//! This module should be replaced once rust provides safe transmutes.

// This module provides functions for both read and write features.
#![cfg_attr(not(all(feature = "read_core", feature = "write_core")), allow(dead_code))]

use alloc::vec::Vec;
use core::{fmt, mem, slice};

/// A trait for types that can safely be converted from and to byte slices.
///
/// A type that is `Pod` must:
/// - be `#[repr(C)]` or `#[repr(transparent)]`
/// - have no invalid byte values
/// - have no padding
pub unsafe trait Pod: Copy + 'static {}

#[inline]
pub(crate) fn from_bytes<T: Pod>(data: &[u8]) -> Option<(&T, &[u8])> {
    let ptr = data.as_ptr();
    if (ptr as usize) % mem::align_of::<T>() != 0 {
        return None;
    }
    let size = mem::size_of::<T>();
    let tail = data.get(size..)?;
    // Safety:
    // The alignment and size are checked by this function.
    // The Pod trait ensures the type is valid to cast from bytes.
    let val = unsafe { &*ptr.cast() };
    Some((val, tail))
}

#[inline]
pub(crate) fn slice_from_bytes<T: Pod>(data: &[u8], count: usize) -> Option<(&[T], &[u8])> {
    let ptr = data.as_ptr();
    if (ptr as usize) % mem::align_of::<T>() != 0 {
        return None;
    }
    let size = count.checked_mul(mem::size_of::<T>())?;
    let tail = data.get(size..)?;
    // Safety:
    // The alignment and size are checked by this function.
    // The Pod trait ensures the type is valid to cast from bytes.
    let slice = unsafe { slice::from_raw_parts(ptr.cast(), count) };
    Some((slice, tail))
}

#[inline]
pub(crate) fn bytes_of<T: Pod>(val: &T) -> &[u8] {
    let size = mem::size_of::<T>();
    // Safety:
    // Any alignment is allowed.
    // The size is determined in this function.
    // The Pod trait ensures the type is valid to cast to bytes.
    unsafe { slice::from_raw_parts(slice::from_ref(val).as_ptr().cast(), size) }
}

/// A newtype for byte slices.
///
/// It has these important features:
/// - no methods that can panic, such as `Index`
/// - convenience methods for `Pod` types
/// - a useful `Debug` implementation
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct Bytes<'data>(pub &'data [u8]);

impl<'data> fmt::Debug for Bytes<'data> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_list_bytes(self.0, fmt)
    }
}

impl<'data> Bytes<'data> {
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn skip(&mut self, offset: usize) -> Option<()> {
        match self.0.get(offset..) {
            Some(tail) => {
                self.0 = tail;
                Some(())
            }
            None => {
                self.0 = &[];
                None
            }
        }
    }

    #[inline]
    pub fn read_bytes(&mut self, count: usize) -> Option<Bytes<'data>> {
        match (self.0.get(..count), self.0.get(count..)) {
            (Some(head), Some(tail)) => {
                self.0 = tail;
                Some(Bytes(head))
            }
            _ => {
                self.0 = &[];
                None
            }
        }
    }

    #[inline]
    pub fn read_bytes_at(mut self, offset: usize, count: usize) -> Option<Bytes<'data>> {
        self.skip(offset)?;
        self.read_bytes(count)
    }

    #[inline]
    pub fn read<T: Pod>(&mut self) -> Option<&'data T> {
        match from_bytes(self.0) {
            Some((value, tail)) => {
                self.0 = tail;
                Some(value)
            }
            None => {
                self.0 = &[];
                None
            }
        }
    }

    #[inline]
    pub fn read_at<T: Pod>(mut self, offset: usize) -> Option<&'data T> {
        self.skip(offset)?;
        self.read()
    }

    #[inline]
    pub fn read_slice<T: Pod>(&mut self, count: usize) -> Option<&'data [T]> {
        match slice_from_bytes(self.0, count) {
            Some((value, tail)) => {
                self.0 = tail;
                Some(value)
            }
            None => {
                self.0 = &[];
                None
            }
        }
    }

    #[inline]
    pub fn read_slice_at<T: Pod>(mut self, offset: usize, count: usize) -> Option<&'data [T]> {
        self.skip(offset)?;
        self.read_slice(count)
    }

    /// Read a null terminated string.
    ///
    /// Does not assume any encoding.
    /// Reads past the null byte, but doesn't return it.
    #[inline]
    pub fn read_string(&mut self) -> Option<&'data [u8]> {
        match self.0.iter().position(|&x| x == 0) {
            Some(null) => {
                // These will never fail.
                let bytes = self.read_bytes(null)?;
                self.skip(1)?;
                Some(bytes.0)
            }
            None => {
                self.0 = &[];
                None
            }
        }
    }

    /// Read a null terminated string at an offset.
    ///
    /// Does not assume any encoding. Does not return the null byte.
    #[inline]
    pub fn read_string_at(mut self, offset: usize) -> Option<&'data [u8]> {
        self.skip(offset)?;
        self.read_string()
    }
}

/// A newtype for byte vectors.
///
/// It provides convenience methods for `Pod` types.
// TODO: should this be an extension trait for `Vec<u8>` instead?
#[derive(Default, Clone, PartialEq, Eq)]
pub(crate) struct BytesMut(pub Vec<u8>);

impl fmt::Debug for BytesMut {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_list_bytes(&self.0, fmt)
    }
}

impl BytesMut {
    #[inline]
    pub fn new() -> Self {
        BytesMut(Vec::new())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    pub fn resize(&mut self, new_len: usize, value: u8) {
        self.0.resize(new_len, value);
    }

    #[inline]
    pub fn write<T: Pod>(&mut self, val: &T) {
        self.0.extend_from_slice(bytes_of(val))
    }

    #[inline]
    pub fn write_at<T: Pod>(&mut self, offset: usize, val: &T) -> Result<(), ()> {
        let src = bytes_of(val);
        let dest = self.0.get_mut(offset..).ok_or(())?;
        let dest = dest.get_mut(..src.len()).ok_or(())?;
        dest.copy_from_slice(src);
        Ok(())
    }

    #[inline]
    pub fn write_bytes(&mut self, bytes: &BytesMut) {
        self.0.extend_from_slice(&bytes.0)
    }

    #[inline]
    pub fn extend(&mut self, val: &[u8]) {
        self.0.extend_from_slice(val)
    }
}

// Only for Debug impl of `Bytes/BytesMut`.
fn debug_list_bytes(bytes: &[u8], fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut list = fmt.debug_list();
    list.entries(bytes.iter().take(8).copied().map(DebugByte));
    if bytes.len() > 8 {
        list.entry(&DebugLen(bytes.len()));
    }
    list.finish()
}

struct DebugByte(u8);

impl fmt::Debug for DebugByte {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "0x{:02x}", self.0)
    }
}

struct DebugLen(usize);

impl fmt::Debug for DebugLen {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "...; {}", self.0)
    }
}

macro_rules! unsafe_impl_pod {
    ($($struct_name:ident),+ $(,)?) => {
        $(
            unsafe impl Pod for $struct_name { }
        )+
    }
}

unsafe_impl_pod!(u8, u16, u32, u64);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single() {
        let x = u32::to_be(0x0123_4567);
        let bytes = bytes_of(&x);
        assert_eq!(bytes, [0x01, 0x23, 0x45, 0x67]);

        let x16 = [u16::to_be(0x0123), u16::to_be(0x4567)];

        let (y, tail) = from_bytes::<u32>(bytes).unwrap();
        assert_eq!(*y, x);
        assert_eq!(tail, &[]);

        let (y, tail) = from_bytes::<u16>(bytes).unwrap();
        assert_eq!(*y, x16[0]);
        assert_eq!(tail, &bytes[2..]);

        let (y, tail) = from_bytes::<u16>(&bytes[2..]).unwrap();
        assert_eq!(*y, x16[1]);
        assert_eq!(tail, &[]);

        assert_eq!(from_bytes::<u16>(&bytes[1..]), None);
        assert_eq!(from_bytes::<u16>(&bytes[3..]), None);
        assert_eq!(from_bytes::<u16>(&bytes[4..]), None);
    }

    #[test]
    fn slice() {
        let x = u64::to_be(0x0123_4567_89ab_cdef);
        let bytes = bytes_of(&x);
        assert_eq!(bytes, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);

        let x16 = [
            u16::to_be(0x0123),
            u16::to_be(0x4567),
            u16::to_be(0x89ab),
            u16::to_be(0xcdef),
        ];

        let (y, tail) = slice_from_bytes::<u16>(&bytes, 4).unwrap();
        assert_eq!(y, x16);
        assert_eq!(tail, &[]);

        let (y, tail) = slice_from_bytes::<u16>(&bytes[2..], 2).unwrap();
        assert_eq!(y, &x16[1..3]);
        assert_eq!(tail, &bytes[6..]);

        assert_eq!(slice_from_bytes::<u16>(&bytes, 5), None);
        assert_eq!(slice_from_bytes::<u16>(&bytes[2..], 4), None);
        assert_eq!(slice_from_bytes::<u16>(&bytes[1..], 2), None);
    }

    #[test]
    fn bytes() {
        let x = u32::to_be(0x0123_4567);
        let data = Bytes(bytes_of(&x));

        let mut bytes = data;
        assert_eq!(bytes.skip(0), Some(()));
        assert_eq!(bytes, data);

        let mut bytes = data;
        assert_eq!(bytes.skip(4), Some(()));
        assert_eq!(bytes, Bytes(&[]));

        let mut bytes = data;
        assert_eq!(bytes.skip(5), None);
        assert_eq!(bytes, Bytes(&[]));

        let mut bytes = data;
        assert_eq!(bytes.read_bytes(0), Some(Bytes(&[])));
        assert_eq!(bytes, data);

        let mut bytes = data;
        assert_eq!(bytes.read_bytes(4), Some(data));
        assert_eq!(bytes, Bytes(&[]));

        let mut bytes = data;
        assert_eq!(bytes.read_bytes(5), None);
        assert_eq!(bytes, Bytes(&[]));

        assert_eq!(data.read_bytes_at(0, 0), Some(Bytes(&[])));
        assert_eq!(data.read_bytes_at(4, 0), Some(Bytes(&[])));
        assert_eq!(data.read_bytes_at(0, 4), Some(data));
        assert_eq!(data.read_bytes_at(1, 4), None);

        let mut bytes = data;
        assert_eq!(bytes.read::<u16>(), Some(&u16::to_be(0x0123)));
        assert_eq!(bytes, Bytes(&[0x45, 0x67]));
        assert_eq!(data.read_at::<u16>(2), Some(&u16::to_be(0x4567)));
        assert_eq!(data.read_at::<u16>(3), None);
        assert_eq!(data.read_at::<u16>(4), None);

        let mut bytes = data;
        assert_eq!(bytes.read::<u32>(), Some(&x));
        assert_eq!(bytes, Bytes(&[]));

        let mut bytes = data;
        assert_eq!(bytes.read::<u64>(), None);
        assert_eq!(bytes, Bytes(&[]));

        let mut bytes = data;
        assert_eq!(bytes.read_slice::<u8>(0), Some(&[][..]));
        assert_eq!(bytes, data);

        let mut bytes = data;
        assert_eq!(bytes.read_slice::<u8>(4), Some(data.0));
        assert_eq!(bytes, Bytes(&[]));

        let mut bytes = data;
        assert_eq!(bytes.read_slice::<u8>(5), None);
        assert_eq!(bytes, Bytes(&[]));

        assert_eq!(data.read_slice_at::<u8>(0, 0), Some(&[][..]));
        assert_eq!(data.read_slice_at::<u8>(4, 0), Some(&[][..]));
        assert_eq!(data.read_slice_at::<u8>(0, 4), Some(data.0));
        assert_eq!(data.read_slice_at::<u8>(1, 4), None);

        let data = Bytes(&[0x01, 0x02, 0x00, 0x04]);

        let mut bytes = data;
        assert_eq!(bytes.read_string(), Some(&data.0[..2]));
        assert_eq!(bytes.0, &data.0[3..]);

        let mut bytes = data;
        bytes.skip(3);
        assert_eq!(bytes.read_string(), None);
        assert_eq!(bytes.0, &[]);

        assert_eq!(data.read_string_at(0), Some(&data.0[..2]));
        assert_eq!(data.read_string_at(1), Some(&data.0[1..2]));
        assert_eq!(data.read_string_at(2), Some(&[][..]));
        assert_eq!(data.read_string_at(3), None);
    }

    #[test]
    fn bytes_mut() {
        let data = BytesMut(vec![0x01, 0x23, 0x45, 0x67]);

        let mut bytes = data.clone();
        bytes.write(&u16::to_be(0x89ab));
        assert_eq!(bytes.0, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab]);

        let mut bytes = data.clone();
        assert_eq!(bytes.write_at(0, &u16::to_be(0x89ab)), Ok(()));
        assert_eq!(bytes.0, [0x89, 0xab, 0x45, 0x67]);

        let mut bytes = data.clone();
        assert_eq!(bytes.write_at(2, &u16::to_be(0x89ab)), Ok(()));
        assert_eq!(bytes.0, [0x01, 0x23, 0x89, 0xab]);

        assert_eq!(bytes.write_at(3, &u16::to_be(0x89ab)), Err(()));
        assert_eq!(bytes.write_at(4, &u16::to_be(0x89ab)), Err(()));
        assert_eq!(
            BytesMut::default().write_at(0, &u32::to_be(0x89ab)),
            Err(())
        );
    }

    #[test]
    fn bytes_debug() {
        assert_eq!(format!("{:?}", Bytes(&[])), "[]");
        assert_eq!(format!("{:?}", Bytes(&[0x01])), "[0x01]");
        assert_eq!(
            format!(
                "{:?}",
                Bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
            ),
            "[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]"
        );
        assert_eq!(
            format!(
                "{:?}",
                Bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09])
            ),
            "[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, ...; 9]"
        );

        assert_eq!(format!("{:?}", BytesMut(vec![])), "[]");
        assert_eq!(
            format!(
                "{:?}",
                BytesMut(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09])
            ),
            "[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, ...; 9]"
        );
    }
}
