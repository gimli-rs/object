//! Tools for converting file format structures to and from bytes.
//!
//! This module should be replaced once rust provides safe transmutes.

// This module provides functions for both read and write features.
#![cfg_attr(not(all(feature = "read", feature = "write")), allow(dead_code))]

use core::{mem, slice};

/// A trait for types that can safely be converted from and to byte slices.
///
/// A type that is `Pod` must:
/// - be `#[repr(C)]` or `#[repr(transparent)]`
/// - have no invalid byte values
/// - have no padding
pub unsafe trait Pod: Copy + 'static {}

#[inline]
pub(crate) fn from_bytes<T: Pod>(data: &[u8]) -> Option<(&T, &[u8])> {
    let size = mem::size_of::<T>();
    let head = data.get(..size)?;
    let tail = data.get(size..)?;
    if (head.as_ptr() as usize) % mem::align_of::<T>() != 0 {
        return None;
    }
    // Safety:
    // The alignment and size are checked by this function.
    // The Pod trait ensures the type is valid to cast from bytes.
    let val = unsafe { &*head.as_ptr().cast() };
    Some((val, tail))
}

#[inline]
pub(crate) fn slice_from_bytes<T: Pod>(
    data: &[u8],
    offset: usize,
    count: usize,
) -> Option<(&[T], &[u8])> {
    let size = count.checked_mul(mem::size_of::<T>())?;
    let data = data.get(offset..)?;
    let head = data.get(..size)?;
    let tail = data.get(size..)?;
    if (head.as_ptr() as usize) % mem::align_of::<T>() != 0 {
        return None;
    }
    // Safety:
    // The alignment and size are checked by this function.
    // The Pod trait ensures the type is valid to cast from bytes.
    let slice = unsafe { slice::from_raw_parts(head.as_ptr().cast(), count) };
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

        let (y, tail) = slice_from_bytes::<u16>(bytes, 0, 4).unwrap();
        assert_eq!(y, x16);
        assert_eq!(tail, &[]);

        let (y, tail) = slice_from_bytes::<u16>(bytes, 2, 2).unwrap();
        assert_eq!(y, &x16[1..3]);
        assert_eq!(tail, &bytes[6..]);

        assert_eq!(slice_from_bytes::<u16>(bytes, 0, 5), None);
        assert_eq!(slice_from_bytes::<u16>(bytes, 2, 4), None);
        assert_eq!(slice_from_bytes::<u16>(bytes, 1, 2), None);
    }
}
