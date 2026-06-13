use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::{io, mem};

use crate::pod::{Pod, bytes_of, bytes_of_slice};

/// Trait for writable buffer.
#[allow(clippy::len_without_is_empty)]
pub trait WritableBuffer {
    /// Returns the next offset that data will be written at.
    ///
    /// This is called often, so implementors should track this value
    /// themselves if determining the length is an expensive operation.
    fn len(&self) -> u64;

    /// Reserves specified number of bytes in the buffer.
    ///
    /// If called, this will be called exactly once before any writes, and the given size
    /// is the exact total number of bytes that will be written. Writers that target
    /// [`GrowableBuffer`] may skip this call, but it is required for other writers.
    fn reserve(&mut self, size: u64) -> Result<(), ()>;

    /// Writes zero bytes at the end of the buffer until the buffer
    /// has the specified length.
    fn resize(&mut self, new_len: u64);

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

// `write_pod`/`write_pod_slice` are generic, so they require `Self: Sized`
// to keep the trait object-safe. That bound also excludes them from
// `&mut dyn WritableBuffer` call sites, so provide them again here.
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

/// A [`WritableBuffer`] that can grow its capacity while writing.
///
/// [`WritableBuffer::reserve`] may still be called but this is not required.
/// Writes will automatically increase the capacity of the buffer.
pub trait GrowableBuffer: WritableBuffer {
    /// Upcast to a [`WritableBuffer`] trait object.
    //
    // Manual upcast because trait upcasting coercion requires MSRV 1.86.
    fn as_writable(&mut self) -> &mut dyn WritableBuffer;
}

impl<'a> dyn GrowableBuffer + 'a {
    /// Writes the specified `Pod` type at the end of the buffer.
    pub fn write<T: Pod>(&mut self, val: &T) {
        self.write_bytes(bytes_of(val))
    }

    /// Writes the specified `Pod` slice at the end of the buffer.
    pub fn write_slice<T: Pod>(&mut self, val: &[T]) {
        self.write_bytes(bytes_of_slice(val))
    }
}

impl GrowableBuffer for Vec<u8> {
    fn as_writable(&mut self) -> &mut dyn WritableBuffer {
        self
    }
}

impl WritableBuffer for Vec<u8> {
    #[inline]
    fn len(&self) -> u64 {
        self.len() as u64
    }

    #[inline]
    fn reserve(&mut self, size: u64) -> Result<(), ()> {
        debug_assert!(self.is_empty());
        let size = usize::try_from(size).map_err(|_| ())?;
        self.reserve(size);
        Ok(())
    }

    #[inline]
    fn resize(&mut self, new_len: u64) {
        debug_assert!(new_len as usize >= self.len());
        self.resize(new_len as usize, 0);
    }

    #[inline]
    fn write_bytes(&mut self, val: &[u8]) {
        self.extend_from_slice(val)
    }
}

/// A [`WritableBuffer`] that streams data to a [`Write`](std::io::Write) implementation.
///
/// [`Self::result`] must be called to determine if an I/O error occurred during writing.
/// Alternatively, [`Self::flush`] will both check for errors and flush.
///
/// It is advisable to use a buffered writer like [`BufWriter`](std::io::BufWriter)
/// instead of an unbuffered writer like [`File`](std::fs::File).
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct StreamingBuffer<W> {
    writer: W,
    len: u64,
    result: Result<(), io::Error>,
}

#[cfg(feature = "std")]
impl<W> StreamingBuffer<W> {
    /// Create a new `StreamingBuffer` backed by the given writer.
    pub fn new(writer: W) -> Self {
        StreamingBuffer {
            writer,
            len: 0,
            result: Ok(()),
        }
    }

    /// Unwraps this [`StreamingBuffer`] giving back the original writer.
    pub fn into_inner(self) -> W {
        self.writer
    }

    /// Returns any error that occurred during writing.
    pub fn result(&mut self) -> Result<(), io::Error> {
        mem::replace(&mut self.result, Ok(()))
    }
}

#[cfg(feature = "std")]
impl<W: io::Write> StreamingBuffer<W> {
    /// Flushes after first checking if any error previously occurred during writing.
    pub fn flush(&mut self) -> Result<(), io::Error> {
        self.result()?;
        self.writer.flush()
    }
}

#[cfg(feature = "std")]
impl<W: io::Write> GrowableBuffer for StreamingBuffer<W> {
    fn as_writable(&mut self) -> &mut dyn WritableBuffer {
        self
    }
}

#[cfg(feature = "std")]
impl<W: io::Write> WritableBuffer for StreamingBuffer<W> {
    #[inline]
    fn len(&self) -> u64 {
        self.len
    }

    #[inline]
    fn reserve(&mut self, _size: u64) -> Result<(), ()> {
        Ok(())
    }

    #[inline]
    fn resize(&mut self, new_len: u64) {
        debug_assert!(self.len <= new_len);
        while self.len < new_len {
            let write_amt = (new_len - self.len).min(1024) as usize;
            self.write_bytes(&[0; 1024][..write_amt]);
        }
    }

    #[inline]
    fn write_bytes(&mut self, val: &[u8]) {
        if self.result.is_ok() {
            self.result = self.writer.write_all(val);
        }
        // Callers depend on `len` being equal to the total requested writes,
        // even if those writes failed.
        self.len += val.len() as u64;
    }
}

/// Write an unsigned number using the LEB128 encoding to a buffer.
///
/// Returns the number of bytes written.
#[allow(dead_code)]
pub(crate) fn write_uleb128(buf: &mut Vec<u8>, mut val: u64) -> usize {
    let mut len = 0;
    loop {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;
        let done = val == 0;
        if !done {
            byte |= 0x80;
        }

        buf.push(byte);
        len += 1;

        if done {
            return len;
        }
    }
}

/// Write a signed number using the LEB128 encoding to a buffer.
///
/// Returns the number of bytes written.
#[allow(dead_code)]
pub(crate) fn write_sleb128(buf: &mut Vec<u8>, mut val: i64) -> usize {
    let mut len = 0;
    loop {
        let mut byte = val as u8;
        // Keep the sign bit for testing
        val >>= 6;
        let done = val == 0 || val == -1;
        if done {
            byte &= !0x80;
        } else {
            // Remove the sign bit
            val >>= 1;
            byte |= 0x80;
        }

        buf.push(byte);
        len += 1;

        if done {
            return len;
        }
    }
}

#[allow(dead_code)]
pub(crate) fn align_u32(offset: u32, size: u32) -> u32 {
    (offset + (size - 1)) & !(size - 1)
}

#[allow(dead_code)]
pub(crate) fn align(offset: u64, size: u64) -> u64 {
    (offset + (size - 1)) & !(size - 1)
}

pub(crate) fn write_align<W: WritableBuffer + ?Sized>(buffer: &mut W, size: u64) {
    let new_len = align(buffer.len(), size);
    buffer.resize(new_len);
}

#[allow(dead_code)]
pub(crate) fn write_pod<T: Pod, W: WritableBuffer + ?Sized>(buffer: &mut W, val: &T) {
    buffer.write_bytes(bytes_of(val))
}

#[allow(dead_code)]
pub(crate) fn write_pod_slice<T: Pod, W: WritableBuffer + ?Sized>(buffer: &mut W, val: &[T]) {
    buffer.write_bytes(bytes_of_slice(val))
}
