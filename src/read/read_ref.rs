use crate::pod::{from_bytes, slice_from_bytes, Pod};
use alloc::vec::Vec;
use core::mem;

/// TODO
pub trait ReadRef<'data>: 'data + Clone + Copy {
    /// TODO
    fn len(self) -> Result<usize, ()>;

    /// TODO
    fn read_bytes_at(self, offset: usize, size: usize) -> Result<&'data [u8], ()>;

    /// TODO
    fn read_bytes(self, offset: &mut usize, size: usize) -> Result<&'data [u8], ()> {
        let bytes = self.read_bytes_at(*offset, size)?;
        *offset = offset.wrapping_add(size);
        Ok(bytes)
    }

    /// TODO
    fn read<T: Pod>(self, offset: &mut usize) -> Result<&'data T, ()> {
        let size = mem::size_of::<T>();
        let bytes = self.read_bytes(offset, size)?;
        let (t, _) = from_bytes(bytes)?;
        Ok(t)
    }

    /// TODO
    fn read_at<T: Pod>(self, mut offset: usize) -> Result<&'data T, ()> {
        self.read(&mut offset)
    }

    /// TODO
    fn read_slice<T: Pod>(self, offset: &mut usize, count: usize) -> Result<&'data [T], ()> {
        let size = count.checked_mul(mem::size_of::<T>()).ok_or(())?;
        let bytes = self.read_bytes(offset, size)?;
        let (t, _) = slice_from_bytes(bytes, count)?;
        Ok(t)
    }

    /// TODO
    fn read_slice_at<T: Pod>(self, mut offset: usize, count: usize) -> Result<&'data [T], ()> {
        self.read_slice(&mut offset, count)
    }
}

/// TODO
impl<'data> ReadRef<'data> for &'data [u8] {
    fn len(self) -> Result<usize, ()> {
        Ok(self.len())
    }

    fn read_bytes_at(self, offset: usize, size: usize) -> Result<&'data [u8], ()> {
        self.get(offset..).ok_or(())?.get(..size).ok_or(())
    }
}

/// TODO
impl<'data> ReadRef<'data> for &'data Vec<u8> {
    fn len(self) -> Result<usize, ()> {
        Ok(self.len())
    }

    fn read_bytes_at(self, offset: usize, size: usize) -> Result<&'data [u8], ()> {
        self.get(offset..).ok_or(())?.get(..size).ok_or(())
    }
}

/// TODO
#[cfg(feature = "std")]
mod cache {
    use super::*;
    use std::boxed::Box;
    use std::cell::RefCell;
    use std::collections::hash_map::Entry;
    use std::collections::HashMap;
    use std::convert::TryInto;
    use std::io::{Read, Seek, SeekFrom};

    /// TODO
    #[derive(Debug)]
    pub struct ReadCache<R: Read + Seek> {
        cache: RefCell<ReadCacheInternal<R>>,
    }

    #[derive(Debug)]
    struct ReadCacheInternal<R: Read + Seek> {
        read: R,
        bufs: HashMap<(usize, usize), Box<[u8]>>,
    }

    /// TODO
    impl<R: Read + Seek> ReadCache<R> {
        /// TODO
        pub fn new(read: R) -> Self {
            ReadCache {
                cache: RefCell::new(ReadCacheInternal {
                    read,
                    bufs: HashMap::new(),
                }),
            }
        }

        /// TODO
        pub fn range<'data>(&'data self, offset: usize, size: usize) -> ReadCacheRange<'data, R> {
            ReadCacheRange {
                r: self,
                offset,
                size,
            }
        }
    }

    impl<'data, R: Read + Seek> ReadRef<'data> for &'data ReadCache<R> {
        fn len(self) -> Result<usize, ()> {
            let cache = &mut *self.cache.borrow_mut();
            cache
                .read
                .seek(SeekFrom::End(0))
                .map_err(|_| ())?
                .try_into()
                .map_err(|_| ())
        }

        fn read_bytes_at(self, offset: usize, size: usize) -> Result<&'data [u8], ()> {
            if size == 0 {
                return Ok(&[]);
            }
            let cache = &mut *self.cache.borrow_mut();
            let buf = match cache.bufs.entry((offset, size)) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    cache
                        .read
                        .seek(SeekFrom::Start(offset as u64))
                        .map_err(|_| ())?;
                    let mut bytes = vec![0; size].into_boxed_slice();
                    cache.read.read_exact(&mut bytes).map_err(|_| ())?;
                    entry.insert(bytes)
                }
            };
            // Extend the lifetime to that of self.
            // This is OK because we never mutate or remove entries.
            Ok(unsafe { mem::transmute::<&[u8], &[u8]>(buf) })
        }
    }

    /// TODO
    #[derive(Debug)]
    pub struct ReadCacheRange<'data, R: Read + Seek> {
        r: &'data ReadCache<R>,
        offset: usize,
        size: usize,
    }

    impl<'data, R: Read + Seek> Clone for ReadCacheRange<'data, R> {
        fn clone(&self) -> Self {
            Self {
                r: self.r,
                offset: self.offset,
                size: self.size,
            }
        }
    }

    impl<'data, R: Read + Seek> Copy for ReadCacheRange<'data, R> {}

    impl<'data, R: Read + Seek> ReadRef<'data> for ReadCacheRange<'data, R> {
        fn len(self) -> Result<usize, ()> {
            Ok(self.size)
        }

        fn read_bytes_at(self, offset: usize, size: usize) -> Result<&'data [u8], ()> {
            if size == 0 {
                return Ok(&[]);
            }
            let end = offset.checked_add(size).ok_or(())?;
            if end >= self.size {
                return Err(());
            }
            let r_offset = self.offset.checked_add(offset).ok_or(())?;
            self.r.read_bytes_at(r_offset, size)
        }
    }
}
#[cfg(feature = "std")]
pub use cache::*;