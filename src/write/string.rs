use alloc::vec::Vec;

use crate::write::{Error, Result};

#[cfg(feature = "write_std")]
type IndexSet<K> = indexmap::IndexSet<K>;
#[cfg(not(feature = "write_std"))]
type IndexSet<K> = indexmap::IndexSet<K, hashbrown::DefaultHashBuilder>;

/// An identifier for an entry in a string table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringId(usize);

/// A string table containing null terminated byte strings.
#[derive(Debug, Default)]
pub(crate) struct StringTable<'a> {
    strings: IndexSet<&'a [u8]>,
    offsets: Vec<u32>,
}

impl<'a> StringTable<'a> {
    /// Return true if the string table contains no strings.
    pub(crate) fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }

    /// Add a string to the string table.
    ///
    /// Duplicate strings return the id of the existing entry.
    ///
    /// Must be called before [`Self::write`].
    ///
    /// The string must not contain a null byte; this is asserted here for
    /// debug builds, and checked by `write` for all builds.
    pub(crate) fn add(&mut self, string: &'a [u8]) -> StringId {
        debug_assert!(self.offsets.is_empty());
        debug_assert!(!string.contains(&0));
        let id = self.strings.insert_full(string).0;
        StringId(id)
    }

    /// Return the id of a previously added string.
    ///
    /// Panics if the string is not in the string table.
    #[allow(dead_code)]
    pub(crate) fn get_id(&self, string: &[u8]) -> StringId {
        let id = self.strings.get_index_of(string).unwrap();
        StringId(id)
    }

    /// Return the string for the given id.
    ///
    /// Panics if `id` is invalid.
    #[allow(dead_code)]
    pub(crate) fn get_string(&self, id: StringId) -> &'a [u8] {
        self.strings.get_index(id.0).unwrap()
    }

    /// Return the offset of the given string.
    ///
    /// Must be called after [`Self::write`].
    ///
    /// Panics if `id` is invalid or `write` was not called.
    pub(crate) fn get_offset(&self, id: StringId) -> u32 {
        self.offsets[id.0]
    }

    /// Append the string table to the given `Vec`, and
    /// calculate the list of string offsets.
    ///
    /// `base` is the initial string table offset. For example,
    /// this should be 1 for ELF, to account for the initial
    /// null byte (which must have been written by the caller).
    ///
    /// Returns the total size, including base.
    ///
    /// Returns an error if:
    /// - `write` has already been called
    /// - any string contains a null byte
    /// - the string table size is > `u32::MAX`
    pub(crate) fn write(&mut self, base: u32, w: &mut Vec<u8>) -> Result<u32> {
        if !self.offsets.is_empty() {
            return Err(Error("string table already written".into()));
        }
        if self.strings.iter().any(|s| s.contains(&0)) {
            return Err(Error("string table entry contains null byte".into()));
        }

        let mut ids: Vec<_> = (0..self.strings.len()).collect();
        sort(&mut ids, 1, &self.strings);

        self.offsets = vec![0; ids.len()];
        let mut offset = u64::from(base);
        let mut previous = &[][..];
        for id in ids {
            let string = self.strings.get_index(id).unwrap();
            let len = string.len() as u64 + 1;
            if previous.ends_with(string) {
                self.offsets[id] = (offset - len) as u32;
            } else {
                self.offsets[id] = offset as u32;
                w.extend_from_slice(string);
                w.push(0);
                offset += len;
                previous = string;
            }
        }
        u32::try_from(offset).map_err(|_| Error("string table size overflow".into()))
    }

    /// Calculate the size in bytes of the string table.
    ///
    /// `base` is the initial string table offset. For example,
    /// this should be 1 for ELF, to account for the initial
    /// null byte.
    #[allow(dead_code)]
    pub(crate) fn size(&self, base: usize) -> usize {
        // TODO: cache this result?
        let mut ids: Vec<_> = (0..self.strings.len()).collect();
        sort(&mut ids, 1, &self.strings);

        let mut size = base;
        let mut previous = &[][..];
        for id in ids {
            let string = self.strings.get_index(id).unwrap();
            if !previous.ends_with(string) {
                size += string.len() + 1;
                previous = string;
            }
        }
        size
    }
}

// Multi-key quicksort.
//
// Ordering is such that if a string is a suffix of at least one other string,
// then it is placed immediately after one of those strings. That is:
// - comparison starts at the end of the string
// - shorter strings come later
//
// Based on the implementation in LLVM.
fn sort(mut ids: &mut [usize], mut pos: usize, strings: &IndexSet<&[u8]>) {
    loop {
        if ids.len() <= 1 {
            return;
        }

        let pivot = byte(ids[0], pos, strings);
        let mut lower = 0;
        let mut upper = ids.len();
        let mut i = 1;
        while i < upper {
            let b = byte(ids[i], pos, strings);
            if b > pivot {
                ids.swap(lower, i);
                lower += 1;
                i += 1;
            } else if b < pivot {
                upper -= 1;
                ids.swap(upper, i);
            } else {
                i += 1;
            }
        }

        sort(&mut ids[..lower], pos, strings);
        sort(&mut ids[upper..], pos, strings);

        if pivot == 0 {
            return;
        }
        ids = &mut ids[lower..upper];
        pos += 1;
    }
}

fn byte(id: usize, pos: usize, strings: &IndexSet<&[u8]>) -> u8 {
    let string = strings.get_index(id).unwrap();
    let len = string.len();
    if len >= pos {
        string[len - pos]
    } else {
        // We know the strings don't contain null bytes.
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_table() {
        let mut table = StringTable::default();
        let id0 = table.add(b"");
        let id1 = table.add(b"foo");
        let id2 = table.add(b"bar");
        let id3 = table.add(b"foobar");

        let mut data = Vec::new();
        data.push(0);
        assert_eq!(table.write(1, &mut data), Ok(12));
        assert_eq!(data, b"\0foobar\0foo\0");

        assert_eq!(table.get_offset(id0), 11);
        assert_eq!(table.get_offset(id1), 8);
        assert_eq!(table.get_offset(id2), 4);
        assert_eq!(table.get_offset(id3), 1);

        let mut data = Vec::new();
        assert!(table.write(1, &mut data).is_err());
    }
}
