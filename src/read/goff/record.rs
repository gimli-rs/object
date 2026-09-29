use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;
use core::{iter, mem};

use crate::BigEndian as BE;
use crate::ebcdic;
use crate::goff;
use crate::pod::{self, Pod};
use crate::read::{Error, ReadError, Result};

/// A record and its continuation records.
#[derive(Debug, Clone, Copy)]
pub struct LogicalRecord<'data, T> {
    /// The initial record.
    pub initial: &'data T,
    /// The continuation records.
    pub continuations: &'data [goff::Record],
}

impl<'data, T> LogicalRecord<'data, T> {
    /// Iterate over the variable length data in the initial record and the continuation
    /// records, limited to a total of `len` bytes.
    ///
    /// Returns an error if there are less than `len` bytes in the records.
    fn data_iter(
        &self,
        initial_data: &'data [u8],
        len: usize,
    ) -> Result<(&'data [u8], impl Iterator<Item = &'data [u8]>)> {
        let head_len = initial_data.len().min(len);
        let head = &initial_data[..head_len];
        let mut remaining = len - head_len;
        if self.continuations.len() * goff::SIZEOF_RECORD_DATA < remaining {
            return Err(Error("GOFF record data length exceeds record size"));
        }
        Ok((
            head,
            self.continuations
                .iter()
                .map(move |record| {
                    let part = &record.data[..record.data.len().min(remaining)];
                    remaining -= part.len();
                    part
                })
                .filter(|part| !part.is_empty()),
        ))
    }

    /// Return the concatenated variable length data in the initial record and the
    /// continuation records, limited to a total of `len` bytes.
    ///
    /// Returns an error if there are less than `len` bytes in the records.
    fn data_join(&self, initial_data: &'data [u8], len: usize) -> Result<Cow<'data, [u8]>> {
        let (head, parts) = self.data_iter(initial_data, len)?;
        if head.len() == len {
            return Ok(Cow::Borrowed(head));
        }
        let mut data = Vec::with_capacity(len);
        data.extend_from_slice(head);
        for part in parts {
            data.extend_from_slice(part);
        }
        Ok(Cow::Owned(data))
    }
}

impl<'data> LogicalRecord<'data, goff::Record> {
    /// Parse a record and its continuations from the start of `records`.
    ///
    /// Returns `None` if `records` is empty.
    pub fn parse(records: &mut &'data [goff::Record]) -> Result<Option<Self>> {
        let [initial, rest @ ..] = *records else {
            return Ok(None);
        };
        if !initial.ptv.is_valid() || initial.ptv.is_continuation() {
            return Err(Error("Invalid GOFF record"));
        }

        let mut count = 0;
        let mut continued = initial.ptv.is_continued();
        while continued {
            let cont_record = rest
                .get(count)
                .read_error("Missing GOFF continuation record")?;
            if !cont_record.ptv.is_valid()
                || !cont_record.ptv.is_continuation()
                || cont_record.ptv.record_type() != initial.ptv.record_type()
            {
                return Err(Error("Invalid GOFF continuation record"));
            }
            count += 1;
            continued = cont_record.ptv.is_continued();
        }
        let (continuations, rest) = rest.split_at(count);
        *records = rest;

        Ok(Some(LogicalRecord {
            initial,
            continuations,
        }))
    }

    /// Cast the record to a different record type.
    ///
    /// Only checks that the length is valid.
    pub fn cast<T: Pod>(self) -> LogicalRecord<'data, T> {
        const {
            assert!(mem::size_of::<T>() == mem::size_of::<goff::Record>());
        }
        // Can't fail: the size is checked above, and all record types have alignment 1.
        let (record, _) = pod::from_bytes::<T>(pod::bytes_of(self.initial)).unwrap();
        LogicalRecord {
            initial: record,
            continuations: self.continuations,
        }
    }
}

impl<'data> LogicalRecord<'data, goff::SymbolRecord> {
    /// Return the concatenated name data in the initial record and the continuation records.
    pub fn esd_name(&self) -> Result<Cow<'data, [u8]>> {
        self.data_join(
            &self.initial.name,
            usize::from(self.initial.name_length.get(BE)),
        )
    }

    /// Return the concatenated name data in the initial record and the continuation records,
    /// converted to UTF-8.
    pub fn esd_name_utf8(&self) -> Result<String> {
        // TODO: avoid intermediate Vec
        self.esd_name().map(|data| ebcdic::to_string(&data))
    }
}

impl<'data> LogicalRecord<'data, goff::TextRecord> {
    /// Iterate over the text data in the initial record and the continuation records.
    pub fn txt_data_parts(&self) -> Result<impl Iterator<Item = &'data [u8]>> {
        let (head, parts) = self.data_iter(
            &self.initial.data,
            usize::from(self.initial.data_length.get(BE)),
        )?;
        Ok(iter::once(head).chain(parts))
    }

    /// Return the concatenated text data in the initial record and the continuation records.
    pub fn txt_data(&self) -> Result<Cow<'data, [u8]>> {
        self.data_join(
            &self.initial.data,
            usize::from(self.initial.data_length.get(BE)),
        )
    }
}

impl<'data> LogicalRecord<'data, goff::RelocationRecord> {
    /// Return the concatenated relocation data in the initial record and the continuation records.
    pub fn rld_data(&self) -> Result<Cow<'data, [u8]>> {
        self.data_join(&self.initial.data, usize::from(self.initial.length.get(BE)))
    }
}

impl<'data> LogicalRecord<'data, goff::EndRecord> {
    /// Return the concatenated entry name data in the initial record and the continuation records.
    pub fn entry_name(&self) -> Result<Cow<'data, [u8]>> {
        self.data_join(
            &self.initial.entry_name,
            usize::from(self.initial.name_length.get(BE)),
        )
    }

    /// Return the concatenated entry name data in the initial record and the continuation records,
    /// converted to UTF-8.
    pub fn entry_name_utf8(&self) -> Result<String> {
        // TODO: avoid intermediate Vec
        self.entry_name().map(|data| ebcdic::to_string(&data))
    }
}

impl<'data> LogicalRecord<'data, goff::LengthRecord> {
    /// Return the concatenated length data in the initial record and the continuation records.
    pub fn len_data(&self) -> Result<Cow<'data, [u8]>> {
        self.data_join(&self.initial.data, usize::from(self.initial.length.get(BE)))
    }

    /// Iterate over the length data items in the initial record and the continuation records.
    ///
    /// Returns an error if the data length is not a multiple of the item size.
    pub fn len_items(&self) -> Result<LengthIterator<'data>> {
        let data = self.len_data()?;
        if data.len() % mem::size_of::<goff::LengthDataItem>() != 0 {
            return Err(Error("Invalid GOFF length data length"));
        }
        Ok(LengthIterator { data, offset: 0 })
    }
}

/// An iterator over the length data items in a LEN record.
///
/// Returned by [`LogicalRecord::len_items`].
#[derive(Debug)]
pub struct LengthIterator<'data> {
    // TODO: this could avoid allocation
    data: Cow<'data, [u8]>,
    offset: usize,
}

impl<'data> Iterator for LengthIterator<'data> {
    type Item = goff::LengthDataItem;

    fn next(&mut self) -> Option<Self::Item> {
        let item = pod::from_bytes::<goff::LengthDataItem>(&self.data[self.offset..]).ok()?;
        self.offset += mem::size_of::<goff::LengthDataItem>();
        Some(*item.0)
    }
}
