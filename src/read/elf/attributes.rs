use crate::endian;
use crate::read::{Bytes, ReadError, Result};

use super::FileHeader;

/// An iterator over the section entries in an ELF `SHT_GNU_attributes` section.
#[derive(Debug, Clone)]
pub struct AttribSubsectionIterator<'data, Elf: FileHeader> {
    endian: Elf::Endian,
    data: Bytes<'data>,
}

impl<'data, Elf: FileHeader> AttribSubsectionIterator<'data, Elf> {
    pub(super) fn new(endian: Elf::Endian, data: Bytes<'data>) -> Self {
        AttribSubsectionIterator { endian, data: data }
    }

    /// Return the next Vendor attribute section
    pub fn next(
        &mut self,
    ) -> Result<Option<(&'data [u8], AttribSubSubsectionIterator<'data, Elf>)>> {
        if self.data.is_empty() {
            return Ok(None);
        }

        // First read the section length
        let mut data = self.data;
        let section_length = data
            .read::<endian::U32Bytes<Elf::Endian>>()
            .read_error("ELF GNU attributes vendor section is too short")?
            .get(self.endian);

        // Now read the entire section
        let mut section = self
            .data
            .read_bytes(section_length as usize)
            .read_error("ELF GNU attributes section incorrectly sized")?;
        // Skip the section length field
        section
            .skip(core::mem::size_of::<endian::U32<Elf::Endian>>())
            .read_error("ELF GNU attributes vendor section is too short")?;

        let vendor_name = section
            .read_string()
            .read_error("ELF GNU attributes vendor section is too short")?;

        // Pass the remainder of this section to the tag iterator
        let tags = AttribSubSubsectionIterator::new(self.endian, section);

        Ok(Some((vendor_name, tags)))
    }
}

/// An iterator over the attribute tags in a GNU attributes section
#[derive(Debug, Clone)]
pub struct AttribSubSubsectionIterator<'data, Elf: FileHeader> {
    endian: Elf::Endian,
    data: Bytes<'data>,
}

impl<'data, Elf: FileHeader> AttribSubSubsectionIterator<'data, Elf> {
    pub(super) fn new(endian: Elf::Endian, data: Bytes<'data>) -> Self {
        AttribSubSubsectionIterator { endian, data: data }
    }

    /// Return the next tag.
    ///
    /// The format of attributes looks like this:
    /// ```text
    /// [ <file-tag> <size> <attribute>*
    /// | <section-tag> <size> <section-number>* 0 <attribute>*
    /// | <symbol-tag> <size> <symbol-number>* 0 <attribute>*
    /// ]+
    /// ```
    /// This iterator returns the (tag, data) pair, allowing the user to access the raw data for
    /// the tags. The data is an array of attributes, each of which is an attribute tag folowed by
    /// either a uleb128 encoded integer or a NULL terminated string
    pub fn next(&mut self) -> Result<Option<(u8, &'data [u8])>> {
        if self.data.is_empty() {
            return Ok(None);
        }

        let tag = self
            .data
            .read::<u8>()
            .read_error("GNU Attributes tag not correctly sized")?;

        let tag_length = self
            .data
            .read::<endian::U32Bytes<Elf::Endian>>()
            .read_error("ELF GNU attributes vendor section is too short")?
            .get(self.endian) as usize;

        // Subtract the size of our tag and length fields here
        let tag_size = tag_length
            .checked_sub(core::mem::size_of::<endian::U32<Elf::Endian>>())
            .ok_or(())
            .read_error("GNU attriutes tag size is too short")?
            .checked_sub(1)
            .ok_or(())
            .read_error("GNU attriutes tag size is too short")?;

        let tag_data = self
            .data
            .read_slice(tag_size)
            .read_error("GNU attributes tag data does not match size requested")?;
        return Ok(Some((*tag, tag_data)));
    }
}
