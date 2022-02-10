use crate::endian::{LittleEndian as LE, U16};
use crate::pe::{ImageResourceDataEntry, ImageResourceDirectory, ImageResourceDirectoryEntry};
use crate::read::{ReadError, ReadRef, Result};

/// A resource directory
#[derive(Clone, Copy)]
pub struct ResourceDirectoryTable<'data> {
    directory_data: &'data [u8],
    /// the resource directory table
    pub table: &'data ImageResourceDirectory,
    /// the resource directory entries
    pub entries: &'data [ImageResourceDirectoryEntry],
}

impl<'data> core::fmt::Debug for ResourceDirectoryTable<'data> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Do not print self.directory_data
        f.debug_struct("ResourceDirectoryTable")
            .field("table", &self.table)
            .field("entries", &self.entries)
            .finish()
    }
}

impl<'data> ResourceDirectoryTable<'data> {
    /// Parses the root resource directory.
    ///
    /// `data` must be the entire resource section
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        Self::read(data, 0)
    }

    fn read(data: &'data [u8], mut offset: u64) -> Result<Self> {
        let table = data
            .read::<ImageResourceDirectory>(&mut offset)
            .read_error("Invalid resource directory table")?;
        let entries_count = table.number_of_id_entries.get(LE) as usize
            + table.number_of_named_entries.get(LE) as usize;
        let entries = data
            .read_slice_at::<ImageResourceDirectoryEntry>(offset, entries_count)
            .read_error("Invalid resource directory entries")?;
        Ok(Self {
            directory_data: data,
            table,
            entries,
        })
    }

    /// Returns an iterator over the directory entries
    pub fn iter(&self) -> ResourceDirectoryIter<'data> {
        ResourceDirectoryIter {
            directory_data: self.directory_data,
            inner: self.entries.iter(),
        }
    }
}

/// An iterator over a resource directory entries
#[allow(missing_debug_implementations)]
pub struct ResourceDirectoryIter<'data> {
    directory_data: &'data [u8],
    inner: core::slice::Iter<'data, ImageResourceDirectoryEntry>,
}

impl<'data> Iterator for ResourceDirectoryIter<'data> {
    type Item = ResourceDirectoryEntry<'data>;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|entry| ResourceDirectoryEntry {
            directory_data: self.directory_data,
            entry,
        })
    }
}

/// A resource directory entry
#[derive(Clone, Copy)]
pub struct ResourceDirectoryEntry<'data> {
    directory_data: &'data [u8],
    entry: &'data ImageResourceDirectoryEntry,
}

impl<'data> core::fmt::Debug for ResourceDirectoryEntry<'data> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Do not print self.directory_data
        f.debug_struct("ResourceDirectoryEntry")
            .field("entry", &self.entry)
            .finish()
    }
}

impl<'data> ResourceDirectoryEntry<'data> {
    /// Returns true if the entry is a sub-directory
    pub fn is_directory(&self) -> bool {
        (self.entry.offset_to_data_or_directory.get(LE)
            & crate::pe::IMAGE_RESOURCE_DATA_IS_DIRECTORY)
            > 0
    }

    /// Returns the offset to the associated directory or data struct
    pub fn data_offset(&self) -> u32 {
        self.entry.offset_to_data_or_directory.get(LE) & 0x7FFF_FFFF
    }

    /// Returns true if the name is an custom string
    pub fn has_string_name(&self) -> bool {
        (self.entry.name_or_id.get(LE) & crate::pe::IMAGE_RESOURCE_NAME_IS_STRING) > 0
    }

    /// Returns the name string offset
    ///
    /// Valid if `has_string_name()` returns true
    fn name_offset(&self) -> u32 {
        self.entry.name_or_id.get(LE) & 0x7FFF_FFFF
    }

    /// Returns the name id
    ///
    /// Valid if `has_string_name()` returns false
    fn name_id(&self) -> u16 {
        (self.entry.name_or_id.get(LE) & 0x0000_FFFF) as u16
    }

    /// Returns the entry name
    pub fn name(&self) -> ResourceNameOrId<'data> {
        if self.has_string_name() {
            ResourceNameOrId::Name(ResourceName {
                directory_data: self.directory_data,
                offset: self.name_offset(),
            })
        } else {
            ResourceNameOrId::Id(self.name_id())
        }
    }

    /// Returns the entry language code
    ///
    /// This is only valid a the level 2 of a standard resource directory structure.
    ///
    /// In a standard resource directory structure:
    /// - level 0: entry.name_or_id is the resource type
    /// - level 1: entry.name_or_id is the resource name
    /// - level 2: entry.name_or_id is the language code
    pub fn language_code(&self) -> Option<u16> {
        if !self.has_string_name() {
            Some(self.name_id())
        } else {
            None
        }
    }

    /// Returns the data associated to this directory entry
    pub fn data(&self) -> Result<ResourceDirectoryEntryData<'data>> {
        if self.is_directory() {
            ResourceDirectoryTable::read(self.directory_data, self.data_offset() as _)
                .map(|t| ResourceDirectoryEntryData::Directory(t))
        } else {
            self.directory_data
                .read_at::<ImageResourceDataEntry>(self.data_offset() as _)
                .read_error("Invalid resource entry")
                .map(|d| ResourceDirectoryEntryData::Entry(d))
        }
    }
}

/// A resource directory entry data
#[derive(Debug, Clone, Copy)]
pub enum ResourceDirectoryEntryData<'data> {
    /// A sub directory entry
    Directory(ResourceDirectoryTable<'data>),
    /// A resource entry
    Entry(&'data ImageResourceDataEntry),
}

impl<'data> ResourceDirectoryEntryData<'data> {
    /// Converts to an option of directory
    ///
    /// Helper for iterator filtering
    pub fn directory(self) -> Option<ResourceDirectoryTable<'data>> {
        match self {
            Self::Directory(dir) => Some(dir),
            _ => None,
        }
    }

    /// Converts to an option of entry
    ///
    /// Helper for iterator filtering
    pub fn resource(self) -> Option<&'data ImageResourceDataEntry> {
        match self {
            Self::Entry(rsc) => Some(rsc),
            _ => None,
        }
    }
}

/// A resource name
pub struct ResourceName<'data> {
    directory_data: &'data [u8],
    offset: u32,
}

impl<'data> ResourceName<'data> {
    /// Converts to a `String`
    pub fn to_string_lossy(&self) -> Result<alloc::string::String> {
        let d = self.data()?;
        Ok(alloc::string::String::from_utf16_lossy(d))
    }

    /// Returns the string unicode buffer
    pub fn data(&self) -> Result<&'data [u16]> {
        let len = self
            .directory_data
            .read_at::<U16<LE>>(self.offset as _)
            .read_error("Invalid name length")?;
        let offset = self
            .offset
            .checked_add(2)
            .read_error("Invalid name offset")?;
        self.directory_data
            .read_slice_at::<u16>(offset as _, len.get(LE) as _)
            .read_error("Invalid name buffer")
    }
}

impl<'data> core::fmt::Debug for ResourceName<'data> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Do not print self.directory_data
        f.debug_struct("ResourceName")
            .field("offset", &self.offset)
            .field("data", &self.data())
            .finish()
    }
}

/// A resource name
///
/// Can be either a string or an id
#[derive(Debug)]
pub enum ResourceNameOrId<'data> {
    /// A resource string name
    Name(ResourceName<'data>),
    /// A resource name id
    Id(u16),
}

// Resource type: https://docs.microsoft.com/en-us/windows/win32/menurc/resource-types

/// ID for: Hardware-dependent cursor resource.
pub const RESOURCE_TYPE_ID_RT_CURSOR: u16 = 1;
/// ID for: Bitmap resource.
pub const RESOURCE_TYPE_ID_RT_BITMAP: u16 = 2;
/// ID for: Hardware-dependent icon resource.
pub const RESOURCE_TYPE_ID_RT_ICON: u16 = 3;
/// ID for: Menu resource.
pub const RESOURCE_TYPE_ID_RT_MENU: u16 = 4;
/// ID for: Dialog box.
pub const RESOURCE_TYPE_ID_RT_DIALOG: u16 = 5;
/// ID for: String-table entry.
pub const RESOURCE_TYPE_ID_RT_STRING: u16 = 6;
/// ID for: Font directory resource.
pub const RESOURCE_TYPE_ID_RT_FONTDIR: u16 = 7;
/// ID for: Font resource.
pub const RESOURCE_TYPE_ID_RT_FONT: u16 = 8;
/// ID for: Accelerator table.
pub const RESOURCE_TYPE_ID_RT_ACCELERATOR: u16 = 9;
/// ID for: Application-defined resource (raw data).
pub const RESOURCE_TYPE_ID_RT_RCDATA: u16 = 10;
/// ID for: Message-table entry.
pub const RESOURCE_TYPE_ID_RT_MESSAGETABLE: u16 = 11;
/// ID for: Hardware-independent cursor resource.
pub const RESOURCE_TYPE_ID_RT_GROUP_CURSOR: u16 = 12;
/// ID for: Hardware-independent icon resource.
pub const RESOURCE_TYPE_ID_RT_GROUP_ICON: u16 = 14;
/// ID for: Version resource.
pub const RESOURCE_TYPE_ID_RT_VERSION: u16 = 16;
/// ID for: Allows a resource editing tool to associate a string with an .rc file.
pub const RESOURCE_TYPE_ID_RT_DLGINCLUDE: u16 = 17;
/// ID for: Plug and Play resource.
pub const RESOURCE_TYPE_ID_RT_PLUGPLAY: u16 = 19;
/// ID for: VXD.
pub const RESOURCE_TYPE_ID_RT_VXD: u16 = 20;
/// ID for: Animated cursor.
pub const RESOURCE_TYPE_ID_RT_ANICURSOR: u16 = 21;
/// ID for: Animated icon.
pub const RESOURCE_TYPE_ID_RT_ANIICON: u16 = 22;
/// ID for: HTML resource.
pub const RESOURCE_TYPE_ID_RT_HTML: u16 = 23;
/// ID for: Side-by-Side Assembly Manifest.
pub const RESOURCE_TYPE_ID_RT_MANIFEST: u16 = 24;
