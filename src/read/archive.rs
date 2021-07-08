//! Support for archive files.

use core::convert::TryInto;

use crate::archive;
use crate::read::{self, Error, ReadError, ReadRef};
use alloc::prelude::v1::Box;

/// Trait for various header style
pub trait GenericHeader {
    /// Name as stored in header.
    fn name(&self) -> &[u8];
    /// File modification timestamp in decimal.
    fn date(&self) -> &[u8];
    /// User ID in decimal.
    fn uid(&self) -> &[u8];
    /// Group ID in decimal.
    fn gid(&self) -> &[u8];
    /// File mode in octal.
    fn mode(&self) -> &[u8];
    /// File size in decimal.
    fn size(&self) -> &[u8];
}

impl core::fmt::Debug for dyn GenericHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl GenericHeader for archive::Header {
    /// Name as stored in header.
    fn name(&self) -> &[u8] {
        &self.name[..]
    }
    /// File modification timestamp in decimal.
    fn date(&self) -> &[u8] {
        &self.date[..]
    }
    /// User ID in decimal.
    fn uid(&self) -> &[u8] {
        &self.uid[..]
    }
    /// Group ID in decimal.
    fn gid(&self) -> &[u8] {
        &self.gid[..]
    }
    /// File mode in octal.
    fn mode(&self) -> &[u8] {
        &self.mode[..]
    }
    /// File size in decimal.
    fn size(&self) -> &[u8] {
        &self.size[..]
    }
}

impl GenericHeader for archive::BigHeader {
    /// Name as stored in header is not the real name for big archive.
    fn name(&self) -> &[u8] {
        &[]
    }
    /// File modification timestamp in decimal.
    fn date(&self) -> &[u8] {
        &self.date[..]
    }
    /// User ID in decimal.
    fn uid(&self) -> &[u8] {
        &self.uid[..]
    }
    /// Group ID in decimal.
    fn gid(&self) -> &[u8] {
        &self.gid[..]
    }
    /// File mode in octal.
    fn mode(&self) -> &[u8] {
        &self.mode[..]
    }
    /// File size in decimal.
    fn size(&self) -> &[u8] {
        &self.size[..]
    }
}

/// The kind of archive format.
// TODO: Gnu64 and Darwin64 (and Darwin for writing)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ArchiveKind {
    /// There are no special files that indicate the archive format.
    Unknown,
    /// The GNU (or System V) archive format.
    Gnu,
    /// The BSD archive format.
    Bsd,
    /// The Windows COFF archive format.
    Coff,
    /// The AIX Big archive (XCOFF) format.
    Xcoff,
}

/// A partially parsed archive file.
#[derive(Debug)]
pub struct ArchiveFile<'data, R: ReadRef<'data> = &'data [u8]> {
    data: R,
    len: u64,
    offset: u64,
    kind: ArchiveKind,
    symbols: (u64, u64),
    names: &'data [u8],
}

impl<'data, R: ReadRef<'data>> ArchiveFile<'data, R> {
    /// Parse the archive header and special members.
    pub fn parse(data: R) -> read::Result<Self> {
        let len = data.len().read_error("Unknown archive length")?;
        let mut tail = 0;
        let magic = data
            .read_bytes(&mut tail, archive::MAGIC.len() as u64)
            .read_error("Invalid archive size")?;
        if magic != &archive::MAGIC[..]
            && magic != &archive::BIG_MAGIC[..] {
            return Err(Error("Unsupported archive identifier"));
        }

        let mut file = if magic == &archive::BIG_MAGIC[..] {
            ArchiveFile {
                data,
                offset: tail,
                len,
                kind: ArchiveKind::Xcoff,
                symbols: (0, 0),
                names: &[],
            }
        } else {
            ArchiveFile {
                data,
                offset: tail,
                len,
                kind: ArchiveKind::Unknown,
                symbols: (0, 0),
                names: &[],
            }
        };

        // The first few members may be special, so parse them.
        // GNU has:
        // - "/": symbol table (optional)
        // - "//": names table (optional)
        // COFF has:
        // - "/": first linker member
        // - "/": second linker member
        // - "//": names table
        // BSD has:
        // - "__.SYMDEF" or "__.SYMDEF SORTED": symbol table (optional)
        if tail < len && file.kind != ArchiveKind::Xcoff {
            let member = ArchiveMember::parse(data, &mut tail, &[], file.kind)?;
            if member.name == b"/" {
                // GNU symbol table (unless we later determine this is COFF).
                file.kind = ArchiveKind::Gnu;
                file.symbols = member.file_range();
                file.offset = tail;

                if tail < len {
                    let member = ArchiveMember::parse(data, &mut tail, &[], file.kind)?;
                    if member.name == b"/" {
                        // COFF linker member.
                        file.kind = ArchiveKind::Coff;
                        file.symbols = member.file_range();
                        file.offset = tail;

                        if tail < len {
                            let member = ArchiveMember::parse(data, &mut tail, &[], file.kind)?;
                            if member.name == b"//" {
                                // COFF names table.
                                file.names = member.data(data)?;
                                file.offset = tail;
                            }
                        }
                    } else if member.name == b"//" {
                        // GNU names table.
                        file.names = member.data(data)?;
                        file.offset = tail;
                    }
                }
            } else if member.name == b"//" {
                // GNU names table.
                file.kind = ArchiveKind::Gnu;
                file.names = member.data(data)?;
                file.offset = tail;
            } else if member.name == b"__.SYMDEF" || member.name == b"__.SYMDEF SORTED" {
                // BSD symbol table.
                file.kind = ArchiveKind::Bsd;
                file.symbols = member.file_range();
                file.offset = tail;
            } else {
                // TODO: This could still be a BSD file. We leave this as unknown for now.
            }
        } else if tail < len && file.kind == ArchiveKind::Xcoff {
            // Read and consume fixed size header.
            let _fixed_size_header = data
                .read::<archive::BigFixedLengthHeader>(&mut tail)
                .read_error("Invalid fixed sized archive header")?;
            file.offset = tail;
        }
        Ok(file)
    }

    /// Return the archive format.
    #[inline]
    pub fn kind(&self) -> ArchiveKind {
        self.kind
    }

    /// Iterate over the members of the archive.
    ///
    /// This does not return special members.
    #[inline]
    pub fn members(&self) -> ArchiveMemberIterator<'data, R> {
        ArchiveMemberIterator {
            data: self.data,
            offset: self.offset,
            len: self.len,
            names: self.names,
            kind: self.kind,
        }
    }
}

/// An iterator over the members of an archive.
#[derive(Debug)]
pub struct ArchiveMemberIterator<'data, R: ReadRef<'data> = &'data [u8]> {
    data: R,
    offset: u64,
    len: u64,
    names: &'data [u8],
    kind: ArchiveKind,
}

impl<'data, R: ReadRef<'data>> Iterator for ArchiveMemberIterator<'data, R> {
    type Item = read::Result<ArchiveMember<'data>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.len {
            return None;
        }
        let member = ArchiveMember::parse(self.data, &mut self.offset, self.names, self.kind);
        if member.is_err() {
            self.offset = self.len;
        }
        Some(member)
    }
}

/// A partially parsed archive member.
#[derive(Debug)]
pub struct ArchiveMember<'data> {
    header: Box<dyn GenericHeader>,
    name: &'data [u8],
    offset: u64,
    size: u64,
}

impl<'data> ArchiveMember<'data> {
    /// Parse the archive member header, name, and file data.
    ///
    /// This reads the extended name (if any) and adjusts the file size.
    fn parse<R: ReadRef<'data>>(
        data: R,
        offset: &mut u64,
        names: &'data [u8],
        kind: ArchiveKind,
    ) -> read::Result<Self> {
        if kind != ArchiveKind::Xcoff {
            let header = data
                .read::<archive::Header>(offset)
                .read_error("Invalid archive member header")?;
            if header.terminator != archive::TERMINATOR {
                return Err(Error("Invalid archive terminator"));
            }
    
            let mut file_offset = *offset;
            let mut file_size =
                parse_u64_digits(&header.size, 10).read_error("Invalid archive member size")?;
            *offset = offset
                .checked_add(file_size)
                .read_error("Archive member size is too large")?;
            // Entries are padded to an even number of bytes.
            if (file_size & 1) != 0 {
                *offset = offset.saturating_add(1);
            }
    
            let name = if header.name[0] == b'/' && (header.name[1] as char).is_digit(10) {
                // Read file name from the names table.
                parse_sysv_extended_name(&header.name[1..], names)
                    .read_error("Invalid archive extended name offset")?
            } else if &header.name[..3] == b"#1/" && (header.name[3] as char).is_digit(10) {
                // Read file name from the start of the file data.
                parse_bsd_extended_name(&header.name[3..], data, &mut file_offset, &mut file_size)
                    .read_error("Invalid archive extended name length")?
            } else if header.name[0] == b'/' {
                let name_len = memchr::memchr(b' ', &header.name).unwrap_or(header.name.len());
                &header.name[..name_len]
            } else {
                let name_len = memchr::memchr(b'/', &header.name)
                    .or_else(|| memchr::memchr(b' ', &header.name))
                    .unwrap_or(header.name.len());
                &header.name[..name_len]
            };
    
            Ok(ArchiveMember {
                header: Box::new(*header),
                name,
                offset: file_offset,
                size: file_size,
            })
        } else {
            let header = data
               .read::<archive::BigHeader>(offset)
               .read_error("Invalid big archive member header")?;

            let file_offset = *offset;
            let namelen = parse_u64_digits(&header.namelen, 10).read_error("Invalid archive name length")?;
            let name = data
                .read_bytes(offset, namelen)
                .read_error("Big archive member name is too large")?;
            // Names are padded to an even number of bytes.
            if (namelen & 1) != 0 {
                *offset = offset.saturating_add(1);
            }
            let _terminator = data
                .read_bytes(offset, 2)
                .read_error("Big archive terminator not found")?;

            let file_size =
               parse_u64_digits(&header.size, 10).read_error("Invalid big archive member size")?;
            *offset = offset
                .checked_add(file_size)
                .read_error("Big archive member size is too large")?;
            // Entries are padded to an even number of bytes.
            if (file_size & 1) != 0 {
                *offset = offset.saturating_add(1);
            }

            Ok(ArchiveMember {
                header: Box::new(*header),
                name,
                offset: file_offset,
                size: file_size
            })
        }
    }

    /// Return the parsed file name.
    ///
    /// This may be an extended file name.
    #[inline]
    pub fn name(&self) -> &'data [u8] {
        self.name
    }

    /// Parse the file modification timestamp from the header.
    #[inline]
    pub fn date(&self) -> Option<u64> {
        parse_u64_digits(&self.header.date(), 10)
    }

    /// Parse the user ID from the header.
    #[inline]
    pub fn uid(&self) -> Option<u64> {
        parse_u64_digits(&self.header.uid(), 10)
    }

    /// Parse the group ID from the header.
    #[inline]
    pub fn gid(&self) -> Option<u64> {
        parse_u64_digits(&self.header.gid(), 10)
    }

    /// Parse the file mode from the header.
    #[inline]
    pub fn mode(&self) -> Option<u64> {
        parse_u64_digits(&self.header.mode(), 8)
    }

    /// Return the offset and size of the file data.
    pub fn file_range(&self) -> (u64, u64) {
        (self.offset, self.size)
    }

    /// Return the file data.
    #[inline]
    pub fn data<R: ReadRef<'data>>(&self, data: R) -> read::Result<&'data [u8]> {
        data.read_bytes_at(self.offset, self.size)
            .read_error("Archive member size is too large")
    }
}

// Ignores bytes starting from the first space.
fn parse_u64_digits(digits: &[u8], radix: u32) -> Option<u64> {
    if let [b' ', ..] = digits {
        return None;
    }
    let mut result: u64 = 0;
    for &c in digits {
        if c == b' ' {
            return Some(result);
        } else {
            let x = (c as char).to_digit(radix)?;
            result = result
                .checked_mul(u64::from(radix))?
                .checked_add(u64::from(x))?;
        }
    }
    Some(result)
}

fn parse_sysv_extended_name<'data>(digits: &[u8], names: &'data [u8]) -> Result<&'data [u8], ()> {
    let offset = parse_u64_digits(digits, 10).ok_or(())?;
    let offset = offset.try_into().map_err(|_| ())?;
    let name_data = names.get(offset..).ok_or(())?;
    let name = match memchr::memchr2(b'/', b'\0', name_data) {
        Some(len) => &name_data[..len],
        None => name_data,
    };
    Ok(name)
}

/// Modifies `data` to start after the extended name.
fn parse_bsd_extended_name<'data, R: ReadRef<'data>>(
    digits: &[u8],
    data: R,
    offset: &mut u64,
    size: &mut u64,
) -> Result<&'data [u8], ()> {
    let len = parse_u64_digits(digits, 10).ok_or(())?;
    *size = size.checked_sub(len).ok_or(())?;
    let name_data = data.read_bytes(offset, len)?;
    let name = match memchr::memchr(b'\0', name_data) {
        Some(len) => &name_data[..len],
        None => name_data,
    };
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind() {
        let data = b"!<arch>\n";
        let archive = ArchiveFile::parse(&data[..]).unwrap();
        assert_eq!(archive.kind(), ArchiveKind::Unknown);

        let data = b"\
            !<arch>\n\
            /                                               4         `\n\
            0000";
        let archive = ArchiveFile::parse(&data[..]).unwrap();
        assert_eq!(archive.kind(), ArchiveKind::Gnu);

        let data = b"\
            !<arch>\n\
            //                                              4         `\n\
            0000";
        let archive = ArchiveFile::parse(&data[..]).unwrap();
        assert_eq!(archive.kind(), ArchiveKind::Gnu);

        let data = b"\
            !<arch>\n\
            /                                               4         `\n\
            0000\
            //                                              4         `\n\
            0000";
        let archive = ArchiveFile::parse(&data[..]).unwrap();
        assert_eq!(archive.kind(), ArchiveKind::Gnu);

        let data = b"\
            !<arch>\n\
            __.SYMDEF                                       4         `\n\
            0000";
        let archive = ArchiveFile::parse(&data[..]).unwrap();
        assert_eq!(archive.kind(), ArchiveKind::Bsd);

        let data = b"\
            !<arch>\n\
            #1/9                                            13        `\n\
            __.SYMDEF0000";
        let archive = ArchiveFile::parse(&data[..]).unwrap();
        assert_eq!(archive.kind(), ArchiveKind::Bsd);

        let data = b"\
            !<arch>\n\
            #1/16                                           20        `\n\
            __.SYMDEF SORTED0000";
        let archive = ArchiveFile::parse(&data[..]).unwrap();
        assert_eq!(archive.kind(), ArchiveKind::Bsd);

        let data = b"\
            !<arch>\n\
            /                                               4         `\n\
            0000\
            /                                               4         `\n\
            0000\
            //                                              4         `\n\
            0000";
        let archive = ArchiveFile::parse(&data[..]).unwrap();
        assert_eq!(archive.kind(), ArchiveKind::Coff);
    }

    #[test]
    fn gnu_names() {
        let data = b"\
            !<arch>\n\
            //                                              18        `\n\
            0123456789abcdef/\n\
            s p a c e/      0           0     0     644     4         `\n\
            0000\
            0123456789abcde/0           0     0     644     3         `\n\
            odd\n\
            /0              0           0     0     644     4         `\n\
            even";
        let data = &data[..];
        let archive = ArchiveFile::parse(data).unwrap();
        assert_eq!(archive.kind(), ArchiveKind::Gnu);
        let mut members = archive.members();

        let member = members.next().unwrap().unwrap();
        assert_eq!(member.name(), b"s p a c e");
        assert_eq!(member.data(data).unwrap(), &b"0000"[..]);

        let member = members.next().unwrap().unwrap();
        assert_eq!(member.name(), b"0123456789abcde");
        assert_eq!(member.data(data).unwrap(), &b"odd"[..]);

        let member = members.next().unwrap().unwrap();
        assert_eq!(member.name(), b"0123456789abcdef");
        assert_eq!(member.data(data).unwrap(), &b"even"[..]);

        assert!(members.next().is_none());
    }

    #[test]
    fn bsd_names() {
        let data = b"\
            !<arch>\n\
            0123456789abcde 0           0     0     644     3         `\n\
            odd\n\
            #1/16           0           0     0     644     20        `\n\
            0123456789abcdefeven";
        let data = &data[..];
        let archive = ArchiveFile::parse(data).unwrap();
        assert_eq!(archive.kind(), ArchiveKind::Unknown);
        let mut members = archive.members();

        let member = members.next().unwrap().unwrap();
        assert_eq!(member.name(), b"0123456789abcde");
        assert_eq!(member.data(data).unwrap(), &b"odd"[..]);

        let member = members.next().unwrap().unwrap();
        assert_eq!(member.name(), b"0123456789abcdef");
        assert_eq!(member.data(data).unwrap(), &b"even"[..]);

        assert!(members.next().is_none());
    }

    #[test]
    fn big_archive() {
        let data = b"\
            <bigaf>\n\
            250                 \
            0                   \
            0                   \
            128                 \
            128                 \
            0                   \
            0                   \
            250                 \
            0                   \
            0           \
            0           \
            0           \
            644         \
            7   \
            nothing `\n\
            48                  \
            0                   \
            128                 \
            0           \
            0           \
            0           \
            0           \
            0   \
            `\n\
            1                   \
            128                 \
            nothing ";
        let data = &data[..];
        let archive = ArchiveFile::parse(data).unwrap();
        assert_eq!(archive.kind(), ArchiveKind::Xcoff);
        let mut members = archive.members();

        // Object header
        let member = members.next().unwrap().unwrap();
        assert_eq!(member.name(), b"nothing");

        // Member table header
        let member = members.next().unwrap().unwrap();
        assert_eq!(member.name(), b"");
    
        assert!(members.next().is_none());
    }
}
