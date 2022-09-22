//! Support for archive files.

use core::convert::TryInto;

use crate::archive;
use crate::read::{self, Error, ReadError, ReadRef};

/// Discriminated union for multiple type headers
#[derive(Debug, Clone, Copy)]
enum MemberHeader<'data> {
    /// GNU or BSD style header
    SystemV(&'data archive::Header),
    /// AIX style big archive header
    AixBig(&'data archive::AixHeader),
}

/// The kind of archive format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ArchiveKind {
    /// There are no special files that indicate the archive format.
    Unknown,
    /// The GNU (or System V) archive format.
    Gnu,
    /// The GNU (or System V) archive format with 64-bit symbol table.
    Gnu64,
    /// The BSD archive format.
    Bsd,
    /// The BSD archive format with 64-bit symbol table.
    ///
    /// This is used for Darwin.
    Bsd64,
    /// The Windows COFF archive format.
    Coff,
    /// The AIX big archive format.
    AixBig,
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
        let kind = if magic == &archive::MAGIC {
            ArchiveKind::Unknown
        } else if magic == &archive::AIX_BIG_MAGIC {
            ArchiveKind::AixBig
        } else {
            return Err(Error("Unsupported archive identifier"));
        };

        let mut file = ArchiveFile {
            data,
            offset: tail,
            len,
            kind,
            symbols: (0, 0),
            names: &[],
        };

        if file.kind == ArchiveKind::AixBig {
            // The fixed length header is located just after magic number.
            let file_header = data.read::<archive::AIXFileHeader>(&mut tail)
                .read_error("Invalid AIX big archive file header")?;

            // Read the span of symbol table.
            let symtbl64 = parse_u64_digits(&file_header.gst64off, 10)
                .read_error("Invalid offset to 64-bit symbol table in AIX big archive")?;
            if symtbl64 > 0 {
                file.symbols = (symtbl64, len);
            } else {
                let symtbl = parse_u64_digits(&file_header.gstoff, 10)
                    .read_error("Invalid offset to symbol table in AIX big archive")?;
                if symtbl > 0 {
                    file.symbols = (symtbl, len);
                }
            }

            // Big archive member table lists file entries with offsets and names. To avoid
            // potential infinite loop (members are double-linked list), the iterator goes
            // through the table instead of real members.
            let mut member_table_offset = parse_u64_digits(&file_header.memoff, 10)
                .read_error("Invalid offset for member table of AIX big archive")?;
            if member_table_offset > 0 {
                // The table itself is also a file with header.
                let header = data
                    .read::<archive::AixHeader>(&mut member_table_offset)
                    .read_error("Invalid AIX big archive member header")?;
                let terminator = data
                    .read_bytes(&mut member_table_offset, 2)
                    .read_error("Invalid AIX big archive terminator")?;
                if terminator != archive::TERMINATOR {
                    return Err(Error("Invalid AIX big archive terminator"));
                }

                // Structure of member table:
                // Number of entries (20 bytes)
                // Offsets of each entry (20*N bytes)
                // Names string table (the rest of bytes to fill size defined in header)
                let table_size = parse_u64_digits(&header.size, 10)
                    .read_error("Invalid AIX big archive member size")?;
                let members_count = data
                    .read_bytes_at(member_table_offset, 30)
                    .ok()
                    .and_then(|bytes| parse_u64_digits(bytes, 10))
                    .read_error("Invalid member count in AIX big archive")?;
                file.offset = member_table_offset.checked_add(20)
                    .read_error("AIX big archive offset overflow")?;
                let member_offsets_size = members_count.checked_mul(20)
                    .read_error("AIX big archive length overflow")?;
                file.len = member_offsets_size.checked_add(file.offset)
                    .read_error("AIX big archive length overflow")?;
                let names_size = table_size
                    .checked_sub(member_offsets_size)
                    .and_then(|size| size.checked_sub(20))
                    .read_error("AIX big archive string table size overflow")?;
                file.names = data.read_bytes_at(file.len, names_size)
                    .read_error("Invalid AIX big archive member name list")?;
            } else {
                // The offset would be zero if archive contains no file.
                file.offset = 0;
                file.len = 0;
            }
            return Ok(file);
        } else if tail < len {
            // The first few members may be special, so parse them.
            // GNU has:
            // - "/" or "/SYM64/": symbol table (optional)
            // - "//": names table (optional)
            // COFF has:
            // - "/": first linker member
            // - "/": second linker member
            // - "//": names table
            // BSD has:
            // - "__.SYMDEF" or "__.SYMDEF SORTED": symbol table (optional)
            // BSD 64-bit has:
            // - "__.SYMDEF_64" or "__.SYMDEF_64 SORTED": symbol table (optional)
            // BSD may use the extended name for the symbol table. This is handled
            // by `ArchiveMember::parse`.
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
            } else if member.name == b"/SYM64/" {
                // GNU 64-bit symbol table.
                file.kind = ArchiveKind::Gnu64;
                file.symbols = member.file_range();
                file.offset = tail;

                if tail < len {
                    let member = ArchiveMember::parse(data, &mut tail, &[], file.kind)?;
                    if member.name == b"//" {
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
            } else if member.name == b"__.SYMDEF_64" || member.name == b"__.SYMDEF_64 SORTED" {
                // BSD 64-bit symbol table.
                file.kind = ArchiveKind::Bsd64;
                file.symbols = member.file_range();
                file.offset = tail;
            } else {
                // TODO: This could still be a BSD file. We leave this as unknown for now.
            }
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
    header: MemberHeader<'data>,
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
        match kind {
            ArchiveKind::AixBig => Self::parse_aixbig(data, offset, &names),
            _ => Self::parse_systemv(data, offset, &names),
        }
    }

    /// Parse with SystemV style.
    fn parse_systemv<R: ReadRef<'data>>(
        data: R,
        offset: &mut u64,
        names: &'data [u8],
    ) -> read::Result<Self> {
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
            header: MemberHeader::SystemV(header),
            name,
            offset: file_offset,
            size: file_size,
        })
    }

    /// Parse with AIX big archive style.
    fn parse_aixbig<R: ReadRef<'data>>(
        data: R,
        offset: &mut u64,
        _names: &'data [u8],
    ) -> read::Result<Self> {
        // The format was described at
        // https://www.ibm.com/docs/en/aix/7.3?topic=formats-ar-file-format-big
        let file_offset_dec = data.read_bytes(offset, 20)
            .read_error("Invalid AIX big archive file member offset")?;
        let mut file_offset = parse_u64_digits(file_offset_dec, 10)
            .read_error("Invalid AIX big archive file member offset")?;
        let header = data
            .read::<archive::AixHeader>(&mut file_offset)
            .read_error("Invalid AIX big archive member header")?;
        let name_length = parse_u64_digits(&header.namlen, 10)
            .read_error("Invalid AIX big archive member name length")?;
        let name = data
            .read_bytes(&mut file_offset, name_length)
            .read_error("Invalid AIX big archive member name")?;

        // The actual data for a file member begins at the first even-byte boundary beyond the
        // member header and continues for the number of bytes specified by the ar_size field. The
        // ar command inserts null bytes for padding where necessary.
        if file_offset & 1 != 0 {
            file_offset = file_offset.saturating_add(1);
        }
        // Because of the even-byte boundary, we have to read and check terminator after header.
        let terminator = data
            .read_bytes(&mut file_offset, 2)
            .read_error("Invalid AIX big archive head terminator")?;
        if terminator != archive::TERMINATOR {
            return Err(Error("Invalid AIX big archive terminator"));
        }

        let file_size = parse_u64_digits(&header.size, 10)
            .read_error("Invalid archive member size in AIX big archive")?;
        Ok(ArchiveMember {
            header: MemberHeader::AixBig(header),
            name,
            offset: file_offset,
            size: file_size,
        })
    }

    /// Return the raw header for SystemV archives.
    #[inline]
    pub fn header(&self) -> Option<&'data archive::Header> {
        match self.header {
            MemberHeader::SystemV(head) => Some(&head),
            _ => None,
        }
    }

    /// Return the raw header for AIX big archives.
    #[inline]
    pub fn aix_header(&self) -> Option<&'data archive::AixHeader> {
        match self.header {
            MemberHeader::AixBig(head) => Some(&head),
            _ => None,
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
        match &self.header {
            MemberHeader::AixBig(head) => parse_u64_digits(&head.date, 10),
            MemberHeader::SystemV(head) => parse_u64_digits(&head.date, 10),
        }
    }

    /// Parse the user ID from the header.
    #[inline]
    pub fn uid(&self) -> Option<u64> {
        match &self.header {
            MemberHeader::AixBig(head) => parse_u64_digits(&head.uid, 10),
            MemberHeader::SystemV(head) => parse_u64_digits(&head.uid, 10),
        }
    }

    /// Parse the group ID from the header.
    #[inline]
    pub fn gid(&self) -> Option<u64> {
        match &self.header {
            MemberHeader::AixBig(head) => parse_u64_digits(&head.gid, 10),
            MemberHeader::SystemV(head) => parse_u64_digits(&head.gid, 10),
        }
    }

    /// Parse the file mode from the header.
    #[inline]
    pub fn mode(&self) -> Option<u64> {
        match &self.header {
            MemberHeader::AixBig(head) => parse_u64_digits(&head.mode, 8),
            MemberHeader::SystemV(head) => parse_u64_digits(&head.mode, 8),
        }
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
            /SYM64/                                         4         `\n\
            0000";
        let archive = ArchiveFile::parse(&data[..]).unwrap();
        assert_eq!(archive.kind(), ArchiveKind::Gnu64);

        let data = b"\
            !<arch>\n\
            /SYM64/                                         4         `\n\
            0000\
            //                                              4         `\n\
            0000";
        let archive = ArchiveFile::parse(&data[..]).unwrap();
        assert_eq!(archive.kind(), ArchiveKind::Gnu64);

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
            __.SYMDEF_64                                    4         `\n\
            0000";
        let archive = ArchiveFile::parse(&data[..]).unwrap();
        assert_eq!(archive.kind(), ArchiveKind::Bsd64);

        let data = b"\
            !<arch>\n\
            #1/12                                           16        `\n\
            __.SYMDEF_640000";
        let archive = ArchiveFile::parse(&data[..]).unwrap();
        assert_eq!(archive.kind(), ArchiveKind::Bsd64);

        let data = b"\
            !<arch>\n\
            #1/19                                           23        `\n\
            __.SYMDEF_64 SORTED0000";
        let archive = ArchiveFile::parse(&data[..]).unwrap();
        assert_eq!(archive.kind(), ArchiveKind::Bsd64);

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

        let data = b"\
            <bigaf>\n\
            0                   0                   \
            0                   0                   \
            0                   128                 \
            6                   0                   \
            0                   \0\0\0\0\0\0\0\0\0\0\0\0\
            \0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
            \0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
            \0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let archive = ArchiveFile::parse(&data[..]).unwrap();
        assert_eq!(archive.kind(), ArchiveKind::AixBig);
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
    fn aix_names() {
        let data = b"\
            <bigaf>\n\
            396                 0                   0                   \
            128                 262                 0                   \
            4                   262                 0                   \
            1662610370  223         1           644         16  \
            0123456789abcdef`\nord\n\
            4                   396                 128                 \
            1662610374  223         1           644         16  \
            fedcba9876543210`\nrev\n\
            94                  0                   262                 \
            0           0           0           0           0   \
            `\n2                   128                 \
            262                 0123456789abcdef\0fedcba9876543210\0";
        let data = &data[..];
        let archive = ArchiveFile::parse(data).unwrap();
        assert_eq!(archive.kind(), ArchiveKind::AixBig);
        assert_eq!(archive.names, b"0123456789abcdef\0fedcba9876543210\0");
        let mut members = archive.members();

        let member = members.next().unwrap().unwrap();
        assert_eq!(member.name(), b"0123456789abcdef");
        assert_eq!(member.data(data).unwrap(), &b"ord\n"[..]);

        let member = members.next().unwrap().unwrap();
        assert_eq!(member.name(), b"fedcba9876543210");
        assert_eq!(member.data(data).unwrap(), &b"rev\n"[..]);

        assert!(members.next().is_none());
    }
}
