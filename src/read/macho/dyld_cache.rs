use crate::read::{Error, ReadError, ReadRef, Result};
use crate::{macho, Architecture, Bytes, Endian, Endianness};

use super::{MachOFile32, MachOFile64};

/// A parsed representation of the dyld shared cache.
#[derive(Debug)]
pub struct DyldCache<'data, E = Endianness, R = &'data [u8]>
where
    E: Endian,
    R: ReadRef<'data>,
{
    endian: E,
    data: R,
    first_mapping_address: u64,
    header: &'data macho::DyldCacheHeader<E>,
    arch: Architecture,
    is_64: bool,
}

impl<'data, E, R> DyldCache<'data, E, R>
where
    E: Endian,
    R: ReadRef<'data>,
{
    /// Parse the raw dyld shared cache data.
    pub fn parse(data: R) -> Result<Self> {
        let mut offset = 0;
        let header = data
            .read::<macho::DyldCacheHeader<E>>(&mut offset)
            .read_error("Invalid dyld cache header size or alignment")?;

        let (arch, is_64, endianness) = match Self::parse_magic(&header.magic) {
            Some(props) => props,
            None => return Err(Error("Unrecognized magic value")),
        };

        let is_big_endian = endianness.is_big_endian();
        let endian = E::from_big_endian(is_big_endian).read_error("Unsupported Mach-O endian")?;
        let mapping_count = header.mapping_count.get(endian);
        if mapping_count == 0 {
            return Err(Error("No mappings in dyld cache"));
        }

        let mapping_offset = header.mapping_offset.get(endian) as u64;
        let first_mapping = data
            .read_at::<macho::DyldCacheMappingInfo<E>>(mapping_offset)
            .read_error("Couldn't read macho::DyldCacheMappingInfo")?;
        if first_mapping.file_offset.get(endian) != 0 {
            // dsc_extractor.cpp bails out in this case, in forEachDylibInCache
            return Err(Error(
                "Unexpected non-zero first mapping file offset in dyld cache",
            ));
        }

        let first_mapping_address = first_mapping.address.get(endian);

        Ok(DyldCache {
            endian,
            header,
            first_mapping_address,
            data,
            arch,
            is_64,
        })
    }

    /// Returns (arch, is_64, endianness) based on the magic string.
    fn parse_magic(magic: &[u8; 16]) -> Option<(Architecture, bool, Endianness)> {
        Some(match magic {
            b"dyld_v1    i386\0" => (Architecture::I386, false, Endianness::Little),
            b"dyld_v1  x86_64\0" => (Architecture::X86_64, true, Endianness::Little),
            b"dyld_v1 x86_64h\0" => (Architecture::X86_64, true, Endianness::Little),
            b"dyld_v1     ppc\0" => (Architecture::PowerPc, false, Endianness::Big),
            b"dyld_v1   armv6\0" => (Architecture::Arm, false, Endianness::Little),
            b"dyld_v1   armv7\0" => (Architecture::Arm, false, Endianness::Little),
            b"dyld_v1  armv7f\0" => (Architecture::Arm, false, Endianness::Little),
            b"dyld_v1  armv7s\0" => (Architecture::Arm, false, Endianness::Little),
            b"dyld_v1  armv7k\0" => (Architecture::Arm, false, Endianness::Little),
            b"dyld_v1   arm64\0" => (Architecture::Aarch64, true, Endianness::Little),
            b"dyld_v1  arm64e\0" => (Architecture::Aarch64, true, Endianness::Little),
            _ => return None,
        })
    }

    /// Get the architecture type of the file.
    pub fn architecture(&self) -> Architecture {
        self.arch
    }

    /// Get the endianness of the file.
    #[inline]
    pub fn endianness(&self) -> Endianness {
        if self.is_little_endian() {
            Endianness::Little
        } else {
            Endianness::Big
        }
    }

    /// Return true if the file is little endian, false if it is big endian.
    pub fn is_little_endian(&self) -> bool {
        self.endian.is_little_endian()
    }

    /// Return true if the file can contain 64-bit addresses.
    pub fn is_64(&self) -> bool {
        self.is_64
    }

    /// Iterate over the images in this cache.
    pub fn iter_images<'cache>(&'cache self) -> DyldCacheImageIterator<'data, 'cache, E, R> {
        let images_offset = self.header.images_offset.get(self.endian) as u64;
        let images_count = self.header.images_count.get(self.endian);
        DyldCacheImageIterator {
            cache: self,
            images_count,
            next_image_index: 0,
            next_image_offset: images_offset,
        }
    }
}

/// An iterator over all the images (dylibs) in the dyld shared cache.
#[derive(Debug)]
pub struct DyldCacheImageIterator<'data, 'cache, E = Endianness, R = &'data [u8]>
where
    E: Endian,
    R: ReadRef<'data>,
{
    cache: &'cache DyldCache<'data, E, R>,
    images_count: u32,
    next_image_index: u32,
    next_image_offset: u64,
}

impl<'data, 'cache, E, R> DyldCacheImageIterator<'data, 'cache, E, R>
where
    E: Endian,
    R: ReadRef<'data>,
{
    /// Advance the iterator and return the current image.
    pub fn next(&mut self) -> Result<Option<DyldCacheImage<'data, E, R>>> {
        if self.next_image_index >= self.images_count {
            return Ok(None);
        }
        self.next_image_index += 1;
        let data = self.cache.data;
        let image_info = data
            .read::<macho::DyldCacheImageInfo<E>>(&mut self.next_image_offset)
            .read_error("Couldn't read macho::DyldCacheImageInfo")?;
        Ok(Some(DyldCacheImage {
            endian: self.cache.endian,
            is_64: self.cache.is_64,
            data,
            first_mapping_address: self.cache.first_mapping_address,
            image_info,
        }))
    }
}

/// One image (dylib) from inside the dyld shared cache.
#[derive(Debug)]
pub struct DyldCacheImage<'data, E = Endianness, R = &'data [u8]>
where
    E: Endian,
    R: ReadRef<'data>,
{
    endian: E,
    is_64: bool,
    data: R,
    first_mapping_address: u64,
    image_info: &'data macho::DyldCacheImageInfo<E>,
}

impl<'data, E, R> DyldCacheImage<'data, E, R>
where
    E: Endian,
    R: ReadRef<'data>,
{
    /// The file system path of this image.
    pub fn path(&self) -> Result<&'data str> {
        // The longest path I've seen is 164 bytes long. In theory paths could be longer than 256.
        const MAX_PATH_LEN: u64 = 256;

        let path_offset = self.image_info.path_file_offset.get(self.endian) as u64;
        let slice_containing_path = self
            .data
            .read_bytes_at(path_offset, MAX_PATH_LEN)
            .read_error("Couldn't read path")?;
        let path = Bytes(slice_containing_path).read_string().read_error(
            "Couldn't read path string (didn't find nul byte within first 256 bytes)",
        )?;
        // The path should always be ascii, so from_utf8 should alway succeed.
        let path = core::str::from_utf8(path).map_err(|_| Error("Path string not valid utf-8"))?;
        Ok(path)
    }

    /// The offset in the dyld cache file where this image starts.
    pub fn offset(&self) -> u64 {
        self.image_info.address.get(self.endian) - self.first_mapping_address
    }

    /// Parse this image into an Object.
    pub fn parse_object(&self) -> Result<crate::File<'data, R>> {
        if !self.is_64 {
            let file = MachOFile32::<Endianness, R>::parse_at_offset(self.data, self.offset())?;
            Ok(crate::File::from_macho_32(file))
        } else {
            let file = MachOFile64::<Endianness, R>::parse_at_offset(self.data, self.offset())?;
            Ok(crate::File::from_macho_64(file))
        }
    }
}
