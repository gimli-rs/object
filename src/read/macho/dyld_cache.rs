use alloc::{boxed::Box, vec::Vec};
use core::fmt::{self, Debug};
use core::iter;
use core::{mem, slice};

use crate::endian::{Endian, Endianness, U16, U32, U64};
use crate::macho;
use crate::read::{Architecture, Error, File, ReadError, ReadRef, Result};

/// A parsed representation of the dyld shared cache.
#[derive(Debug)]
pub struct DyldCache<'data, E = Endianness, R = &'data [u8]>
where
    E: Endian,
    R: ReadRef<'data>,
{
    endian: E,
    data: R,
    subcaches: Vec<DyldSubCache<'data, E, R>>,
    mappings: DyldCacheMappingSlice<'data, E, R>,
    images: &'data [macho::DyldCacheImageInfo<E>],
    arch: Architecture,
}

/// Information about a subcache.
#[derive(Debug)]
pub struct DyldSubCache<'data, E = Endianness, R = &'data [u8]>
where
    E: Endian,
    R: ReadRef<'data>,
{
    data: R,
    mappings: DyldCacheMappingSlice<'data, E, R>,
}

/// Information about a mapping.
#[derive(Clone, Copy)]
pub enum DyldCacheMapping<'data, E = Endianness, R = &'data [u8]>
where
    E: Endian,
    R: ReadRef<'data>,
{
    /// Corresponds to struct dyld_cache_mapping_info from dyld_cache_format.h.
    V1 {
        /// The mapping endianness
        endian: E,
        /// The mapping data
        data: R,
        /// The mapping information
        info: &'data macho::DyldCacheMappingInfo<E>,
    },
    /// Corresponds to struct dyld_cache_mapping_and_slide_info from dyld_cache_format.h.
    V2 {
        /// The mapping endianness
        endian: E,
        /// The mapping data
        data: R,
        /// The mapping information
        info: &'data macho::DyldCacheMappingAndSlideInfo<E>,
    },
}

impl<'data, E, R> Debug for DyldCacheMapping<'data, E, R>
where
    E: Endian,
    R: ReadRef<'data>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DyldCacheMapping")
            .field("address", &format_args!("{:#x}", self.address()))
            .field("size", &format_args!("{:#x}", self.size()))
            .field("file_offset", &format_args!("{:#x}", self.file_offset()))
            .field("max_prot", &format_args!("{:#x}", self.max_prot()))
            .field("init_prot", &format_args!("{:#x}", self.init_prot()))
            .finish()
    }
}

impl<'data, E, R> DyldCacheMapping<'data, E, R>
where
    E: Endian,
    R: ReadRef<'data>,
{
    /// The mapping address
    pub fn address(&self) -> u64 {
        match self {
            Self::V1 {
                endian,
                data: _,
                info,
            } => info.address.get(*endian),
            Self::V2 {
                endian,
                data: _,
                info,
            } => info.address.get(*endian),
        }
    }

    /// The mapping size
    pub fn size(&self) -> u64 {
        match self {
            Self::V1 {
                endian,
                data: _,
                info,
            } => info.size.get(*endian),
            Self::V2 {
                endian,
                data: _,
                info,
            } => info.size.get(*endian),
        }
    }

    /// The mapping file offset
    pub fn file_offset(&self) -> u64 {
        match self {
            Self::V1 {
                endian,
                data: _,
                info,
            } => info.file_offset.get(*endian),
            Self::V2 {
                endian,
                data: _,
                info,
            } => info.file_offset.get(*endian),
        }
    }

    /// The mapping maximum protection
    pub fn max_prot(&self) -> u32 {
        match self {
            Self::V1 {
                endian,
                data: _,
                info,
            } => info.max_prot.get(*endian),
            Self::V2 {
                endian,
                data: _,
                info,
            } => info.max_prot.get(*endian),
        }
    }

    /// The mapping initial protection
    pub fn init_prot(&self) -> u32 {
        match self {
            Self::V1 {
                endian,
                data: _,
                info,
            } => info.init_prot.get(*endian),
            Self::V2 {
                endian,
                data: _,
                info,
            } => info.init_prot.get(*endian),
        }
    }

    /// The mapping data
    pub fn data(&self) -> &'data [u8] {
        match self {
            Self::V1 { endian, data, info } => data
                .read_bytes_at(info.file_offset.get(*endian), info.size.get(*endian))
                .unwrap(),
            Self::V2 { endian, data, info } => data
                .read_bytes_at(info.file_offset.get(*endian), info.size.get(*endian))
                .unwrap(),
        }
    }

    /// Relocations for the mapping
    pub fn relocations(&self) -> DyldCacheRelocationMappingIterator<'data, E, R> {
        match self {
            Self::V1 { .. } => DyldCacheRelocationMappingIterator::empty(),
            Self::V2 { endian, data, info } => {
                if let Some(slide) = info.slide(*endian, *data).unwrap() {
                    DyldCacheRelocationMappingIterator::slide(*data, *endian, *info, slide)
                } else {
                    DyldCacheRelocationMappingIterator::empty()
                }
            }
        }
    }
}

/// An iterator over relocations in a mapping
#[derive(Debug)]
pub enum DyldCacheRelocationMappingIterator<'data, E = Endianness, R = &'data [u8]>
where
    E: Endian,
    R: ReadRef<'data>,
{
    /// Empty
    Empty,
    /// Slide
    Slide {
        /// The mapping data
        data: R,
        /// Endian
        endian: E,
        /// The mapping information
        info: &'data macho::DyldCacheMappingAndSlideInfo<E>,
        /// The mapping slide information
        slide: DyldCacheSlideInfoSlice<'data, E>,
        /// Page starts
        page_index: u32,
        /// Page iterator
        iter: Option<DyldCacheRelocationPageIterator<'data, E, R>>,
    },
}

impl<'data, E, R> DyldCacheRelocationMappingIterator<'data, E, R>
where
    E: Endian,
    R: ReadRef<'data>,
{
    /// Slide iterator
    pub fn slide(
        data: R,
        endian: E,
        info: &'data macho::DyldCacheMappingAndSlideInfo<E>,
        slide: DyldCacheSlideInfoSlice<'data, E>,
    ) -> Self {
        Self::Slide {
            data,
            endian,
            info,
            slide,
            page_index: 0,
            iter: None,
        }
    }

    /// Empty iterator
    pub fn empty() -> Self {
        Self::Empty
    }
}

impl<'data, E, R> Iterator for DyldCacheRelocationMappingIterator<'data, E, R>
where
    E: Endian,
    R: ReadRef<'data>,
{
    type Item = DyldRelocation;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Empty => None,
            Self::Slide {
                data,
                endian,
                info,
                slide,
                page_index,
                iter,
            } => loop {
                if let Some(reloc) = iter.as_mut().and_then(|iter| iter.next()) {
                    return Some(reloc);
                }

                match slide {
                    DyldCacheSlideInfoSlice::V5(slide, page_starts) => {
                        if *page_index < slide.page_starts_count.get(*endian) {
                            let page_start = page_starts[*page_index as usize].get(*endian);

                            if page_start != macho::DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE {
                                *iter = Some(DyldCacheRelocationPageIterator::V5 {
                                    data: *data,
                                    endian: *endian,
                                    slide: *slide,
                                    page_offset: Some(
                                        info.file_offset.get(*endian)
                                            + (*page_index as u64
                                                * slide.page_size.get(*endian) as u64)
                                            + page_start as u64,
                                    ),
                                });
                            } else {
                                *iter = None;
                            }

                            *page_index += 1;
                        } else {
                            return None;
                        }
                    }
                }
            },
        }
    }
}

/// A versioned iterator over relocations in a page
#[derive(Debug)]
pub enum DyldCacheRelocationPageIterator<'data, E = Endianness, R = &'data [u8]>
where
    E: Endian,
    R: ReadRef<'data>,
{
    /// Corresponds to struct dyld_cache_slide_info5 from dyld_cache_format.h.
    V5 {
        /// The mapping data
        data: R,
        /// Endian
        endian: E,
        /// The mapping slide information
        slide: &'data macho::DyldCacheSlideInfo5<E>,
        /// The current offset into the page
        page_offset: Option<u64>,
    },
}

impl<'data, E, R> Iterator for DyldCacheRelocationPageIterator<'data, E, R>
where
    E: Endian,
    R: ReadRef<'data>,
{
    type Item = DyldRelocation;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::V5 {
                data,
                endian,
                slide,
                page_offset,
            } => {
                if let Some(offset) = *page_offset {
                    let pointer: macho::DyldCacheSlidePointer5 =
                        data.read_at::<U64<E>>(offset).unwrap().get(*endian).into();

                    let next = pointer.next() as u64;
                    if next == 0 {
                        *page_offset = None;
                    } else {
                        *page_offset = Some(offset + (next * 8));
                    }

                    let value_add = slide.value_add.get(*endian);
                    let value = pointer.value(value_add);
                    let auth = pointer.auth();
                    Some(DyldRelocation {
                        offset,
                        value,
                        auth,
                    })
                } else {
                    None
                }
            }
        }
    }
}

/// A cache mapping relocation.
pub struct DyldRelocation {
    /// The offset of the relocation within the mapping
    pub offset: u64,
    /// The relocation value
    pub value: u64,
    /// The value auth context
    pub auth: Option<macho::Ptrauth>,
}

impl Debug for DyldRelocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DyldRelocation")
            .field("offset", &format_args!("{:#x}", self.offset))
            .field("value", &format_args!("{:#x}", self.value))
            .field("auth", &self.auth)
            .finish()
    }
}

/// A slice of structs describing each subcache. The struct gained
/// an additional field (the file suffix) in dyld-1042.1 (macOS 13 / iOS 16),
/// so this is an enum of the two possible slice types.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum DyldSubCacheSlice<'data, E: Endian> {
    /// V1, used between dyld-940 and dyld-1042.1.
    V1(&'data [macho::DyldSubCacheEntryV1<E>]),
    /// V2, used since dyld-1042.1.
    V2(&'data [macho::DyldSubCacheEntryV2<E>]),
}

/// An enum of arrays containing dyld cache mappings
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum DyldCacheMappingSlice<'data, E = Endianness, R = &'data [u8]>
where
    E: Endian,
    R: ReadRef<'data>,
{
    /// Corresponds to an array of struct dyld_cache_mapping_info
    V1 {
        /// The mapping endianness
        endian: E,
        /// The mapping data
        data: R,
        /// The slice of mapping info
        info: &'data [macho::DyldCacheMappingInfo<E>],
    },
    /// Corresponds to an array of struct dyld_cache_mapping_and_slide_info
    V2 {
        /// The mapping endianness
        endian: E,
        /// The mapping data
        data: R,
        /// The slice of mapping info
        info: &'data [macho::DyldCacheMappingAndSlideInfo<E>],
    },
}

impl<'data, E, R> DyldCacheMappingSlice<'data, E, R>
where
    E: Endian,
    R: ReadRef<'data>,
{
    /// Return a slice iterator
    pub fn iter(self) -> DyldCacheMappingIterator<'data, E, R> {
        match self {
            Self::V1 { endian, data, info } => DyldCacheMappingIterator::V1 {
                endian,
                data,
                iter: info.iter(),
            },
            Self::V2 { endian, data, info } => DyldCacheMappingIterator::V2 {
                endian,
                data,
                iter: info.iter(),
            },
        }
    }

    /// Find the file offset of the image by looking up its address in the mappings.
    pub fn address_to_file_offset(&self, address: u64) -> Option<u64> {
        for mapping in self.iter() {
            let mapping_address = mapping.address();
            if address >= mapping_address && address < mapping_address.wrapping_add(mapping.size())
            {
                return Some(address - mapping_address + mapping.file_offset());
            }
        }
        None
    }
}

/// An iterator over all the mappings in a dyld shared cache.
#[derive(Debug)]
pub enum DyldCacheMappingIterator<'data, E = Endianness, R = &'data [u8]>
where
    E: Endian,
    R: ReadRef<'data>,
{
    /// Corresponds to struct dyld_cache_mapping_info from dyld_cache_format.h.
    V1 {
        /// The mapping endianness
        endian: E,
        /// The mapping data
        data: R,
        /// The mapping info iterator
        iter: slice::Iter<'data, macho::DyldCacheMappingInfo<E>>,
    },
    /// Corresponds to struct dyld_cache_mapping_and_slide_info from dyld_cache_format.h.
    V2 {
        /// The mapping endianness
        endian: E,
        /// The mapping data
        data: R,
        /// The mapping info iterator
        iter: slice::Iter<'data, macho::DyldCacheMappingAndSlideInfo<E>>,
    },
}

impl<'data, E, R> Iterator for DyldCacheMappingIterator<'data, E, R>
where
    E: Endian,
    R: ReadRef<'data>,
{
    type Item = DyldCacheMapping<'data, E, R>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::V1 { endian, data, iter } => {
                let info = iter.next()?;
                Some(DyldCacheMapping::V1 {
                    endian: *endian,
                    data: *data,
                    info,
                })
            }
            Self::V2 { endian, data, iter } => {
                let info = iter.next()?;
                Some(DyldCacheMapping::V2 {
                    endian: *endian,
                    data: *data,
                    info,
                })
            }
        }
    }
}

/// An enum of arrays containing dyld cache mappings
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum DyldCacheSlideInfoSlice<'data, E: Endian> {
    /// Corresponds to struct dyld_cache_slide_info5 from dyld_cache_format.h.
    V5(&'data macho::DyldCacheSlideInfo5<E>, &'data [U16<E>]),
}

impl<E: Endian> Debug for DyldCacheSlideInfoSlice<'_, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V5(info, _) => f
                .debug_struct("DyldCacheSlideInfoSlice::V5")
                .field("info", info)
                .finish(),
        }
    }
}

// This is the offset of the end of the images_across_all_subcaches_count field.
const MIN_HEADER_SIZE_SUBCACHES_V1: u32 = 0x1c8;

// This is the offset of the end of the cacheSubType field.
// This field comes right after the images_across_all_subcaches_count field,
// and we don't currently have it in our definition of the DyldCacheHeader type.
const MIN_HEADER_SIZE_SUBCACHES_V2: u32 = 0x1d0;

impl<'data, E, R> DyldCache<'data, E, R>
where
    E: Endian,
    R: ReadRef<'data>,
{
    /// Parse the raw dyld shared cache data.
    ///
    /// For shared caches from macOS 12 / iOS 15 and above, the subcache files need to be
    /// supplied as well, in the correct order, with the `.symbols` subcache last (if present).
    /// For example, `data` would be the data for `dyld_shared_cache_x86_64`,
    /// and `subcache_data` would be the data for `[dyld_shared_cache_x86_64.1, dyld_shared_cache_x86_64.2, ...]`.
    pub fn parse(data: R, subcache_data: &[R]) -> Result<Self> {
        let header = macho::DyldCacheHeader::parse(data)?;
        let (arch, endian) = header.parse_magic()?;
        let mappings = header.mappings(endian, data)?;

        let symbols_subcache_uuid = header.symbols_subcache_uuid(endian);
        let subcaches_info = header.subcaches(endian, data)?;
        let subcaches_count = match subcaches_info {
            Some(DyldSubCacheSlice::V1(subcaches)) => subcaches.len(),
            Some(DyldSubCacheSlice::V2(subcaches)) => subcaches.len(),
            None => 0,
        };
        if subcache_data.len() != subcaches_count + symbols_subcache_uuid.is_some() as usize {
            return Err(Error("Incorrect number of SubCaches"));
        }

        // Split out the .symbols subcache data from the other subcaches.
        let (symbols_subcache_data_and_uuid, subcache_data) =
            if let Some(symbols_uuid) = symbols_subcache_uuid {
                let (sym_data, rest_data) = subcache_data.split_last().unwrap();
                (Some((*sym_data, symbols_uuid)), rest_data)
            } else {
                (None, subcache_data)
            };

        // Read the regular SubCaches, if present.
        let mut subcaches = Vec::new();
        if let Some(subcaches_info) = subcaches_info {
            let (v1, v2) = match subcaches_info {
                DyldSubCacheSlice::V1(s) => (s, &[][..]),
                DyldSubCacheSlice::V2(s) => (&[][..], s),
            };
            let uuids = v1.iter().map(|e| &e.uuid).chain(v2.iter().map(|e| &e.uuid));
            for (&data, uuid) in subcache_data.iter().zip(uuids) {
                let header = macho::DyldCacheHeader::<E>::parse(data)?;
                if &header.uuid != uuid {
                    return Err(Error("Unexpected SubCache UUID"));
                }
                let mappings = header.mappings(endian, data)?;
                subcaches.push(DyldSubCache { data, mappings });
            }
        }

        // Read the .symbols SubCache, if present.
        // Other than the UUID verification, the symbols SubCache is currently unused.
        let _symbols_subcache = match symbols_subcache_data_and_uuid {
            Some((data, uuid)) => {
                let header = macho::DyldCacheHeader::<E>::parse(data)?;
                if header.uuid != uuid {
                    return Err(Error("Unexpected .symbols SubCache UUID"));
                }
                let mappings = header.mappings(endian, data)?;
                Some(DyldSubCache { data, mappings })
            }
            None => None,
        };

        let images = header.images(endian, data)?;
        Ok(DyldCache {
            endian,
            data,
            subcaches,
            mappings,
            images,
            arch,
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

    /// Iterate over the images in this cache.
    pub fn images<'cache>(&'cache self) -> DyldCacheImageIterator<'data, 'cache, E, R> {
        DyldCacheImageIterator {
            cache: self,
            iter: self.images.iter(),
        }
    }

    /// Return all the mappings in this cache.
    pub fn mappings<'cache>(
        &'cache self,
    ) -> Box<dyn Iterator<Item = DyldCacheMapping<'data, E, R>> + 'cache> {
        let mut mappings: Box<dyn Iterator<Item = DyldCacheMapping<'data, E, R>>> =
            Box::new(self.mappings.iter());

        for subcache in &self.subcaches {
            mappings = Box::new(mappings.chain(subcache.mappings.iter()));
        }

        mappings
    }

    /// Return all the relocations in this cache.
    pub fn relocations<'cache>(&'cache self) -> Box<dyn Iterator<Item = DyldRelocation> + 'cache> {
        let mut relocations: Box<dyn Iterator<Item = DyldRelocation>> = Box::new(iter::empty());

        for mapping in self.mappings.iter() {
            relocations = Box::new(relocations.chain(mapping.relocations()));
        }

        for subcache in &self.subcaches {
            for mapping in subcache.mappings.iter() {
                relocations = Box::new(relocations.chain(mapping.relocations()));
            }
        }

        relocations
    }

    /// Find the address in a mapping and return the cache or subcache data it was found in,
    /// together with the translated file offset.
    pub fn data_and_offset_for_address(&self, address: u64) -> Option<(R, u64)> {
        if let Some(file_offset) = self.mappings.address_to_file_offset(address) {
            return Some((self.data, file_offset));
        }
        for subcache in &self.subcaches {
            if let Some(file_offset) = subcache.mappings.address_to_file_offset(address) {
                return Some((subcache.data, file_offset));
            }
        }
        None
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
    iter: slice::Iter<'data, macho::DyldCacheImageInfo<E>>,
}

impl<'data, 'cache, E, R> Iterator for DyldCacheImageIterator<'data, 'cache, E, R>
where
    E: Endian,
    R: ReadRef<'data>,
{
    type Item = DyldCacheImage<'data, 'cache, E, R>;

    fn next(&mut self) -> Option<DyldCacheImage<'data, 'cache, E, R>> {
        let image_info = self.iter.next()?;
        Some(DyldCacheImage {
            cache: self.cache,
            image_info,
        })
    }
}

/// One image (dylib) from inside the dyld shared cache.
#[derive(Debug)]
pub struct DyldCacheImage<'data, 'cache, E = Endianness, R = &'data [u8]>
where
    E: Endian,
    R: ReadRef<'data>,
{
    pub(crate) cache: &'cache DyldCache<'data, E, R>,
    image_info: &'data macho::DyldCacheImageInfo<E>,
}

impl<'data, 'cache, E, R> DyldCacheImage<'data, 'cache, E, R>
where
    E: Endian,
    R: ReadRef<'data>,
{
    /// The file system path of this image.
    pub fn path(&self) -> Result<&'data str> {
        let path = self.image_info.path(self.cache.endian, self.cache.data)?;
        // The path should always be ascii, so from_utf8 should always succeed.
        let path = core::str::from_utf8(path).map_err(|_| Error("Path string not valid utf-8"))?;
        Ok(path)
    }

    /// The subcache data which contains the Mach-O header for this image,
    /// together with the file offset at which this image starts.
    pub fn image_data_and_offset(&self) -> Result<(R, u64)> {
        let address = self.image_info.address.get(self.cache.endian);
        self.cache
            .data_and_offset_for_address(address)
            .ok_or(Error("Address not found in any mapping"))
    }

    /// Parse this image into an Object.
    pub fn parse_object(&self) -> Result<File<'data, R>> {
        File::parse_dyld_cache_image(self)
    }
}

impl<E: Endian> macho::DyldCacheMappingAndSlideInfo<E> {
    /// Return the (optional) array of slide information structs
    pub fn slide<'data, R: ReadRef<'data>>(
        &self,
        endian: E,
        data: R,
    ) -> Result<Option<DyldCacheSlideInfoSlice<'data, E>>> {
        match self.slide_info_file_size.get(endian) {
            0 => Ok(None),
            _ => {
                let slide_info_file_offset = self.slide_info_file_offset.get(endian);
                let version = data
                    .read_at::<U32<E>>(slide_info_file_offset)
                    .read_error("Invalid slide info file offset size or alignment")?
                    .get(endian);
                match version {
                    5 => {
                        let slide = data
                            .read_at::<macho::DyldCacheSlideInfo5<E>>(slide_info_file_offset)
                            .read_error("Invalid dyld cache slide info size or alignment")?;
                        let page_starts_offset = slide_info_file_offset
                            .checked_add(mem::size_of::<macho::DyldCacheSlideInfo5<E>>() as u64)
                            .unwrap();
                        let page_starts = data
                            .read_slice_at::<U16<E>>(
                                page_starts_offset,
                                slide.page_starts_count.get(endian) as usize,
                            )
                            .read_error("Invalid page starts size or alignment")?;
                        Ok(Some(DyldCacheSlideInfoSlice::V5(slide, page_starts)))
                    }
                    _ => todo!("handle other dyld_cache_slide_info versions"),
                }
            }
        }
    }
}

impl<E: Endian> macho::DyldCacheHeader<E> {
    /// Read the dyld cache header.
    pub fn parse<'data, R: ReadRef<'data>>(data: R) -> Result<&'data Self> {
        data.read_at::<macho::DyldCacheHeader<E>>(0)
            .read_error("Invalid dyld cache header size or alignment")
    }

    /// Returns (arch, endian) based on the magic string.
    pub fn parse_magic(&self) -> Result<(Architecture, E)> {
        let (arch, is_big_endian) = match &self.magic {
            b"dyld_v1    i386\0" => (Architecture::I386, false),
            b"dyld_v1  x86_64\0" => (Architecture::X86_64, false),
            b"dyld_v1 x86_64h\0" => (Architecture::X86_64, false),
            b"dyld_v1     ppc\0" => (Architecture::PowerPc, true),
            b"dyld_v1   armv6\0" => (Architecture::Arm, false),
            b"dyld_v1   armv7\0" => (Architecture::Arm, false),
            b"dyld_v1  armv7f\0" => (Architecture::Arm, false),
            b"dyld_v1  armv7s\0" => (Architecture::Arm, false),
            b"dyld_v1  armv7k\0" => (Architecture::Arm, false),
            b"dyld_v1   arm64\0" => (Architecture::Aarch64, false),
            b"dyld_v1  arm64e\0" => (Architecture::Aarch64, false),
            _ => return Err(Error("Unrecognized dyld cache magic")),
        };
        let endian =
            E::from_big_endian(is_big_endian).read_error("Unsupported dyld cache endian")?;
        Ok((arch, endian))
    }

    /// Return the mapping information table.
    pub fn mappings<'data, R: ReadRef<'data>>(
        &self,
        endian: E,
        data: R,
    ) -> Result<DyldCacheMappingSlice<'data, E, R>> {
        if self.mapping_with_slide_offset.get(endian) != 0 {
            let info = data
                .read_slice_at::<macho::DyldCacheMappingAndSlideInfo<E>>(
                    self.mapping_with_slide_offset.get(endian).into(),
                    self.mapping_with_slide_count.get(endian) as usize,
                )
                .read_error("Invalid dyld cache mapping size or alignment")?;
            Ok(DyldCacheMappingSlice::V2 { endian, data, info })
        } else {
            let info = data
                .read_slice_at::<macho::DyldCacheMappingInfo<E>>(
                    self.mapping_offset.get(endian).into(),
                    self.mapping_count.get(endian) as usize,
                )
                .read_error("Invalid dyld cache mapping size or alignment")?;
            Ok(DyldCacheMappingSlice::V1 { endian, data, info })
        }
    }

    /// Return the information about subcaches, if present.
    ///
    /// Returns `None` for dyld caches produced before dyld-940 (macOS 12).
    pub fn subcaches<'data, R: ReadRef<'data>>(
        &self,
        endian: E,
        data: R,
    ) -> Result<Option<DyldSubCacheSlice<'data, E>>> {
        let header_size = self.mapping_offset.get(endian);
        if header_size >= MIN_HEADER_SIZE_SUBCACHES_V2 {
            let subcaches = data
                .read_slice_at::<macho::DyldSubCacheEntryV2<E>>(
                    self.sub_cache_array_offset.get(endian).into(),
                    self.sub_cache_array_count.get(endian) as usize,
                )
                .read_error("Invalid dyld subcaches size or alignment")?;
            Ok(Some(DyldSubCacheSlice::V2(subcaches)))
        } else if header_size >= MIN_HEADER_SIZE_SUBCACHES_V1 {
            let subcaches = data
                .read_slice_at::<macho::DyldSubCacheEntryV1<E>>(
                    self.sub_cache_array_offset.get(endian).into(),
                    self.sub_cache_array_count.get(endian) as usize,
                )
                .read_error("Invalid dyld subcaches size or alignment")?;
            Ok(Some(DyldSubCacheSlice::V1(subcaches)))
        } else {
            Ok(None)
        }
    }

    /// Return the UUID for the .symbols subcache, if present.
    pub fn symbols_subcache_uuid(&self, endian: E) -> Option<[u8; 16]> {
        if self.mapping_offset.get(endian) >= MIN_HEADER_SIZE_SUBCACHES_V1 {
            let uuid = self.symbol_file_uuid;
            if uuid != [0; 16] {
                return Some(uuid);
            }
        }
        None
    }

    /// Return the image information table.
    pub fn images<'data, R: ReadRef<'data>>(
        &self,
        endian: E,
        data: R,
    ) -> Result<&'data [macho::DyldCacheImageInfo<E>]> {
        if self.mapping_offset.get(endian) >= MIN_HEADER_SIZE_SUBCACHES_V1 {
            data.read_slice_at::<macho::DyldCacheImageInfo<E>>(
                self.images_offset.get(endian).into(),
                self.images_count.get(endian) as usize,
            )
            .read_error("Invalid dyld cache image size or alignment")
        } else {
            data.read_slice_at::<macho::DyldCacheImageInfo<E>>(
                self.images_offset_old.get(endian).into(),
                self.images_count_old.get(endian) as usize,
            )
            .read_error("Invalid dyld cache image size or alignment")
        }
    }
}

impl<E: Endian> macho::DyldCacheImageInfo<E> {
    /// The file system path of this image.
    pub fn path<'data, R: ReadRef<'data>>(&self, endian: E, data: R) -> Result<&'data [u8]> {
        let r_start = self.path_file_offset.get(endian).into();
        let r_end = data.len().read_error("Couldn't get data len()")?;
        data.read_bytes_at_until(r_start..r_end, 0)
            .read_error("Couldn't read dyld cache image path")
    }

    /// Find the file offset of the image by looking up its address in the mappings.
    pub fn file_offset<'data, R: ReadRef<'data>>(
        &self,
        endian: E,
        mappings: &DyldCacheMappingSlice<'data, E, R>,
    ) -> Result<u64> {
        let address = self.address.get(endian);
        mappings
            .address_to_file_offset(address)
            .read_error("Invalid dyld cache image address")
    }
}
