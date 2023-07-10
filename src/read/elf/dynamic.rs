use core::convert::TryInto;
use core::fmt::Debug;
use core::mem;

use crate::elf;
use crate::endian;
use crate::pod::Pod;
use crate::read::{
    self,
    elf::{
        ElfDynamicRelocationIteratorFromDynamic, ElfRelaIterator, ElfSymbolTable, FileHeader,
        GnuHashTable, HashTable, ProgramHeader, SymbolTable,
    },
    Error, ReadError, Result, StringTable,
};
use crate::ReadRef;

/// A trait for generic access to `Dyn32` and `Dyn64`.
#[allow(missing_docs)]
pub trait Dyn: Debug + Pod {
    type Word: Into<u64>;
    type Endian: endian::Endian;

    fn d_tag(&self, endian: Self::Endian) -> Self::Word;
    fn d_val(&self, endian: Self::Endian) -> Self::Word;

    /// Try to convert the tag to a `u32`.
    fn tag32(&self, endian: Self::Endian) -> Option<u32> {
        self.d_tag(endian).into().try_into().ok()
    }

    /// Try to convert the value to a `u32`.
    fn val32(&self, endian: Self::Endian) -> Option<u32> {
        self.d_val(endian).into().try_into().ok()
    }

    /// Return true if the value is an offset in the dynamic string table.
    fn is_string(&self, endian: Self::Endian) -> bool {
        if let Some(tag) = self.tag32(endian) {
            match tag {
                elf::DT_NEEDED
                | elf::DT_SONAME
                | elf::DT_RPATH
                | elf::DT_RUNPATH
                | elf::DT_AUXILIARY
                | elf::DT_FILTER => true,
                _ => false,
            }
        } else {
            false
        }
    }

    /// Use the value to get a string in a string table.
    ///
    /// Does not check for an appropriate tag.
    fn string<'data>(
        &self,
        endian: Self::Endian,
        strings: StringTable<'data>,
    ) -> Result<&'data [u8]> {
        self.val32(endian)
            .and_then(|val| strings.get(val).ok())
            .read_error("Invalid ELF dyn string")
    }

    /// Return true if the value is an address.
    fn is_address(&self, endian: Self::Endian) -> bool {
        if let Some(tag) = self.tag32(endian) {
            match tag {
                elf::DT_PLTGOT
                | elf::DT_HASH
                | elf::DT_STRTAB
                | elf::DT_SYMTAB
                | elf::DT_RELA
                | elf::DT_INIT
                | elf::DT_FINI
                | elf::DT_SYMBOLIC
                | elf::DT_REL
                | elf::DT_DEBUG
                | elf::DT_JMPREL
                | elf::DT_FINI_ARRAY
                | elf::DT_INIT_ARRAY
                | elf::DT_PREINIT_ARRAY
                | elf::DT_SYMTAB_SHNDX
                | elf::DT_VERDEF
                | elf::DT_VERNEED
                | elf::DT_VERSYM
                | elf::DT_ADDRRNGLO..=elf::DT_ADDRRNGHI => true,
                _ => false,
            }
        } else {
            false
        }
    }
}

impl<Endian: endian::Endian> Dyn for elf::Dyn32<Endian> {
    type Word = u32;
    type Endian = Endian;

    #[inline]
    fn d_tag(&self, endian: Self::Endian) -> Self::Word {
        self.d_tag.get(endian)
    }

    #[inline]
    fn d_val(&self, endian: Self::Endian) -> Self::Word {
        self.d_val.get(endian)
    }
}

impl<Endian: endian::Endian> Dyn for elf::Dyn64<Endian> {
    type Word = u64;
    type Endian = Endian;

    #[inline]
    fn d_tag(&self, endian: Self::Endian) -> Self::Word {
        self.d_tag.get(endian)
    }

    #[inline]
    fn d_val(&self, endian: Self::Endian) -> Self::Word {
        self.d_val.get(endian)
    }
}

#[derive(Debug)]
enum DynamicHashTableIternal<'data, Elf>
where
    Elf: FileHeader,
{
    Hash(HashTable<'data, Elf>),
    GnuHash(GnuHashTable<'data, Elf>),
}

/// Hash table found through the dynamic segment.
#[derive(Debug)]
pub struct DynamicHashTable<'data, Elf>
where
    Elf: FileHeader,
{
    inner: DynamicHashTableIternal<'data, Elf>,
}

impl<'data, Elf> DynamicHashTable<'data, Elf>
where
    Elf: FileHeader,
{
    /// Returns the symbol table length.
    pub fn symbol_table_length(&self, endian: Elf::Endian) -> Option<u32> {
        match &self.inner {
            DynamicHashTableIternal::GnuHash(t) => t.symbol_table_length(endian),
            DynamicHashTableIternal::Hash(t) => Some(t.symbol_table_length()),
        }
    }
}

/// A parsed dynamic segment
#[derive(Debug)]
pub struct Dynamic<'data, Elf, R = &'data [u8]>
where
    Elf: FileHeader,
    R: ReadRef<'data>,
{
    pub(super) base: usize,
    pub(super) header: &'data Elf,
    pub(super) endian: Elf::Endian,
    pub(super) data: R,
    pub(super) dynamic: &'data [Elf::Dyn],
    pub(super) strings: StringTable<'data, R>,
    pub(super) hash: DynamicHashTable<'data, Elf>,
    pub(super) symbols: SymbolTable<'data, Elf, R>,
}

impl<'data, 'file, Elf, R> Dynamic<'data, Elf, R>
where
    Elf: FileHeader,
    R: ReadRef<'data> + 'data,
{
    /// Parse the dynamic table of a static elf.
    /// Example usage:
    /// ```no_run
    /// let file = std::fs::read("<path to elf>").unwrap();
    /// let file = file.as_slice();
    /// let elf  = ElfFile64::<Endianness>::parse(file).unwrap();
    /// let dynamic = Dynamic::new(elf.raw_header(), file)
    ///     .unwrap();
    /// ```
    pub fn new(elf: &'data Elf, data: R) -> read::Result<Self> {
        // Since this elf is not loaded, the addresses should contain offsets into the elf, thus base is 0.
        let endian = elf.endian()?;
        let program_headers = elf.program_headers(elf.endian()?, data)?;
        let dynamic = program_headers
            .iter()
            .find_map(|ph| ph.dynamic(endian, data).transpose())
            .transpose()?
            .read_error("No dynamic segment!")?;
        Self::new_loaded(0, elf, data, Some(dynamic))
    }

    /// Parse the dynamic table of a loaded elf.
    /// `base` should point to the base address of the elf, and will be used to convert absolute memory addresses into
    /// offsets into the elf.
    /// `dynamic` is optional, as it can be derived from the header, or by the caller (for example using
    /// `dl_iterate_phdr`).
    pub fn new_loaded(
        base: usize,
        header: &'data Elf,
        data: R,
        dynamic: Option<&'data [Elf::Dyn]>,
    ) -> read::Result<Self> {
        let endian = header.endian()?;
        let program_headers = header.program_headers(header.endian()?, data)?;

        // Use provided dynamic segment or find one.
        let dynamic = if let Some(dynamic) = dynamic {
            dynamic
        } else {
            program_headers
                .iter()
                .find_map(|ph| ph.dynamic_loaded(endian, data).transpose())
                .transpose()?
                .read_error("No dynamic segment!")?
        };

        // Parse and check only mandatory fields.

        // The last element in dynamic must be DT_NULL:
        if dynamic
            .last()
            .read_error("Dynamic table is empty!")?
            .tag32(endian)
            .read_error("Failed to parse dynamic table entry's tag!")?
            != elf::DT_NULL
        {
            return Err(Error("Dynamic table's last element is not of type DT_NULL"));
        }

        let strings = Self::parse_strings(base, endian, data, dynamic)?;
        let hash = Self::parse_hash(base, endian, data, dynamic)?;
        let symbols = Self::parse_symbols(base, endian, data, dynamic, &hash, strings)?;

        Ok(Self {
            base,
            header,
            endian,
            data,
            dynamic,
            strings,
            hash,
            symbols,
        })
    }

    /// Returns base address of elf
    pub fn base(&self) -> usize {
        self.base
    }

    /// Returns endiannes
    pub fn endian(&self) -> Elf::Endian {
        self.endian
    }

    /// Returns string table
    pub fn strings(&self) -> StringTable<'data, R> {
        self.strings
    }

    /// Returns hash table
    pub fn hash(&self) -> &'_ DynamicHashTable<'data, Elf> {
        &self.hash
    }

    /// Returns symbol table
    pub fn symbols(&'file self) -> ElfSymbolTable<'data, 'file, Elf, R> {
        ElfSymbolTable {
            endian: self.endian,
            symbols: &self.symbols,
        }
    }

    /// Returns dynamic relocations iterator (`.rela.dyn`)
    pub fn dynamic_relocations(
        &'file self,
    ) -> Result<Option<ElfDynamicRelocationIteratorFromDynamic<'data, 'file, Elf>>> {
        let pltrel = if let Some(p) = Self::dyn_by_tag(self.endian, self.dynamic, elf::DT_PLTREL) {
            p
        } else {
            return Ok(None);
        }
        .into() as u32;

        let (dt_relsz, dt_relent) = match pltrel {
            elf::DT_REL => (elf::DT_RELSZ, elf::DT_RELENT),
            elf::DT_RELA => (elf::DT_RELASZ, elf::DT_RELAENT),
            _ => return Err(Error("Invalid pltrel value!")),
        };

        let dynamic_relocations_val =
            if let Some(r) = Self::dyn_by_tag(self.endian, self.dynamic, pltrel) {
                r
            } else {
                return Ok(None);
            };
        let dynamic_relocations_offset =
            dyn_val_into_offset(self.base as u64, dynamic_relocations_val.into());

        // Unwrap safety: according to the ELF manual, if DT_REL or DT_RELA exist, then DT_RELSZ and DT_RELENT or
        // DT_RELASZ and DT_RELAENT (accordingly) *MUST* exist.
        let dynamic_relocations_size = Self::dyn_by_tag(self.endian, self.dynamic, dt_relsz)
            .unwrap()
            .into() as usize;
        let dynamic_relocations_entry_size = Self::dyn_by_tag(self.endian, self.dynamic, dt_relent)
            .unwrap()
            .into() as usize;

        // TODO: return error?
        match pltrel {
            elf::DT_REL => {
                debug_assert_eq!(dynamic_relocations_entry_size, mem::size_of::<Elf::Rel>())
            }
            elf::DT_RELA => {
                debug_assert_eq!(dynamic_relocations_entry_size, mem::size_of::<Elf::Rela>())
            }
            _ => unreachable!("should have returned an error in the previous match"),
        };

        let dynamic_relocations = match pltrel {
            elf::DT_REL => ElfRelaIterator::<Elf>::Rel(
                self.data
                    .read_slice_at(
                        dynamic_relocations_offset,
                        dynamic_relocations_size / dynamic_relocations_entry_size,
                    )
                    .read_error("Failed to read dynamic relocations")?
                    .iter(),
            ),
            elf::DT_RELA => ElfRelaIterator::<Elf>::Rela(
                self.data
                    .read_slice_at(
                        dynamic_relocations_offset,
                        dynamic_relocations_size / dynamic_relocations_entry_size,
                    )
                    .read_error("Failed to read dynamic relocations")?
                    .iter(),
            ),
            _ => unreachable!("should have returned an error in the previous match"),
        };

        Ok(Some(ElfDynamicRelocationIteratorFromDynamic {
            header: self.header,
            endian: self.endian,
            relocations: dynamic_relocations,
        }))
    }

    /// Returns PLT relocations iterator (`.rela.plt`)
    pub fn plt_relocations(
        &'file self,
    ) -> Result<Option<ElfDynamicRelocationIteratorFromDynamic<'data, 'file, Elf>>> {
        let plt_relocations_val =
            if let Some(r) = Self::dyn_by_tag(self.endian, self.dynamic, elf::DT_JMPREL) {
                r
            } else {
                return Ok(None);
            };
        let plt_relocations_offset =
            dyn_val_into_offset(self.base as u64, plt_relocations_val.into());

        // Unwrap safety: according to the ELF manual, if DT_JMPREL exists, then DT_PLTREL and DT_PLTRELSZ *MUST* exist.
        let pltrel = Self::dyn_by_tag(self.endian, self.dynamic, elf::DT_PLTREL)
            .unwrap()
            .into() as u32;
        let plt_relocations_size = Self::dyn_by_tag(self.endian, self.dynamic, elf::DT_PLTRELSZ)
            .unwrap()
            .into() as usize;

        let dt_relent = match pltrel {
            elf::DT_REL => elf::DT_RELENT,
            elf::DT_RELA => elf::DT_RELAENT,
            _ => return Err(Error("Invalid pltrel value!")),
        };

        let plt_relocations_entry_size = Self::dyn_by_tag(self.endian, self.dynamic, dt_relent)
            .ok_or(Error("Unable to find relocation size entry!"))?
            .into() as usize;

        // TODO: return error?
        match pltrel {
            elf::DT_REL => {
                debug_assert_eq!(plt_relocations_entry_size, mem::size_of::<Elf::Rel>())
            }
            elf::DT_RELA => {
                debug_assert_eq!(plt_relocations_entry_size, mem::size_of::<Elf::Rela>())
            }
            _ => unreachable!("should have returned an error in the previous match"),
        };

        let plt_relocations = match pltrel {
            elf::DT_REL => ElfRelaIterator::<Elf>::Rel(
                self.data
                    .read_slice_at(
                        plt_relocations_offset,
                        plt_relocations_size / plt_relocations_entry_size,
                    )
                    .read_error("Failed to read dynamic relocations")?
                    .iter(),
            ),
            elf::DT_RELA => ElfRelaIterator::<Elf>::Rela(
                self.data
                    .read_slice_at(
                        plt_relocations_offset,
                        plt_relocations_size / plt_relocations_entry_size,
                    )
                    .read_error("Failed to read dynamic relocations")?
                    .iter(),
            ),
            _ => unreachable!("should have returned an error in the previous match"),
        };

        Ok(Some(ElfDynamicRelocationIteratorFromDynamic {
            header: self.header,
            endian: self.endian,
            relocations: plt_relocations,
        }))
    }

    fn parse_strings(
        base: usize,
        endian: Elf::Endian,
        data: R,
        dynamic: &'data [Elf::Dyn],
    ) -> Result<StringTable<'data, R>> {
        let strings_val = Self::dyn_by_tag(endian, dynamic, elf::DT_STRTAB)
            .read_error("Dynamic strings table is missing!")?;
        let strings_offset = dyn_val_into_offset(base as u64, strings_val.into());
        let strings_size = Self::dyn_by_tag(endian, dynamic, elf::DT_STRSZ)
            .read_error("Dynamic strings table size is missing!")?;

        Ok(StringTable::new(
            data,
            strings_offset,
            strings_offset + strings_size.into(),
        ))
    }

    fn parse_hash(
        base: usize,
        endian: Elf::Endian,
        data: R,
        dynamic: &'data [Elf::Dyn],
    ) -> Result<DynamicHashTable<'data, Elf>> {
        // First, try finding GNU_HASH as it's the new de-facto standard.
        let hash_val = Self::dyn_by_tag(endian, dynamic, elf::DT_GNU_HASH);

        if let Some(hash_val) = hash_val {
            let hash_offset = dyn_val_into_offset(base as u64, hash_val.into());

            let table = GnuHashTable::parse(
                endian,
                data.read_slice_at(
                    hash_offset,
                    (data.len().read_error("Can't get data len")? - hash_offset) as usize,
                )
                .read_error("Failed to get slice of data to parse gnu hash table")?,
            )?;

            let inner = DynamicHashTableIternal::GnuHash(table);
            return Ok(DynamicHashTable { inner });
        };

        // No gnu hash table, let's try OG hash table
        let hash_val = Self::dyn_by_tag(endian, dynamic, elf::DT_HASH)
            .read_error("Failed to find Gnu or regular hash table!")?;

        let hash_offset = dyn_val_into_offset(base as u64, hash_val.into());

        let table = HashTable::parse(
            endian,
            data.read_slice_at(
                hash_offset,
                (data.len().read_error("Can't get data len")? - hash_offset) as usize,
            )
            .read_error("Failed to get slice of data to parse hash table")?,
        )?;

        let inner = DynamicHashTableIternal::Hash(table);

        Ok(DynamicHashTable { inner })
    }

    fn parse_symbols(
        base: usize,
        endian: Elf::Endian,
        data: R,
        dynamic: &'data [Elf::Dyn],
        hash: &DynamicHashTable<'data, Elf>,
        strings: StringTable<'data, R>,
    ) -> Result<SymbolTable<'data, Elf, R>> {
        let symbols_val = Self::dyn_by_tag(endian, dynamic, elf::DT_SYMTAB)
            .read_error("Dynamic symbols table is missing!")?;
        let symbols_offset = dyn_val_into_offset(base as u64, symbols_val.into());
        let symbols_amount = hash
            .symbol_table_length(endian)
            .read_error("Failed to get dynamic symbol table length")?;
        let symbols: &[Elf::Sym] = data
            .read_slice_at(symbols_offset, symbols_amount as usize)
            .read_error("Failed to read dynamic symbols table")?;

        SymbolTable::dynamic(symbols, strings)
    }

    fn dyn_by_tag(endian: Elf::Endian, dynamic: &[Elf::Dyn], tag: u32) -> Option<Elf::Word> {
        dynamic.iter().find_map(|entry| {
            let tag32 = entry.tag32(endian)?;
            if tag32 == tag {
                Some(entry.d_val(endian))
            } else {
                None
            }
        })
    }
}

#[cfg(target_os = "android")]
#[inline]
fn dyn_val_into_offset(_: u64, val: u64) -> u64 {
    val
}

#[cfg(target_os = "linux")]
#[inline]
fn dyn_val_into_offset(base: u64, val: u64) -> u64 {
    val - base
}
