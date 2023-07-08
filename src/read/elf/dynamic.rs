use core::convert::TryInto;
use core::fmt::Debug;

use crate::elf;
use crate::endian;
use crate::pod::Pod;
use crate::read::{
    self,
    elf::{FileHeader, SymbolTable},
    Error, ReadError, Result, StringTable,
};
use crate::ReadRef;

use super::ElfSymbolTable;
use super::GnuHashTable;
use super::HashTable;

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
    pub(super) endian: Elf::Endian,
    pub(super) data: R,
    pub(super) table: &'data [Elf::Dyn],
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
    pub fn new(endian: Elf::Endian, data: R, dynamic: &'data [Elf::Dyn]) -> read::Result<Self> {
        // Since this elf is not loaded, the addresses should contain offsets into the elf, thus base is 0.
        Self::new_loaded(0, endian, data, dynamic)
    }

    /// Parse the dynamic table of a loaded elf.
    /// `base` should point to the base address of the elf, and will be used to convert absolute memory addresses into
    /// offsets into the elf.
    pub fn new_loaded(
        base: usize,
        endian: Elf::Endian,
        data: R,
        dynamic: &'data [Elf::Dyn],
    ) -> read::Result<Self> {
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
            endian,
            data,
            table: dynamic,
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

    fn parse_strings(
        base: usize,
        endian: Elf::Endian,
        data: R,
        dynamic: &'data [Elf::Dyn],
    ) -> Result<StringTable<'data, R>> {
        let strings_val = dyn_by_tag::<Elf>(endian, dynamic, elf::DT_STRTAB)
            .read_error("Dynamic strings table is missing!")?;
        let strings_offset = dyn_val_into_offset(base as u64, strings_val.into());
        let strings_size = dyn_by_tag::<Elf>(endian, dynamic, elf::DT_STRSZ)
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
        let hash_val = dyn_by_tag::<Elf>(endian, dynamic, elf::DT_GNU_HASH);

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
        let hash_val = dyn_by_tag::<Elf>(endian, dynamic, elf::DT_HASH)
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
        return Ok(DynamicHashTable { inner });
    }

    fn parse_symbols(
        base: usize,
        endian: Elf::Endian,
        data: R,
        dynamic: &'data [Elf::Dyn],
        hash: &DynamicHashTable<'data, Elf>,
        strings: StringTable<'data, R>,
    ) -> Result<SymbolTable<'data, Elf, R>> {
        let symbols_val = dyn_by_tag::<Elf>(endian, dynamic, elf::DT_SYMTAB)
            .read_error("Dynamic symbols table is missing!")?;
        let symbols_offset = dyn_val_into_offset(base as u64, symbols_val.into());
        let symbols_amount = hash
            .symbol_table_length(endian)
            .read_error("Failed to get dynamic symbol table length")?;
        let symbols: &[Elf::Sym] = data
            .read_slice_at(symbols_offset as u64, symbols_amount as usize)
            .read_error("Failed to read dynamic symbols table")?;

        SymbolTable::dynamic(symbols, strings)
    }
}

fn dyn_by_tag<Elf: FileHeader>(
    endian: Elf::Endian,
    dynamic: &[Elf::Dyn],
    tag: u32,
) -> Option<Elf::Word> {
    dynamic.iter().find_map(|entry| {
        let tag32 = entry.tag32(endian)?;
        if tag32 == tag {
            Some(entry.d_val(endian))
        } else {
            None
        }
    })
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
