use alloc::fmt;
use core::fmt::Debug;
use core::str;

use crate::elf;
use crate::endian::{self, RunTimeEndian};
use crate::pod::Pod;
use crate::read::util::StringTable;
use crate::read::{
    SectionIndex, Symbol, SymbolFlags, SymbolIndex, SymbolKind, SymbolScope, SymbolSection,
};

use super::{ElfFile, FileHeader};

#[derive(Debug, Clone, Copy)]
pub(super) struct SymbolTable<'data, Elf: FileHeader> {
    pub symbols: &'data [Elf::Sym],
    pub strings: StringTable<'data>,
    pub shndx: &'data [u32],
}

/// An iterator over the symbols of an `ElfFile32`.
pub type ElfSymbolIterator32<'data, 'file, Endian = RunTimeEndian> =
    ElfSymbolIterator<'data, 'file, elf::FileHeader32<Endian>>;
/// An iterator over the symbols of an `ElfFile64`.
pub type ElfSymbolIterator64<'data, 'file, Endian = RunTimeEndian> =
    ElfSymbolIterator<'data, 'file, elf::FileHeader64<Endian>>;

/// An iterator over the symbols of an `ElfFile`.
pub struct ElfSymbolIterator<'data, 'file, Elf>
where
    'data: 'file,
    Elf: FileHeader,
{
    pub(super) file: &'file ElfFile<'data, Elf>,
    pub(super) symbols: SymbolTable<'data, Elf>,
    pub(super) index: usize,
}

impl<'data, 'file, Elf: FileHeader> fmt::Debug for ElfSymbolIterator<'data, 'file, Elf> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ElfSymbolIterator").finish()
    }
}

impl<'data, 'file, Elf: FileHeader> Iterator for ElfSymbolIterator<'data, 'file, Elf> {
    type Item = (SymbolIndex, Symbol<'data>);

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.index;
        let shndx = self.symbols.shndx.get(index).cloned();
        self.symbols.symbols.get(index).map(|symbol| {
            self.index += 1;
            (
                SymbolIndex(index),
                parse_symbol::<Elf>(self.file.endian, index, symbol, self.symbols.strings, shndx),
            )
        })
    }
}

pub(super) fn parse_symbol<'data, Elf: FileHeader>(
    endian: Elf::Endian,
    index: usize,
    symbol: &Elf::Sym,
    strings: StringTable<'data>,
    shndx: Option<u32>,
) -> Symbol<'data> {
    let name = strings
        .get(symbol.st_name(endian))
        .ok()
        .and_then(|s| str::from_utf8(s).ok());
    let kind = match symbol.st_type() {
        elf::STT_NOTYPE if index == 0 => SymbolKind::Null,
        elf::STT_OBJECT | elf::STT_COMMON => SymbolKind::Data,
        elf::STT_FUNC => SymbolKind::Text,
        elf::STT_SECTION => SymbolKind::Section,
        elf::STT_FILE => SymbolKind::File,
        elf::STT_TLS => SymbolKind::Tls,
        _ => SymbolKind::Unknown,
    };
    let section = match symbol.st_shndx(endian) {
        elf::SHN_UNDEF => SymbolSection::Undefined,
        elf::SHN_ABS => {
            if kind == SymbolKind::File {
                SymbolSection::None
            } else {
                SymbolSection::Absolute
            }
        }
        elf::SHN_COMMON => SymbolSection::Common,
        elf::SHN_XINDEX => match shndx {
            Some(index) => SymbolSection::Section(SectionIndex(index as usize)),
            None => SymbolSection::Unknown,
        },
        index if index < elf::SHN_LORESERVE => SymbolSection::Section(SectionIndex(index as usize)),
        _ => SymbolSection::Unknown,
    };
    let weak = symbol.st_bind() == elf::STB_WEAK;
    let scope = match symbol.st_bind() {
        _ if section == SymbolSection::Undefined => SymbolScope::Unknown,
        elf::STB_LOCAL => SymbolScope::Compilation,
        elf::STB_GLOBAL | elf::STB_WEAK => {
            if symbol.st_visibility() == elf::STV_HIDDEN {
                SymbolScope::Linkage
            } else {
                SymbolScope::Dynamic
            }
        }
        _ => SymbolScope::Unknown,
    };
    let flags = SymbolFlags::Elf {
        st_info: symbol.st_info(),
        st_other: symbol.st_other(),
    };
    Symbol {
        name,
        address: symbol.st_value(endian).into(),
        size: symbol.st_size(endian).into(),
        kind,
        section,
        weak,
        scope,
        flags,
    }
}

/// A trait for generic access to `Sym32` and `Sym64`.
#[allow(missing_docs)]
pub trait Sym: Debug + Pod {
    type Word: Into<u64>;
    type Endian: endian::Endian;

    fn st_name(&self, endian: Self::Endian) -> u32;
    fn st_info(&self) -> u8;
    fn st_bind(&self) -> u8;
    fn st_type(&self) -> u8;
    fn st_other(&self) -> u8;
    fn st_visibility(&self) -> u8;
    fn st_shndx(&self, endian: Self::Endian) -> u16;
    fn st_value(&self, endian: Self::Endian) -> Self::Word;
    fn st_size(&self, endian: Self::Endian) -> Self::Word;
}

impl<Endian: endian::Endian> Sym for elf::Sym32<Endian> {
    type Word = u32;
    type Endian = Endian;

    #[inline]
    fn st_name(&self, endian: Self::Endian) -> u32 {
        self.st_name.get(endian)
    }

    #[inline]
    fn st_info(&self) -> u8 {
        self.st_info
    }

    #[inline]
    fn st_bind(&self) -> u8 {
        self.st_bind()
    }

    #[inline]
    fn st_type(&self) -> u8 {
        self.st_type()
    }

    #[inline]
    fn st_other(&self) -> u8 {
        self.st_other
    }

    #[inline]
    fn st_visibility(&self) -> u8 {
        self.st_visibility()
    }

    #[inline]
    fn st_shndx(&self, endian: Self::Endian) -> u16 {
        self.st_shndx.get(endian)
    }

    #[inline]
    fn st_value(&self, endian: Self::Endian) -> Self::Word {
        self.st_value.get(endian)
    }

    #[inline]
    fn st_size(&self, endian: Self::Endian) -> Self::Word {
        self.st_size.get(endian)
    }
}

impl<Endian: endian::Endian> Sym for elf::Sym64<Endian> {
    type Word = u64;
    type Endian = Endian;

    #[inline]
    fn st_name(&self, endian: Self::Endian) -> u32 {
        self.st_name.get(endian)
    }

    #[inline]
    fn st_info(&self) -> u8 {
        self.st_info
    }

    #[inline]
    fn st_bind(&self) -> u8 {
        self.st_bind()
    }

    #[inline]
    fn st_type(&self) -> u8 {
        self.st_type()
    }

    #[inline]
    fn st_other(&self) -> u8 {
        self.st_other
    }

    #[inline]
    fn st_visibility(&self) -> u8 {
        self.st_visibility()
    }

    #[inline]
    fn st_shndx(&self, endian: Self::Endian) -> u16 {
        self.st_shndx.get(endian)
    }

    #[inline]
    fn st_value(&self, endian: Self::Endian) -> Self::Word {
        self.st_value.get(endian)
    }

    #[inline]
    fn st_size(&self, endian: Self::Endian) -> Self::Word {
        self.st_size.get(endian)
    }
}
