//! Interface for reading object files.

use crate::alloc::vec::Vec;

mod any;
pub use any::*;

mod coff;
pub use coff::*;

mod elf;
pub use elf::*;

mod macho;
pub use macho::*;

mod pe;
pub use pe::*;

mod traits;
pub use traits::*;

#[cfg(feature = "wasm")]
mod wasm;
#[cfg(feature = "wasm")]
pub use wasm::*;

/// The native object file for the target platform.
#[cfg(target_os = "linux")]
pub type NativeFile<'data> = ElfFile<'data>;

/// The native object file for the target platform.
#[cfg(target_os = "macos")]
pub type NativeFile<'data> = MachOFile<'data>;

/// The native object file for the target platform.
#[cfg(target_os = "windows")]
pub type NativeFile<'data> = PeFile<'data>;

/// The native object file for the target platform.
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub type NativeFile<'data> = WasmFile<'data>;

/// The kind of a section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    /// The section kind is unknown.
    Unknown,
    /// An executable code section.
    ///
    /// Example ELF sections: `.text`
    ///
    /// Example Mach-O sections: `__TEXT/__text`
    Text,
    /// A data section.
    ///
    /// Example ELF sections: `.data`
    ///
    /// Example Mach-O sections: `__DATA/__data`
    Data,
    /// A read only data section.
    ///
    /// Example ELF sections: `.rodata`
    ///
    /// Example Mach-O sections: `__TEXT/__const`, `__DATA/__const`
    ReadOnlyData,
    /// A loadable string section.
    ///
    /// Example ELF sections: `.rodata.str`
    ///
    /// Example Mach-O sections: `__TEXT/__cstring`
    ReadOnlyString,
    /// An uninitialized data section.
    ///
    /// Example ELF sections: `.bss`
    ///
    /// Example Mach-O sections: `__DATA/__bss`
    UninitializedData,
    /// A TLS data section.
    ///
    /// Example ELF sections: `.tdata`
    ///
    /// Example Mach-O sections: `__DATA/__thread_data`
    Tls,
    /// An uninitialized TLS data section.
    ///
    /// Example ELF sections: `.tbss`
    ///
    /// Example Mach-O sections: `__DATA/__thread_bss`
    UninitializedTls,
    /// A TLS variables section.
    ///
    /// This contains TLS variable structures, rather than the variable initializers.
    ///
    /// Example Mach-O sections: `__DATA/__thread_vars`
    TlsVariables,
    /// A non-loadable string section.
    ///
    /// Example ELF sections: `.comment`, `.debug_str`
    OtherString,
    /// Some other non-loadable section.
    ///
    /// Example ELF sections: `.debug_info`
    Other,
    /// Debug information.
    ///
    /// Example Mach-O sections: `__DWARF/__debug_info`
    Debug,
    /// Information for the linker.
    ///
    /// Example COFF sections: `.drectve`
    Linker,
    /// Metadata such as symbols or relocations.
    ///
    /// Example ELF sections: `.symtab`, `.strtab`
    Metadata,
}

/// The index used to identify a section of a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SectionIndex(pub usize);

/// The index used to identify a symbol of a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SymbolIndex(pub usize);

/// The kind of a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    /// The symbol kind is unknown.
    Unknown,
    /// The symbol is a null placeholder.
    Null,
    /// The symbol is for executable code.
    Text,
    /// The symbol is for a data object.
    Data,
    /// The symbol is for a section.
    Section,
    /// The symbol is the name of a file. It precedes symbols within that file.
    File,
    /// The symbol is for a code label.
    Label,
    /// The symbol is for an uninitialized common block.
    Common,
    /// The symbol is for a thread local storage entity.
    Tls,
}

/// A symbol table entry.
#[derive(Debug)]
pub struct Symbol<'data> {
    kind: SymbolKind,
    section_index: Option<SectionIndex>,
    undefined: bool,
    global: bool,
    name: Option<&'data str>,
    address: u64,
    size: u64,
}

impl<'data> Symbol<'data> {
    /// Return the kind of this symbol.
    #[inline]
    pub fn kind(&self) -> SymbolKind {
        self.kind
    }

    /// Returns the section index for the section containing this symbol.
    ///
    /// May return `None` if the section is unknown or the symbol is undefined.
    #[inline]
    pub fn section_index(&self) -> Option<SectionIndex> {
        self.section_index
    }

    /// Return true if the symbol is undefined.
    #[inline]
    pub fn is_undefined(&self) -> bool {
        self.undefined
    }

    /// Return true if the symbol is global.
    #[inline]
    pub fn is_global(&self) -> bool {
        self.global
    }

    /// Return true if the symbol is local.
    #[inline]
    pub fn is_local(&self) -> bool {
        !self.is_global()
    }

    /// The name of the symbol.
    #[inline]
    pub fn name(&self) -> Option<&'data str> {
        self.name
    }

    /// The address of the symbol. May be zero if the address is unknown.
    #[inline]
    pub fn address(&self) -> u64 {
        self.address
    }

    /// The size of the symbol. May be zero if the size is unknown.
    #[inline]
    pub fn size(&self) -> u64 {
        self.size
    }
}

/// A map from addresses to symbols.
#[derive(Debug)]
pub struct SymbolMap<'data> {
    symbols: Vec<Symbol<'data>>,
}

impl<'data> SymbolMap<'data> {
    /// Get the symbol containing the given address.
    pub fn get(&self, address: u64) -> Option<&Symbol<'data>> {
        self.symbols
            .binary_search_by(|symbol| {
                if address < symbol.address {
                    std::cmp::Ordering::Greater
                } else if address < symbol.address + symbol.size {
                    std::cmp::Ordering::Equal
                } else {
                    std::cmp::Ordering::Less
                }
            })
            .ok()
            .and_then(|index| self.symbols.get(index))
    }

    /// Get all symbols in the map.
    pub fn symbols(&self) -> &[Symbol<'data>] {
        &self.symbols
    }

    /// Return true for symbols that should be included in the map.
    fn filter(symbol: &Symbol<'_>) -> bool {
        match symbol.kind() {
            SymbolKind::Unknown | SymbolKind::Text | SymbolKind::Data => {}
            SymbolKind::Null
            | SymbolKind::Section
            | SymbolKind::File
            | SymbolKind::Label
            | SymbolKind::Common
            | SymbolKind::Tls => {
                return false;
            }
        }
        !symbol.is_undefined() && symbol.size() > 0
    }
}

/// The kind of a relocation.
///
/// The relocation descriptions use the following definitions. Note that
/// these definitions probably don't match any ELF ABI.
///
/// * A - The value of the addend.
/// * G - The address of the symbol's entry within the global offset table.
/// * L - The address of the symbol's entry within the procedure linkage table.
/// * P - The address of the place of the relocation.
/// * S - The address of the symbol.
/// * GotBase - The address of the global offset table.
/// * Image - The base address of the image.
/// * Section - The address of the section containing the symbol.
///
/// 'XxxRelative' means 'Xxx + A - P'.  'XxxOffset' means 'S + A - Xxx'.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationKind {
    /// S + A
    Absolute,
    /// S + A - P
    Relative,
    /// G + A - GotBase
    Got,
    /// G + A - P
    GotRelative,
    /// GotBase + A - P
    GotBaseRelative,
    /// S + A - GotBase
    GotBaseOffset,
    /// L + A - P
    PltRelative,
    /// S + A - Image
    ImageOffset,
    /// S + A - Section
    SectionOffset,
    /// The index of the section containing the symbol.
    SectionIndex,
    /// Some other kind of relocation. The value is dependent on file format and machine.
    Other(u32),
}

/// Extra information about how the relocation should be applied. This is often architecture
/// specific.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationSubkind {
    /// Default subkind for the given relocation kind.
    Default,

    /// x86 rip-relative addressing.
    X86RipRelative,
    /// x86 rip-relative addressing in movq instruction.
    X86RipRelativeMovq,
    /// `RelocationKind::Absolute` with sign extension at runtime.
    X86Signed,
    /// x86 branch instruction.
    X86Branch,
}

/// The target referenced by a relocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelocationTarget {
    /// The target is a symbol.
    Symbol(SymbolIndex),
    /// The target is a section.
    Section(SectionIndex),
}

/// A relocation entry.
#[derive(Debug)]
pub struct Relocation {
    kind: RelocationKind,
    subkind: RelocationSubkind,
    size: u8,
    target: RelocationTarget,
    addend: i64,
    implicit_addend: bool,
}

impl Relocation {
    /// The kind of relocation.
    #[inline]
    pub fn kind(&self) -> RelocationKind {
        self.kind
    }

    /// Extra information about how the relocation should be applied.
    #[inline]
    pub fn subkind(&self) -> RelocationSubkind {
        self.subkind
    }

    /// The size in bits of the place of the relocation.
    ///
    /// If 0, then the size is determined by the relocation kind.
    #[inline]
    pub fn size(&self) -> u8 {
        self.size
    }

    /// The target of the relocation.
    #[inline]
    pub fn target(&self) -> RelocationTarget {
        self.target
    }

    /// The addend to use in the relocation calculation.
    pub fn addend(&self) -> i64 {
        self.addend
    }

    /// Set the addend to use in the relocation calculation.
    pub fn set_addend(&mut self, addend: i64) {
        self.addend = addend
    }

    /// Returns true if there is an implicit addend stored in the data at the offset
    /// to be relocated.
    pub fn has_implicit_addend(&self) -> bool {
        self.implicit_addend
    }
}

fn data_range(data: &[u8], data_address: u64, range_address: u64, size: u64) -> Option<&[u8]> {
    if range_address >= data_address {
        let start_offset = (range_address - data_address) as usize;
        let end_offset = start_offset + size as usize;
        if end_offset <= data.len() {
            return Some(&data[start_offset..end_offset]);
        }
    }
    None
}
