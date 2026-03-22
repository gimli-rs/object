use alloc::vec::Vec;

use crate::read::{Object, ObjectSymbol, ObjectSymbolTable};
use crate::{SymbolKind, SymbolScope};

/// An entry in a [`SymbolMap`].
pub trait SymbolMapEntry {
    /// The symbol address.
    fn address(&self) -> u64;
}

/// A map from addresses to symbol information.
///
/// The symbol information depends on the chosen entry type, such as [`SymbolMapName`].
///
/// Returned by [`Object::symbol_map`].
#[derive(Debug, Default, Clone)]
pub struct SymbolMap<T: SymbolMapEntry> {
    symbols: Vec<T>,
}

impl<T: SymbolMapEntry> SymbolMap<T> {
    /// Construct a new symbol map.
    ///
    /// This function will sort the symbols by address.
    pub fn new(mut symbols: Vec<T>) -> Self {
        symbols.sort_by_key(|s| s.address());
        SymbolMap { symbols }
    }

    /// Get the symbol before the given address.
    pub fn get(&self, address: u64) -> Option<&T> {
        let index = match self
            .symbols
            .binary_search_by_key(&address, |symbol| symbol.address())
        {
            Ok(index) => index,
            Err(index) => index.checked_sub(1)?,
        };
        self.symbols.get(index)
    }

    /// Get all symbols in the map.
    #[inline]
    pub fn symbols(&self) -> &[T] {
        &self.symbols
    }
}

/// The type used for entries in a [`SymbolMap`] that maps from addresses to names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SymbolMapName<'data> {
    address: u64,
    name: &'data str,
}

impl<'data> SymbolMapName<'data> {
    /// Construct a `SymbolMapName`.
    pub fn new(address: u64, name: &'data str) -> Self {
        SymbolMapName { address, name }
    }

    /// The symbol address.
    #[inline]
    pub fn address(&self) -> u64 {
        self.address
    }

    /// The symbol name.
    #[inline]
    pub fn name(&self) -> &'data str {
        self.name
    }
}

impl<'data> SymbolMapEntry for SymbolMapName<'data> {
    #[inline]
    fn address(&self) -> u64 {
        self.address
    }
}

/// A map from addresses to symbol names and object files.
///
/// This is derived from STAB entries in Mach-O files.
///
/// Returned by [`Object::object_map`].
#[derive(Debug, Default, Clone)]
pub struct ObjectMap<'data> {
    symbols: SymbolMap<ObjectMapEntry<'data>>,
    objects: Vec<ObjectMapFile<'data>>,
}

impl<'data> ObjectMap<'data> {
    #[cfg(feature = "macho")]
    pub(super) fn new(
        symbols: Vec<ObjectMapEntry<'data>>,
        objects: Vec<ObjectMapFile<'data>>,
    ) -> Self {
        ObjectMap {
            symbols: SymbolMap::new(symbols),
            objects,
        }
    }

    /// Get the entry containing the given address.
    pub fn get(&self, address: u64) -> Option<&ObjectMapEntry<'data>> {
        self.symbols
            .get(address)
            .filter(|entry| entry.size == 0 || address.wrapping_sub(entry.address) < entry.size)
    }

    /// Get all symbols in the map.
    #[inline]
    pub fn symbols(&self) -> &[ObjectMapEntry<'data>] {
        self.symbols.symbols()
    }

    /// Get all objects in the map.
    #[inline]
    pub fn objects(&self) -> &[ObjectMapFile<'data>] {
        &self.objects
    }
}

/// A symbol in an [`ObjectMap`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectMapEntry<'data> {
    address: u64,
    size: u64,
    name: &'data [u8],
    object: usize,
}

impl<'data> ObjectMapEntry<'data> {
    #[cfg(feature = "macho")]
    pub(super) fn new(address: u64, size: u64, name: &'data [u8], object: usize) -> Self {
        ObjectMapEntry {
            address,
            size,
            name,
            object,
        }
    }

    /// Get the symbol address.
    #[inline]
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Get the symbol size.
    ///
    /// This may be 0 if the size is unknown.
    #[inline]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get the symbol name.
    #[inline]
    pub fn name(&self) -> &'data [u8] {
        self.name
    }

    /// Get the index of the object file name.
    #[inline]
    pub fn object_index(&self) -> usize {
        self.object
    }

    /// Get the object file name.
    #[inline]
    pub fn object<'a>(&self, map: &'a ObjectMap<'data>) -> &'a ObjectMapFile<'data> {
        &map.objects[self.object]
    }
}

impl<'data> SymbolMapEntry for ObjectMapEntry<'data> {
    #[inline]
    fn address(&self) -> u64 {
        self.address
    }
}

/// An object file name in an [`ObjectMap`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectMapFile<'data> {
    path: &'data [u8],
    member: Option<&'data [u8]>,
}

impl<'data> ObjectMapFile<'data> {
    #[cfg(feature = "macho")]
    pub(super) fn new(path: &'data [u8], member: Option<&'data [u8]>) -> Self {
        ObjectMapFile { path, member }
    }

    /// Get the path to the file containing the object.
    #[inline]
    pub fn path(&self) -> &'data [u8] {
        self.path
    }

    /// If the file is an archive, get the name of the member containing the object.
    #[inline]
    pub fn member(&self) -> Option<&'data [u8]> {
        self.member
    }
}

/// A builder for a [`SymbolMap`].
// TODO: builder options for
// - synthetic function start/end (from LC_FUNCTION_STARTS or exception handling)
// - section filter (e.g. text only)
// - map entries (e.g. subtract base address)
#[derive(Debug, Default)]
pub struct SymbolMapBuilder(());

impl SymbolMapBuilder {
    /// Construct a new symbol map builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read the symbols from an object file to create a symbol map.
    pub fn build<'data, O>(self, object: &O) -> SymbolMap<SymbolMapName<'data>>
    where
        O: Object<'data> + ?Sized,
    {
        let mut symbols = Vec::new();
        if let Some(table) = object
            .symbol_table()
            .or_else(|| object.dynamic_symbol_table())
        {
            // Sometimes symbols share addresses. Collect them all then choose the "best".
            let mut all_symbols = Vec::new();
            for symbol in table.symbols() {
                // Must have an address.
                if !symbol.is_definition() {
                    continue;
                }
                // Must have a name.
                let name = match symbol.name() {
                    Ok(name) => name,
                    _ => continue,
                };
                if name.is_empty() {
                    continue;
                }

                // Lower is better.
                let mut priority = 0u32;

                // Prefer known kind.
                match symbol.kind() {
                    SymbolKind::Text | SymbolKind::Data => {}
                    SymbolKind::Unknown => priority += 1,
                    _ => continue,
                }
                priority *= 2;

                // Prefer global visibility.
                priority += match symbol.scope() {
                    SymbolScope::Unknown => 3,
                    SymbolScope::Compilation => 2,
                    SymbolScope::Linkage => 1,
                    SymbolScope::Dynamic => 0,
                };
                priority *= 4;

                // Prefer later entries (earlier symbol is likely to be less specific).
                let index = !0 - symbol.index().0;

                // Tuple is ordered for sort.
                all_symbols.push((symbol.address(), priority, index, name));
            }
            // Unstable sort is okay because tuple includes index.
            all_symbols.sort_unstable();

            let mut previous_address = !0;
            for (address, _priority, _index, name) in all_symbols {
                if address != previous_address {
                    symbols.push(SymbolMapName::new(address, name));
                    previous_address = address;
                }
            }
        }
        SymbolMap::new(symbols)
    }
}
