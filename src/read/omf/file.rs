//! OMF file implementation for the unified read API.

use crate::read::{
    Architecture, ByteString, Error, Export, FileFlags, Import, NoDynamicRelocationIterator,
    Object, ObjectKind, ObjectSection, ReadRef, Result, SectionIndex, SymbolIndex,
};
use crate::SubArchitecture;

use super::{
    OmfComdat, OmfComdatIterator, OmfFile, OmfSection, OmfSectionIterator, OmfSegmentIterator,
    OmfSegmentRef, OmfSymbol, OmfSymbolIterator, OmfSymbolTable,
};

impl<'data, R: ReadRef<'data>> Object<'data> for OmfFile<'data, R> {
    type Segment<'file>
        = OmfSegmentRef<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type SegmentIterator<'file>
        = OmfSegmentIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type Section<'file>
        = OmfSection<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type SectionIterator<'file>
        = OmfSectionIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type Comdat<'file>
        = OmfComdat<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type ComdatIterator<'file>
        = OmfComdatIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type Symbol<'file>
        = OmfSymbol<'data>
    where
        Self: 'file,
        'data: 'file;
    type SymbolIterator<'file>
        = OmfSymbolIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type SymbolTable<'file>
        = OmfSymbolTable<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type DynamicRelocationIterator<'file>
        = NoDynamicRelocationIterator
    where
        Self: 'file,
        'data: 'file;

    fn architecture(&self) -> Architecture {
        Architecture::I386
    }

    fn sub_architecture(&self) -> Option<SubArchitecture> {
        None
    }

    fn is_little_endian(&self) -> bool {
        true
    }

    fn is_64(&self) -> bool {
        false
    }

    fn kind(&self) -> ObjectKind {
        ObjectKind::Relocatable
    }

    fn segments(&self) -> Self::SegmentIterator<'_> {
        OmfSegmentIterator {
            file: self,
            index: 0,
        }
    }

    fn section_by_name_bytes<'file>(
        &'file self,
        section_name: &[u8],
    ) -> Option<Self::Section<'file>> {
        self.sections()
            .find(|section| section.name_bytes() == Ok(section_name))
    }

    fn section_by_index(&self, index: SectionIndex) -> Result<Self::Section<'_>> {
        let idx = index
            .0
            .checked_sub(1)
            .ok_or(Error("Invalid section index"))?;
        if idx < self.segments.len() {
            Ok(OmfSection {
                file: self,
                index: idx,
            })
        } else {
            Err(Error("Section index out of bounds"))
        }
    }

    fn sections(&self) -> Self::SectionIterator<'_> {
        OmfSectionIterator {
            file: self,
            index: 0,
        }
    }

    fn comdats(&self) -> Self::ComdatIterator<'_> {
        OmfComdatIterator {
            file: self,
            index: 0,
        }
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> Result<Self::Symbol<'_>> {
        let idx = index.0;
        if idx >= self.symbols.len() {
            return Err(Error("Symbol index out of bounds"));
        }
        Ok(self.symbols[idx].clone())
    }

    fn symbols(&self) -> Self::SymbolIterator<'_> {
        OmfSymbolIterator {
            file: self,
            index: 0,
        }
    }

    fn symbol_table(&self) -> Option<Self::SymbolTable<'_>> {
        Some(OmfSymbolTable { file: self })
    }

    fn dynamic_symbols(&self) -> Self::SymbolIterator<'_> {
        OmfSymbolIterator {
            file: self,
            index: usize::MAX, // Empty iterator
        }
    }

    fn dynamic_symbol_table(&self) -> Option<Self::SymbolTable<'_>> {
        None
    }

    fn dynamic_relocations(&self) -> Option<Self::DynamicRelocationIterator<'_>> {
        None
    }

    fn imports(&self) -> Result<alloc::vec::Vec<Import<'data>>> {
        // Only true external symbols are imports in OMF
        // LocalExternal (LEXTDEF) are module-local references that should be resolved
        // within the same module by LocalPublic (LPUBDEF) symbols
        Ok(self
            .all_symbols()
            .iter()
            .filter(|sym| {
                matches!(
                    sym.class,
                    super::OmfSymbolClass::External | super::OmfSymbolClass::ComdatExternal
                )
            })
            .map(|ext| Import {
                library: ByteString(b""),
                name: ByteString(ext.name),
            })
            .collect())
    }

    fn exports(&self) -> Result<alloc::vec::Vec<Export<'data>>> {
        // Only true public symbols are exports in OMF
        // LocalPublic (LPUBDEF) are module-local symbols not visible outside
        Ok(self
            .all_symbols()
            .iter()
            .filter(|sym| sym.class == super::OmfSymbolClass::Public)
            .map(|pub_sym| Export {
                name: ByteString(pub_sym.name),
                address: pub_sym.offset as u64,
            })
            .collect())
    }

    fn has_debug_symbols(&self) -> bool {
        false
    }

    fn mach_uuid(&self) -> Result<Option<[u8; 16]>> {
        Ok(None)
    }

    fn build_id(&self) -> Result<Option<&'data [u8]>> {
        Ok(None)
    }

    fn gnu_debuglink(&self) -> Result<Option<(&'data [u8], u32)>> {
        Ok(None)
    }

    fn gnu_debugaltlink(&self) -> Result<Option<(&'data [u8], &'data [u8])>> {
        Ok(None)
    }

    fn pdb_info(&self) -> Result<Option<crate::read::CodeView<'_>>> {
        Ok(None)
    }

    fn relative_address_base(&self) -> u64 {
        0
    }

    fn entry(&self) -> u64 {
        0
    }

    fn flags(&self) -> FileFlags {
        FileFlags::None
    }
}
