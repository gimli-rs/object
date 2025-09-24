//! OMF file implementation for the unified read API.

use crate::read::{
    self, Architecture, ByteString, ComdatKind, Error, Export, FileFlags, Import,
    NoDynamicRelocationIterator, Object, ObjectComdat, ObjectKind, ObjectSection, ObjectSegment,
    ReadRef, Result, SectionIndex, SegmentFlags, SymbolIndex,
};
use crate::SubArchitecture;

use super::{OmfFile, OmfSection, OmfSymbol, OmfSymbolIterator, OmfSymbolTable};

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
        = OmfSymbolIterator<'data, 'file>
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
        let total_publics = self.publics.len();
        let total_externals = self.externals.len();
        let total_before_communals = total_publics + total_externals;

        if idx < total_publics {
            Ok(self.publics[idx].clone())
        } else if idx < total_before_communals {
            Ok(self.externals[idx - total_publics].clone())
        } else if idx < total_before_communals + self.communals.len() {
            Ok(self.communals[idx - total_before_communals].clone())
        } else {
            Err(Error("Symbol index out of bounds"))
        }
    }

    fn symbols(&self) -> Self::SymbolIterator<'_> {
        OmfSymbolIterator {
            publics: &self.publics,
            externals: &self.externals,
            communals: &self.communals,
            index: 0,
        }
    }

    fn symbol_table(&self) -> Option<Self::SymbolTable<'_>> {
        Some(OmfSymbolTable { file: self })
    }

    fn dynamic_symbols(&self) -> Self::SymbolIterator<'_> {
        OmfSymbolIterator {
            publics: &[],
            externals: &[],
            communals: &[],
            index: 0,
        }
    }

    fn dynamic_symbol_table(&self) -> Option<Self::SymbolTable<'_>> {
        None
    }

    fn dynamic_relocations(&self) -> Option<Self::DynamicRelocationIterator<'_>> {
        None
    }

    fn imports(&self) -> Result<alloc::vec::Vec<Import<'data>>> {
        // External symbols are imports in OMF
        Ok(self
            .externals
            .iter()
            .map(|ext| Import {
                library: ByteString(b""),
                name: ByteString(ext.name),
            })
            .collect())
    }

    fn exports(&self) -> Result<alloc::vec::Vec<Export<'data>>> {
        // Public symbols are exports in OMF
        Ok(self
            .publics
            .iter()
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

/// An OMF segment reference.
#[derive(Debug)]
pub struct OmfSegmentRef<'data, 'file, R: ReadRef<'data>> {
    file: &'file OmfFile<'data, R>,
    index: usize,
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for OmfSegmentRef<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectSegment<'data> for OmfSegmentRef<'data, 'file, R> {
    fn address(&self) -> u64 {
        0
    }

    fn size(&self) -> u64 {
        self.file.segments[self.index].length as u64
    }

    fn align(&self) -> u64 {
        match self.file.segments[self.index].alignment {
            crate::omf::SegmentAlignment::Byte => 1,
            crate::omf::SegmentAlignment::Word => 2,
            crate::omf::SegmentAlignment::Paragraph => 16,
            crate::omf::SegmentAlignment::Page => 256,
            crate::omf::SegmentAlignment::DWord => 4,
            crate::omf::SegmentAlignment::Page4K => 4096,
            _ => 1,
        }
    }

    fn file_range(&self) -> (u64, u64) {
        (0, 0)
    }

    fn data(&self) -> Result<&'data [u8]> {
        // OMF segments don't have direct file mapping
        Ok(&[])
    }

    fn data_range(&self, _address: u64, _size: u64) -> Result<Option<&'data [u8]>> {
        Ok(None)
    }

    fn name_bytes(&self) -> Result<Option<&'data [u8]>> {
        Ok(self
            .file
            .get_name(self.file.segments[self.index].name_index))
    }

    fn name(&self) -> Result<Option<&'data str>> {
        let index = self.file.segments[self.index].name_index;
        let name_opt = self.file.get_name(index);
        match name_opt {
            Some(bytes) => Ok(core::str::from_utf8(bytes).ok()),
            None => Ok(None),
        }
    }

    fn flags(&self) -> SegmentFlags {
        SegmentFlags::None
    }
}

/// An iterator over OMF segments.
#[derive(Debug)]
pub struct OmfSegmentIterator<'data, 'file, R: ReadRef<'data>> {
    file: &'file OmfFile<'data, R>,
    index: usize,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfSegmentIterator<'data, 'file, R> {
    type Item = OmfSegmentRef<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.file.segments.len() {
            let segment = OmfSegmentRef {
                file: self.file,
                index: self.index,
            };
            self.index += 1;
            Some(segment)
        } else {
            None
        }
    }
}

/// An iterator over OMF sections.
#[derive(Debug)]
pub struct OmfSectionIterator<'data, 'file, R: ReadRef<'data>> {
    file: &'file OmfFile<'data, R>,
    index: usize,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfSectionIterator<'data, 'file, R> {
    type Item = OmfSection<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.file.segments.len() {
            let section = OmfSection {
                file: self.file,
                index: self.index,
            };
            self.index += 1;
            Some(section)
        } else {
            None
        }
    }
}

/// A COMDAT section in an OMF file.
#[derive(Debug)]
pub struct OmfComdat<'data, 'file, R: ReadRef<'data>> {
    file: &'file OmfFile<'data, R>,
    index: usize,
    _phantom: core::marker::PhantomData<&'data ()>,
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for OmfComdat<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectComdat<'data> for OmfComdat<'data, 'file, R> {
    type SectionIterator = OmfComdatSectionIterator<'data, 'file, R>;

    fn kind(&self) -> ComdatKind {
        let comdat = &self.file.comdats[self.index];
        match comdat.selection {
            super::OmfComdatSelection::Explicit => ComdatKind::NoDuplicates,
            super::OmfComdatSelection::UseAny => ComdatKind::Any,
            super::OmfComdatSelection::SameSize => ComdatKind::SameSize,
            super::OmfComdatSelection::ExactMatch => ComdatKind::ExactMatch,
        }
    }

    fn symbol(&self) -> SymbolIndex {
        // COMDAT symbols don't have a direct symbol index in OMF
        // Return an invalid index
        SymbolIndex(usize::MAX)
    }

    fn name_bytes(&self) -> Result<&'data [u8]> {
        let comdat = &self.file.comdats[self.index];
        Ok(comdat.name)
    }

    fn name(&self) -> Result<&'data str> {
        let comdat = &self.file.comdats[self.index];
        core::str::from_utf8(comdat.name).map_err(|_| Error("Invalid UTF-8 in COMDAT name"))
    }

    fn sections(&self) -> Self::SectionIterator {
        let comdat = &self.file.comdats[self.index];
        OmfComdatSectionIterator {
            segment_index: if comdat.segment_index > 0 {
                Some(comdat.segment_index as usize - 1)
            } else {
                None
            },
            returned: false,
            _phantom: core::marker::PhantomData,
        }
    }
}

/// An iterator over COMDAT sections.
#[derive(Debug)]
pub struct OmfComdatIterator<'data, 'file, R: ReadRef<'data>> {
    file: &'file OmfFile<'data, R>,
    index: usize,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfComdatIterator<'data, 'file, R> {
    type Item = OmfComdat<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.file.comdats.len() {
            let comdat = OmfComdat {
                file: self.file,
                index: self.index,
                _phantom: core::marker::PhantomData,
            };
            self.index += 1;
            Some(comdat)
        } else {
            None
        }
    }
}

/// An iterator over sections in a COMDAT.
#[derive(Debug)]
pub struct OmfComdatSectionIterator<'data, 'file, R: ReadRef<'data>> {
    segment_index: Option<usize>,
    returned: bool,
    _phantom: core::marker::PhantomData<(&'data (), &'file (), R)>,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfComdatSectionIterator<'data, 'file, R> {
    type Item = SectionIndex;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.returned {
            self.returned = true;
            self.segment_index.map(|idx| SectionIndex(idx + 1))
        } else {
            None
        }
    }
}
