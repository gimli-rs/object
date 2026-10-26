use core::fmt::Debug;
use core::marker::PhantomData;

use crate::ebcdic::{EbcdicArray, EbcdicString};
use crate::read::{
    self, Error, NoDynamicRelocationIterator, NoExportIterator, NoImportIterator,
    NoImportLibraryIterator, Object, ReadError, ReadRef, Result,
};

use crate::{
    Architecture, BigEndian as BE, FileFlags, ObjectKind, ObjectSymbolTable, SectionIndex,
    SymbolIndex, goff,
};

use crate::goff::*;

use super::{
    GoffComdat, GoffComdatIterator, GoffSection, GoffSectionIterator, GoffSectionTableInternal,
    GoffSegment, GoffSegmentIterator, GoffSymbol, GoffSymbolIterator, GoffSymbolTable,
    GoffSymbolTableInternal, LogicalRecord,
};

/// A parsed GOFF file.
///
/// Most functionality is provided by the [`Object`] trait implementation.
#[derive(Debug)]
pub struct GoffFile<'data, R = &'data [u8]>
where
    R: ReadRef<'data>,
{
    pub(super) header: &'data goff::HeaderRecord,
    pub(super) sections: GoffSectionTableInternal<'data>,
    pub(super) symbols: GoffSymbolTableInternal<'data>,
    pub(super) end: LogicalRecord<'data, goff::EndRecord>,
    marker: PhantomData<R>,
}

impl<'data, R> GoffFile<'data, R>
where
    R: ReadRef<'data>,
{
    /// Parse raw GOFF file data. Only fixed length records are supported
    pub fn parse(data: R) -> Result<Self> {
        let header = goff::HeaderRecord::parse(data)?;

        let mut symbols = GoffSymbolTableInternal::new();
        let mut sections = GoffSectionTableInternal::new();
        let end;

        let mut records = header.records(data)?;
        loop {
            let Some(record) = LogicalRecord::parse(&mut records)? else {
                return Err(Error("Missing GOFF END record"));
            };
            match record.initial.ptv.record_type() {
                RT_ESD => symbols.add_esd(record.cast(), &mut sections)?,
                RT_TXT => sections.add_txt(&symbols, record.cast())?,
                RT_RLD => sections.add_rld(&symbols, record.cast())?,
                RT_LEN => symbols.add_len(record.cast())?,
                RT_END => {
                    end = record.cast();
                    break;
                }
                _ => return Err(Error("Invalid GOFF record type encountered while parsing")),
            }
        }

        sections.finalize(&mut symbols)?;

        Ok(GoffFile {
            header,
            sections,
            symbols,
            end,
            marker: PhantomData,
        })
    }

    /// Get the raw GOFF HDR record.
    pub fn goff_header(&self) -> &'data goff::HeaderRecord {
        self.header
    }

    /// Get the raw GOFF END record and its continuation records.
    pub fn goff_end(&self) -> LogicalRecord<'data, goff::EndRecord> {
        self.end
    }
}

impl<'data, R> read::private::Sealed for GoffFile<'data, R> where R: ReadRef<'data> {}

//DC: Object trait definition at read/traits.rs
impl<'data, R> Object<'data> for GoffFile<'data, R>
where
    R: ReadRef<'data>,
{
    type Segment<'file>
        = GoffSegment<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type SegmentIterator<'file>
        = GoffSegmentIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type Section<'file>
        = GoffSection<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type SectionIterator<'file>
        = GoffSectionIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type Comdat<'file>
        = GoffComdat<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type ComdatIterator<'file>
        = GoffComdatIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type Symbol<'file>
        = GoffSymbol<'data, 'file>
    where
        Self: 'file,
        'data: 'file;
    type SymbolIterator<'file>
        = GoffSymbolIterator<'data, 'file>
    where
        Self: 'file,
        'data: 'file;
    type SymbolTable<'file>
        = GoffSymbolTable<'data, 'file>
    where
        Self: 'file,
        'data: 'file;
    type DynamicRelocationIterator<'file>
        = NoDynamicRelocationIterator
    where
        Self: 'file,
        'data: 'file;
    type ImportLibraryIterator<'file>
        = NoImportLibraryIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type ImportIterator<'file>
        = NoImportIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type ExportIterator<'file>
        = NoExportIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;

    fn architecture(&self) -> crate::Architecture {
        Architecture::S390x
    }

    fn is_little_endian(&self) -> bool {
        false
    }

    fn is_64(&self) -> bool {
        true
    }

    fn kind(&self) -> ObjectKind {
        ObjectKind::Relocatable
    }

    fn segments(&self) -> GoffSegmentIterator<'data, '_, R> {
        GoffSegmentIterator { file: self }
    }

    fn section_by_name_bytes<'file>(
        &'file self,
        section_name: &[u8],
    ) -> Option<GoffSection<'data, 'file, R>> {
        let section_name = EbcdicString::from_utf8(section_name)?;
        self.sections()
            .find(|section| *section.goff_name() == *section_name)
    }

    fn section_by_index(&self, index: SectionIndex) -> Result<GoffSection<'data, '_, R>> {
        let section = self
            .sections
            .get(index)
            .read_error("Invalid GOFF section index")?;
        Ok(GoffSection::new(self, index, section))
    }

    fn sections(&self) -> GoffSectionIterator<'data, '_, R> {
        GoffSectionIterator {
            file: self,
            iter: self.sections.iter().enumerate(),
        }
    }

    fn comdats(&self) -> GoffComdatIterator<'data, '_, R> {
        GoffComdatIterator { file: self }
    }

    fn symbol_table(&self) -> Option<GoffSymbolTable<'data, '_>> {
        Some(GoffSymbolTable::new(&self.symbols))
    }

    fn symbol_by_name_bytes<'file>(
        &'file self,
        symbol_name: &[u8],
    ) -> Option<GoffSymbol<'data, 'file>> {
        let symbol_name = EbcdicString::from_utf8(symbol_name)?;
        self.symbols()
            .find(|symbol| *symbol.goff_name() == *symbol_name)
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> Result<GoffSymbol<'data, '_>> {
        GoffSymbolTable::new(&self.symbols).symbol_by_index(index)
    }

    fn symbols(&self) -> GoffSymbolIterator<'data, '_> {
        GoffSymbolIterator::new(&self.symbols)
    }

    fn dynamic_symbol_table(&self) -> Option<GoffSymbolTable<'data, '_>> {
        // Access dynamic symbols through dynamic_symbols() method
        None
    }

    fn dynamic_symbols(&self) -> GoffSymbolIterator<'data, '_> {
        GoffSymbolIterator::empty()
    }

    fn dynamic_relocations(&self) -> Option<Self::DynamicRelocationIterator<'_>> {
        None
    }

    fn import_libraries(&self) -> Result<Self::ImportLibraryIterator<'_>> {
        Ok(Default::default())
    }

    fn imports(&self) -> Result<Self::ImportIterator<'_>> {
        Ok(Default::default())
    }

    fn exports(&self) -> Result<Self::ExportIterator<'_>> {
        Ok(Default::default())
    }

    fn has_debug_symbols(&self) -> bool {
        // DWARF sections have a "D_" prefix.
        const EBCDIC_D: EbcdicArray<2> = EbcdicArray::from_ascii(*b"D_");
        self.sections()
            .any(|section| section.goff_name().starts_with(&EBCDIC_D))
    }

    fn relative_address_base(&self) -> u64 {
        0
    }

    fn entry(&self) -> u64 {
        0
    }

    fn flags(&self) -> FileFlags {
        FileFlags::Goff {
            archlvl: self.header.archlvl.get(BE),
        }
    }
}

impl goff::HeaderRecord {
    /// Read the header record.
    ///
    /// Also checks that the prefix is valid.
    pub fn parse<'data, R: ReadRef<'data>>(data: R) -> Result<&'data Self> {
        let header = data
            .read_at::<goff::HeaderRecord>(0)
            .read_error("Invalid GOFF header size or alignment")?;
        if header.ptv != goff::HDR_PREFIX {
            return Err(Error("Unsupported GOFF header"));
        }
        Ok(header)
    }

    /// Read the records following the header record.
    ///
    /// `data` must be the entire file data.
    /// Only fixed length records are supported.
    pub fn records<'data, R: ReadRef<'data>>(&self, data: R) -> Result<&'data [goff::Record]> {
        let len = data.len().read_error("Unknown GOFF file size")?;
        if len % goff::RECORD_LEN != 0 {
            return Err(Error(
                "Bad GOFF file length, only fixed length GOFF records are supported",
            ));
        }
        let count = len / goff::RECORD_LEN - 1;
        data.read_slice_at(goff::RECORD_LEN, count as usize)
            .read_error("GOFF read failed")
    }
}
