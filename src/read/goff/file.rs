use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::marker::PhantomData;

use crate::read::{
    self, Error, NoDynamicRelocationIterator, NoExportIterator, NoImportIterator,
    NoImportLibraryIterator, Object, ReadError, ReadRef, Result,
};

use crate::{
    Architecture, BigEndian as BE, FileFlags, ObjectKind, ObjectSymbolTable, SectionIndex,
    SymbolIndex, goff,
};

use crate::goff::*;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as HashMap;
#[cfg(feature = "std")]
use std::collections::HashMap;

use super::{
    GoffComdat, GoffComdatIterator, GoffSection, GoffSectionIterator, GoffSegment,
    GoffSegmentIterator, GoffSegmentRef, GoffSymbol, GoffSymbolIterator, GoffSymbolTable,
    GoffTextReference, LogicalRecord,
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
    pub(super) sections: Vec<SymbolIndex>,
    pub(super) segments: HashMap<SymbolIndex, GoffSegment<'data>>,
    pub(super) symbols: Vec<GoffSymbol>,
    pub(super) relocations: Vec<goff::Relocation>,
    pub(super) record_count: Option<u32>,
    pub(super) entry_name: Cow<'data, [u8]>,
    pub(super) entry_flags: Option<goff::FileFlags>,
    pub(super) entry_amode: Option<goff::Amode>,
    pub(super) entry_esdid: Option<u32>,
    pub(super) entry_offset: Option<u32>,
    marker: PhantomData<R>,
}

impl<'data, R> GoffFile<'data, R>
where
    R: ReadRef<'data>,
{
    /// Parse raw GOFF file data. Only fixed length records are supported
    pub fn parse(data: R) -> Result<Self> {
        let header = goff::HeaderRecord::parse(data)?;
        let records = header.records(data)?;

        let mut file = GoffFile {
            header,
            sections: Vec::new(),
            segments: HashMap::new(),
            symbols: Vec::new(),
            relocations: Vec::new(),
            record_count: None,
            entry_name: Cow::Borrowed(&[]),
            entry_flags: None,
            entry_amode: None,
            entry_esdid: None,
            entry_offset: None,
            marker: PhantomData,
        };

        file.parse_records(records)?;
        Ok(file)
    }

    /// Parses the body of a GOFF file (each record after the module header record)
    fn parse_records(&mut self, mut records: &'data [goff::Record]) -> Result<()> {
        while let Some(record) = LogicalRecord::parse(&mut records)? {
            match record.initial.ptv.record_type() {
                RT_ESD => self.parse_esd(record.cast())?,
                RT_TXT => self.parse_txt(record.cast())?,
                RT_RLD => {
                    self.parse_relocations(record.cast())?;
                }
                RT_LEN => {
                    self.parse_len_record(record.cast())?;
                }
                RT_END => {
                    self.parse_end(record.cast())?;
                    break;
                }
                _ => return Err(Error("Invalid GOFF record type encountered while parsing")),
            }
        }
        Ok(())
    }

    fn parse_esd(&mut self, record: LogicalRecord<'data, goff::SymbolRecord>) -> Result<()> {
        let esd_record = record.initial;

        // grab element symbol ID and parent
        let esdid = esd_record.esdid.get(BE);
        let symbolindex = SymbolIndex(
            usize::try_from(esdid).expect("Target architecture pointer size is too small"),
        );
        let parent_esdid = esd_record.parent_esdid.get(BE);
        let parent_symbolindex = SymbolIndex(
            usize::try_from(parent_esdid).expect("Target architecture pointer size is too small"),
        );

        // Flatten name from the ESD record and any continuation records into a single Vec<u8>
        let name = record.esd_name()?.into_owned();

        let goffsymbol = GoffSymbol {
            symbol_index: symbolindex,
            esdid,
            name,
            symbol_type: esd_record.symbol_type,
            parent_esdid: parent_symbolindex,
            offset: esd_record.offset.get(BE),
            length: esd_record.length.get(BE),
            ea_esdid: esd_record.ea_esdid.get(BE),
            ea_data_offset: esd_record.ea_data_offset.get(BE),
            namespace: esd_record.namespace,
            flags: esd_record.flags,
            fill_byte_value: esd_record.fill_byte_value,
            ada_esdid: esd_record.ada_esdid.get(BE),
            priority: esd_record.priority.get(BE),
            behavioral_attributes: esd_record.behavioral_attributes,
            name_length: esd_record.name_length.get(BE),
        };
        // insert into symbol table (and section table if appropriate)
        // ESDIDs are 1-based and sequential; push ensures index == esdid - 1
        self.symbols.push(goffsymbol);
        // Only ED (Element Definition) represents user sections
        // SD (Section Definition) is the compile unit, not a user section
        if esd_record.symbol_type == ESD_ST_ED {
            self.sections.push(symbolindex);
        }

        Ok(())
    }

    fn parse_txt(&mut self, record: LogicalRecord<'data, goff::TextRecord>) -> Result<()> {
        let txt_record = record.initial;
        let esdid = txt_record.element_esdid.get(BE);

        let symbolindex = SymbolIndex(
            usize::try_from(esdid).expect("Target architecture pointer size is too small"),
        );

        // if esdid is a PR, get the parent ED
        let symbol = self
            .symbols
            .get(esdid as usize - 1)
            .ok_or(Error("txt record references undefined symbol"))?;
        let ed_symbolindex: SymbolIndex = match symbol.symbol_type() {
            ESD_ST_ED => symbolindex,
            _ => symbol.parent_esdid(),
        };

        // Create text reference
        let text_ref = GoffTextReference {
            esdid: symbolindex,
            record_style: txt_record.record_style,
            offset: txt_record.offset.get(BE),
            true_length: txt_record.true_length.get(BE),
            text_encoding: txt_record.text_encoding.get(BE),
            data_length: txt_record.data_length.get(BE),
            text_data: record.txt_data_parts()?.collect(),
        };

        // Update segments map with new text data if ED ESDID already exists
        if let Some(segment) = self.segments.get_mut(&ed_symbolindex) {
            segment.text_refs.push(text_ref);
        } else {
            // insert new segment into segments map
            let ed_symbol = self
                .symbols
                .get(ed_symbolindex.0 - 1)
                .ok_or(Error("ED symbol not found for segment"))?
                .clone();
            let segment = GoffSegment {
                symbol: ed_symbol,
                text_refs: vec![text_ref],
            };
            self.segments.insert(ed_symbolindex, segment);
        }

        Ok(())
    }

    /// Parses the END record (if an entry point is specified, will be parsed here)
    fn parse_end(&mut self, record: LogicalRecord<'data, goff::EndRecord>) -> Result<()> {
        let end_record = record.initial;

        // Parse record count and entry flags first
        self.record_count = Some(end_record.record_count.get(BE)).filter(|&cnt| cnt != 0);
        self.entry_flags = Some(end_record.flags).filter(|f| f.entry() != goff::ENTRY_NONE);

        // If entry flags are empty (i.e, 0) no entry point specified and no need to continue
        if self.entry_flags.is_none() {
            self.entry_amode = None;
            self.entry_esdid = None;
            return Ok(());
        }

        // Parse entry point data
        self.entry_amode = Some(end_record.amode);
        self.entry_esdid = Some(end_record.esdid.get(BE));
        self.entry_name = record.entry_name()?;
        Ok(())
    }

    /// Parses a RelocationRecord and its continuations, extracting individual relocation items
    fn parse_relocations(
        &mut self,
        record: LogicalRecord<'data, goff::RelocationRecord>,
    ) -> Result<()> {
        for relocation in record.rld_items()? {
            self.relocations.push(relocation?);
        }
        Ok(())
    }

    /// Parses a LengthRecord and its continuations, extracting deferred element-length data items
    /// and updating the corresponding symbols with their lengths
    fn parse_len_record(&mut self, record: LogicalRecord<'data, goff::LengthRecord>) -> Result<()> {
        for item in record.len_items()? {
            let esdid = item.esdid.get(BE);
            let length = item.length.get(BE);

            // Update symbol in Vec (ESDIDs are 1-based)
            let idx =
                usize::try_from(esdid).expect("Target architecture pointer size is too small");

            let symbol = self
                .symbols
                .get_mut(idx - 1)
                .ok_or(Error("LEN record references undefined symbol"))?;

            symbol.length = length;
        }

        Ok(())
    }

    /// Access all symbols including ED and SD.
    ///
    /// This method provides access to the complete symbol table for internal
    /// operations and testing that need to traverse parent relationships or access
    /// structural metadata symbols (ED/SD).
    ///
    /// **Note:** This is primarily for internal use and testing. For the public API,
    /// use `symbol_table()` which filters out ED/SD symbols.
    pub fn symbol_records(&self) -> &Vec<GoffSymbol> {
        &self.symbols
    }
}

impl<'data, R> read::private::Sealed for GoffFile<'data, R> where R: ReadRef<'data> {}

//DC: Object trait definition at read/traits.rs
impl<'data, R> Object<'data> for GoffFile<'data, R>
where
    R: ReadRef<'data>,
{
    type Segment<'file>
        = GoffSegmentRef<'data, 'file, R>
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
        = GoffSymbol
    where
        Self: 'file,
        'data: 'file;
    type SymbolIterator<'file>
        = GoffSymbolIterator<'data, 'file, R>
    where
        Self: 'file,
        'data: 'file;
    type SymbolTable<'file>
        = GoffSymbolTable<'data, 'file, R>
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
        ObjectKind::Unknown
    }

    fn segments(&self) -> GoffSegmentIterator<'data, '_, R> {
        GoffSegmentIterator { file: self }
    }

    fn section_by_name_bytes<'file>(
        &'file self,
        _section_name: &[u8],
    ) -> Option<GoffSection<'data, 'file, R>> {
        // GOFF does not have unique section names or continguent section name bytes
        None
    }

    fn section_by_index(&self, index: SectionIndex) -> Result<GoffSection<'data, '_, R>> {
        let esdid = *self
            .sections
            .get(index.0)
            .ok_or(Error("Invalid GOFF section index"))?;
        Ok(GoffSection {
            file: self,
            esdid,
            index,
        })
    }

    fn sections(&self) -> GoffSectionIterator<'data, '_, R> {
        GoffSectionIterator {
            file: self,
            iter: self.sections.iter(),
            index: 0,
        }
    }

    fn comdats(&self) -> GoffComdatIterator<'data, '_, R> {
        GoffComdatIterator { file: self }
    }

    fn symbol_table(&self) -> Option<GoffSymbolTable<'data, '_, R>> {
        Some(GoffSymbolTable { file: self })
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> Result<GoffSymbol> {
        let symbol_table = self.symbol_table().ok_or(Error("missing symbol table"))?;
        symbol_table.symbol_by_index(index)
    }

    fn symbols(&self) -> GoffSymbolIterator<'data, '_, R> {
        let symbol_table = self.symbol_table().unwrap();
        symbol_table.symbols()
    }

    fn dynamic_symbol_table(&self) -> Option<GoffSymbolTable<'data, '_, R>> {
        // Access dynamic symbols through dynamic_symbols() method
        None
    }

    fn dynamic_symbols(&self) -> GoffSymbolIterator<'data, '_, R> {
        let symbol_table = GoffSymbolTable { file: self };
        symbol_table.iter_none()
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
        // Check if any symbol name begins with the debug symbol prefix [0xC4, 0x6D] (i.e., the prefix D_ in EBCDIC)
        self.symbols.iter().any(|symbol| {
            let name = symbol.name_bytes_owned();
            name.len() >= 2 && name[0] == 0xC4 && name[1] == 0x6D
        })
    }

    fn relative_address_base(&self) -> u64 {
        0
    }

    fn entry(&self) -> u64 {
        match self.entry_offset {
            Some(offset) => offset.into(),
            None => 0,
        }
    }

    fn flags(&self) -> FileFlags {
        FileFlags::Goff {
            archlvl: self.header.archlvl.get(BE),
            flags: self.entry_flags,
            amode: self.entry_amode,
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
