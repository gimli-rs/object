use core::fmt::Debug;
use core::mem;

use alloc::vec::Vec;

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
    GoffComdat, GoffComdatIterator, GoffRelocation, GoffSection, GoffSectionIterator, GoffSegment,
    GoffSegmentIterator, GoffSegmentRef, GoffSymbol, GoffSymbolIterator, GoffSymbolTable,
    GoffTextReference,
};

///
/// This is a file that starts with [`goff::HeaderRecord64`], and corresponds
/// to [`crate::FileKind::Goff64`].
pub type GoffFile64<'data, R = &'data [u8]> = GoffFile<'data, R>;

/// A parsed GOFF file.
///
/// Most functionality is provided by the [`Object`] trait implementation.
#[derive(Debug)]
pub struct GoffFile<'data, R = &'data [u8]>
where
    R: ReadRef<'data>,
{
    pub(super) data: R,
    pub(super) header: &'data goff::HeaderRecord64,
    pub(super) sections: Vec<SymbolIndex>,
    pub(super) segments: HashMap<SymbolIndex, GoffSegment<'data>>,
    pub(super) symbols: HashMap<SymbolIndex, GoffSymbol<'data>>,
    pub(super) relocations: Vec<GoffRelocation>,
    pub(super) record_count: Option<u32>,
    pub(super) entry_name: Vec<&'data [u8]>,
    pub(super) entry_flags: Option<u8>,
    pub(super) entry_amode: Option<u8>,
    pub(super) entry_esdid: Option<u32>,
    pub(super) entry_offset: Option<u32>,
}

impl<'data, R> GoffFile<'data, R>
where
    R: ReadRef<'data>,
{
    /// Parse raw GOFF file data. Only fixed length records are supported
    pub fn parse(data: R) -> Result<Self> {
        if (data.len().unwrap() % goff::RECORD_LEN) != 0 {
            return Err(Error(
                "Bad GOFF file length, only fixed length GOFF records are supported",
            ));
        }

        let mut offset = 0;
        let header = goff::HeaderRecord64::parse(data, &mut offset)?;
        let mut file = GoffFile {
            data,
            header,
            sections: Vec::new(),
            segments: HashMap::new(),
            symbols: HashMap::new(),
            relocations: Vec::new(),
            record_count: None,
            entry_name: Vec::new(),
            entry_flags: None,
            entry_amode: None,
            entry_esdid: None,
            entry_offset: None,
        };

        file.parse_records(&mut offset)?;
        Ok(file)
    }

    /// Parses the body of a GOFF file (each record after the module header record)
    pub fn parse_records(&mut self, offset: &mut u64) -> Result<()> {
        while let Ok(record_prefix) = self.data.read_at::<goff::RecordPrefix>(*offset) {
            if !record_prefix.is_valid() {
                return Err(Error(
                    "Invalid GOFF prefix or version encountered while parsing",
                ));
            }

            match record_prefix.record_type() {
                RT_ESD => self.parse_esd(offset, record_prefix.is_continued())?,
                RT_TXT => self.parse_txt(offset, record_prefix.is_continued())?,
                RT_RLD => {
                    self.parse_relocations(offset, record_prefix.is_continued())?;
                }
                RT_LEN => {
                    self.parse_len_record(offset, record_prefix.is_continued())?;
                }
                RT_END => {
                    self.parse_end(offset, record_prefix.is_continued())?;
                    break;
                }
                _ => return Err(Error("Invalid GOFF record type encountered while parsing")),
            }
        }
        Ok(())
    }

    /// Parses ESD records and their continuations, incrementing offset
    pub fn parse_esd(&mut self, offset: &mut u64, is_continued: bool) -> Result<()> {
        let esd_record = self
            .data
            .read::<SymbolRecord64>(offset)
            .map_err(|_| Error("failed to read esd record"))?;

        // grab element symbol ID and parent
        let esdid = esd_record.esdid.get(BE);
        let symbolindex = SymbolIndex(
            usize::try_from(esdid).expect("Target architecture pointer size is too small"),
        );
        let parent_esdid = esd_record.parentesdid.get(BE);
        let parent_symbolindex = SymbolIndex(
            usize::try_from(parent_esdid).expect("Target architecture pointer size is too small"),
        );

        // parse continuations if any (provides name data)
        let mut cont_data: Vec<&'data [u8]>;
        if is_continued {
            cont_data = self.parse_continuations(offset)?;
        } else {
            cont_data = Vec::new();
        }

        // names are non-contiguous data encoded in EBCDIC, create vector of raw name data
        let name_length: usize = esd_record.namelength.get(BE).into();
        let capped_length = name_length.clamp(0, SIZEOF_ESD_DATA);
        let mut esd_name_data: Vec<&'data [u8]> = vec![&esd_record.name[0..capped_length]];
        esd_name_data.append(&mut cont_data);

        let goffsymbol = GoffSymbol {
            symbolindex: symbolindex,
            esdid: esdid,
            name: esd_name_data,
            symboltype: esd_record.symboltype,
            parentesdid: parent_symbolindex,
            offset: esd_record.offset.get(BE),
            length: esd_record.length.get(BE),
            eaesdid: esd_record.eaesdid.get(BE),
            eadataoffset: esd_record.eadataoffset.get(BE),
            namespaceid: esd_record.namespaceid,
            symflags: esd_record.symflags,
            fillbytevalue: esd_record.fillbytevalue,
            adaesdid: esd_record.adaesdid.get(BE),
            priority: esd_record.priority.get(BE),
            behavioralattributes: esd_record.behavioralattributes,
            namelength: esd_record.namelength.get(BE),
        };
        // insert into symbol table (and section table if appropriate)
        self.symbols.insert(symbolindex, goffsymbol);
        // Only ED (Element Definition) represents user sections
        // SD (Section Definition) is the compile unit, not a user section
        if esd_record.symboltype == ESD_SYMTYPE_ED {
            self.sections.push(symbolindex);
        }

        Ok(())
    }

    /// Parses TXT records and their continuations, incrementing offset
    pub fn parse_txt(&mut self, offset: &mut u64, is_continued: bool) -> Result<()> {
        let txt_record = self
            .data
            .read::<TextRecord64>(offset)
            .map_err(|_| Error("failed to read txt record"))?;
        let esdid = txt_record.elementesdid.get(BE);

        let symbolindex = SymbolIndex(
            usize::try_from(esdid).expect("Target architecture pointer size is too small"),
        );

        // if esdid is a PR, get the parent ED
        let symbol = self
            .symbols
            .get(&symbolindex)
            .ok_or(Error("txt record references undefined symbol"))?;
        let ed_symbolindex: SymbolIndex = match symbol.symboltype() {
            ESD_SYMTYPE_ED => symbolindex,
            _ => symbol.parentesdid(),
        };

        // Parse continuations if any
        let mut cont_data: Vec<&'data [u8]>;
        if is_continued {
            cont_data = self.parse_continuations(offset)?;
        } else {
            cont_data = Vec::new();
        }

        // Create text reference
        let data_length = usize::from(txt_record.datalength.get(BE));
        // Only slice up to the size of the data field in this record (56 bytes max)
        let initial_data_len = data_length.min(goff::SIZEOF_TXT_DATA);
        let mut text_ref = GoffTextReference {
            esdid: symbolindex,
            recordstyle: txt_record.recordstyle,
            offset: txt_record.offset.get(BE),
            true_length: txt_record.truelength.get(BE),
            text_encoding: txt_record.textencoding.get(BE),
            data_length: txt_record.datalength.get(BE),
            text_data: vec![&txt_record.data[..initial_data_len]],
        };
        text_ref.text_data.append(&mut cont_data);

        // Update segments map with new text data if ED ESDID already exists
        if let Some(segment) = self.segments.get_mut(&ed_symbolindex) {
            segment.text_refs.push(text_ref);
        } else {
            // insert new segment into segments map
            let ed_symbol = self
                .symbols
                .get(&ed_symbolindex)
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
    pub fn parse_end(&mut self, offset: &mut u64, is_continued: bool) -> Result<()> {
        let end_record = self
            .data
            .read::<EndRecord64>(offset)
            .map_err(|_| Error("failed to read end record"))?;

        // Parse record count and entry flags first
        self.record_count = Some(end_record.recordcnt.get(BE)).filter(|&cnt| cnt != 0);
        self.entry_flags = Some(end_record.flags).filter(|&flags| flags != 0);

        // If entry flags are empty (i.e, 0) no entry point specified and no need to continue
        if self.entry_flags.is_none() {
            self.entry_amode = None;
            self.entry_esdid = None;
            return Ok(());
        }

        // Parse entry point data
        self.entry_amode = Some(end_record.amode);
        self.entry_esdid = Some(end_record.esdid.get(BE));
        let name_length: usize = end_record.name_length.get(BE).into();
        let capped_length = name_length.clamp(0, SIZEOF_ENTRY_POINT_NAME);
        self.entry_name
            .push(&end_record.entry_name[0..capped_length]);

        // If entry name is too large, need to parse the rest from continuation records
        if is_continued {
            let mut name_data = self.parse_continuations(offset)?;
            self.entry_name.append(&mut name_data);
        }
        Ok(())
    }

    /// Parses continuation records until none are left (incrementing offset)
    pub fn parse_continuations(&self, offset: &mut u64) -> Result<Vec<&'data [u8]>> {
        let mut cont_data: Vec<&[u8]> = Vec::new();
        loop {
            let record_prefix = self.data.read_at::<goff::RecordPrefix>(*offset).unwrap();
            let cont_record = self.data.read::<ContinuationRecord64>(offset).unwrap();
            cont_data.push(&cont_record.data[..]);

            if !record_prefix.is_continued() {
                break;
            }
        }
        Ok(cont_data)
    }

    /// Parses individual relocation items from a byte buffer
    /// Items are variable size (8-28 bytes) depending on compression flags
    fn parse_relocation_items(&self, data: &[u8], data_length: u16) -> Result<Vec<GoffRelocation>> {
        let mut relocations = Vec::new();
        let mut cursor = 0;
        let mut prev_r_pointer: Option<u32> = None;
        let mut prev_p_pointer: Option<u32> = None;
        let mut prev_offset: Option<u32> = None;

        // The length field indicates total bytes of relocation data to parse
        let rld_end = (data_length as usize).min(data.len());

        // Parse items until we've consumed all the relocation data
        while cursor < rld_end {
            // Need at least 8 bytes for flags (6) + reserved (2)
            if cursor + 8 > rld_end {
                break;
            }

            // Peek at flags to calculate item size
            let flags_bytes: [u8; 6] = data[cursor..cursor + 6]
                .try_into()
                .map_err(|_| Error("failed to read relocation flags"))?;
            let flags = super::RelocationFlags::from_bytes(flags_bytes);

            // Calculate expected item size based on flags
            let mut item_size = 8; // flags (6) + reserved (2)
            if !flags.same_r_id() {
                item_size += 4; // R-pointer
            }
            if !flags.same_p_id() {
                item_size += 4; // P-pointer
            }
            if !flags.same_offset() {
                item_size += 4; // Offset
            }

            // Check if complete item fits within valid data
            if cursor + item_size > rld_end {
                // Incomplete item at end - stop parsing
                break;
            }

            // Now parse the item
            cursor += 6; // Skip flags
            cursor += 2; // Skip reserved

            // Parse R-pointer (conditionally)
            let r_pointer = if !flags.same_r_id() {
                let val = u32::from_be_bytes(data[cursor..cursor + 4].try_into().unwrap());
                cursor += 4;
                val
            } else {
                prev_r_pointer.ok_or(Error("R-pointer compression without previous value"))?
            };

            // Parse P-pointer (conditionally)
            let p_pointer = if !flags.same_p_id() {
                let val = u32::from_be_bytes(data[cursor..cursor + 4].try_into().unwrap());
                cursor += 4;
                val
            } else {
                prev_p_pointer.ok_or(Error("P-pointer compression without previous value"))?
            };

            // Parse Offset (conditionally)
            let offset = if !flags.same_offset() {
                let val = u32::from_be_bytes(data[cursor..cursor + 4].try_into().unwrap());
                cursor += 4;
                val
            } else {
                prev_offset.ok_or(Error("Offset compression without previous value"))?
            };

            // Create and store relocation
            relocations.push(GoffRelocation {
                flags,
                r_pointer,
                p_pointer,
                offset,
            });

            // Update previous values for next iteration
            prev_r_pointer = Some(r_pointer);
            prev_p_pointer = Some(p_pointer);
            prev_offset = Some(offset);
        }

        Ok(relocations)
    }

    /// Parses a RelocationRecord64 and its continuations, extracting individual relocation items
    pub fn parse_relocations(&mut self, offset: &mut u64, is_continued: bool) -> Result<()> {
        // Read the main RLD record
        let rel_record = self
            .data
            .read::<RelocationRecord64>(offset)
            .map_err(|_| Error("failed to read relocation record"))?;

        // Get the length field which indicates how much relocation data is present
        let data_length = rel_record.length.get(BE);

        // Start with main record data (74 bytes)
        let mut all_data: Vec<u8> = rel_record.data.to_vec();

        // Append continuation data if present (77 bytes per continuation)
        if is_continued {
            let cont_data = self.parse_continuations(offset)?;
            for chunk in cont_data {
                all_data.extend_from_slice(chunk);
            }
        }

        // Parse individual items from concatenated buffer using the length field
        let relocations = self.parse_relocation_items(&all_data, data_length)?;

        // Store each relocation in file.relocations
        self.relocations.extend(relocations);

        Ok(())
    }

    /// Parses a LenRecord64 and its continuations, extracting deferred element-length data items
    /// and updating the corresponding symbols with their lengths
    pub fn parse_len_record(&mut self, offset: &mut u64, is_continued: bool) -> Result<()> {
        // Read the main LEN record
        let len_record = self
            .data
            .read::<LenRecord64>(offset)
            .map_err(|_| Error("failed to read len record"))?;

        // Get the length field which indicates how much length data is present
        let data_length = len_record.length.get(BE);

        // Start with main record data (72 bytes)
        let mut all_data: Vec<u8> = len_record.data.to_vec();

        // Append continuation data if present (77 bytes per continuation)
        if is_continued {
            let cont_data = self.parse_continuations(offset)?;
            for chunk in cont_data {
                all_data.extend_from_slice(chunk);
            }
        }

        // Calculate number of data items (each LengthDataItem is 12 bytes)
        const ITEM_SIZE: usize = mem::size_of::<LengthDataItem>();
        let num_items = (data_length as usize) / ITEM_SIZE;

        // Parse each LengthDataItem from the buffer
        let mut cursor: u64 = 0;
        for _ in 0..num_items {
            if cursor + ITEM_SIZE as u64 > all_data.len() as u64 {
                break; // Incomplete item at end
            }

            // Parse the item from the buffer using read
            let item = all_data
                .as_slice()
                .read::<LengthDataItem>(&mut cursor)
                .map_err(|_| Error("failed to read length data item"))?;

            let esdid = item.esdid.get(BE);
            let length = item.length.get(BE);

            // Update symbol in HashMap
            let symbolindex = SymbolIndex(
                usize::try_from(esdid).expect("Target architecture pointer size is too small"),
            );

            let symbol = self
                .symbols
                .get_mut(&symbolindex)
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
    pub fn symbol_records(&self) -> &HashMap<SymbolIndex, GoffSymbol<'data>> {
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
        = GoffSymbol<'data>
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
        GoffSegmentIterator {
            file: self,
            iter: self.segments.keys(),
        }
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
        unimplemented!(); // currently unsupported
    }

    fn symbol_table(&self) -> Option<GoffSymbolTable<'data, '_, R>> {
        Some(GoffSymbolTable { file: self })
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> Result<GoffSymbol<'data>> {
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
        GoffSymbolIterator {
            file: self,
            index: SymbolIndex(0),
            esdid_map: self
                .symbols
                .keys()
                .filter(|idx| {
                    let Some(sym) = self.symbols.get(idx) else {
                        return false;
                    };

                    let scope = sym.behavioral_flags().binding_scope();
                    let is_explicit_import = sym.symflags & 0x08 != 0;
                    let is_import_er =
                        sym.symboltype() == ESD_SYMTYPE_ER && scope == GOFF_SCOPE_IMPORT_EXPORT;
                    let is_export_def = matches!(sym.symboltype(), ESD_SYMTYPE_ED | ESD_SYMTYPE_LD)
                        && scope == GOFF_SCOPE_IMPORT_EXPORT;

                    is_explicit_import || is_import_er || is_export_def
                })
                .copied()
                .collect(),
        }
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
        // GOFF doesn't provide fixed Debug classes / debug sections
        unimplemented!();
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
            archlvl: self.header.archlvl(),
            flags: self.entry_flags.map(|f| goff::FileFlags(f)),
            amode: self.entry_amode,
        }
    }
}

impl goff::HeaderRecord64 {
    /// Prefix (first 3 bytes) in module header record serves as magic number
    fn magic(&self) -> [u8; 3] {
        self.ptv
    }

    /// Returns architecture level
    fn archlvl(&self) -> u32 {
        self.archlvl.get(BE)
    }

    /// Verifies header prefix contains proper magic
    fn is_supported(&self) -> bool {
        self.magic() == goff::GOFF_HDR_BYTES
    }

    /// Read the file header.
    ///
    /// Also checks that the magic field in the file header is a supported format.
    fn parse<'data, R: ReadRef<'data>>(data: R, offset: &mut u64) -> Result<&'data Self> {
        let header: &Self = data
            .read::<Self>(offset)
            .read_error("Invalid GOFF header size or alignment")?;
        if !header.is_supported() {
            return Err(Error("Unsupported GOFF header"));
        }
        Ok(header)
    }
}

/// An iterator for the symbols in an [`GoffFile64`](super::GoffFile64).
pub type GoffSymbolIterator64<'data, 'file, R = &'data [u8]> = GoffSymbolIterator<'data, 'file, R>;
