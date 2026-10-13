use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::{fmt, iter, slice, str};

use crate::ebcdic::EbcdicStr;
use crate::goff;
use crate::read::{
    self, Error, ObjectSection, ReadError, ReadRef, RelocationMap, Result, SectionIndex,
    SymbolIndex,
};
use crate::{BigEndian as BE, CompressedData, CompressedFileRange, SectionFlags, SectionKind};

use super::{
    GoffFile, GoffRelocationIterator, GoffSymbolIndex, GoffSymbolInternal, GoffSymbolTableInternal,
    LogicalRecord,
};

/// A table of sections in a GOFF file.
#[derive(Debug)]
pub(super) struct GoffSectionTableInternal<'data> {
    sections: Vec<GoffSectionInternal<'data>>,
}

impl<'data> GoffSectionTableInternal<'data> {
    pub(super) fn new() -> Self {
        GoffSectionTableInternal {
            sections: Vec::new(),
        }
    }

    pub(super) fn add_esd(
        &mut self,
        symbols: &GoffSymbolTableInternal<'data>,
        symbol: &GoffSymbolInternal<'data>,
        symbol_index: GoffSymbolIndex,
    ) -> Option<SectionIndex> {
        match symbol.record().symbol_type {
            // Only ED (Element Definition) represents user sections.
            // SD (Section Definition) is the compile unit, not a user section.
            goff::ESD_ST_ED => {
                let section_index = SectionIndex(self.sections.len());
                self.sections.push(GoffSectionInternal {
                    symbol: symbol_index,
                    text: Vec::new(),
                    relocations: Vec::new(),
                });
                Some(section_index)
            }
            goff::ESD_ST_LD | goff::ESD_ST_PR => symbols
                .get(symbol.parent_esdid())
                .filter(|parent| parent.record().symbol_type == goff::ESD_ST_ED)
                .and_then(|parent| parent.section()),
            _ => None,
        }
    }

    pub(super) fn add_txt(
        &mut self,
        symbols: &GoffSymbolTableInternal<'data>,
        record: LogicalRecord<'data, goff::TextRecord>,
    ) -> Result<()> {
        let txt_record = record.initial;
        let esdid = SymbolIndex(txt_record.element_esdid.get(BE) as usize);
        let section_index = Self::element_section(symbols, esdid)
            .read_error("Invalid element ESDID in GOFF TXT record")?;
        self.sections[section_index.0].text.push(record);
        Ok(())
    }

    pub(super) fn add_rld(
        &mut self,
        symbols: &GoffSymbolTableInternal<'data>,
        record: LogicalRecord<'data, goff::RelocationRecord>,
    ) -> Result<()> {
        let mut relocations = record.rld_items()?;
        while let Some(relocation) = relocations.next()? {
            let p_pointer = SymbolIndex(relocation.p_pointer as usize);
            let section_index = Self::element_section(symbols, p_pointer)
                .read_error("Invalid P pointer in GOFF RLD entry")?;
            self.sections[section_index.0].relocations.push(relocation);
        }
        Ok(())
    }

    /// Get the section that owns the data for the given ED or PR symbol index.
    ///
    /// Returns `None` for an invalid index, or if the symbol is not an ED or PR.
    fn element_section(
        symbols: &GoffSymbolTableInternal<'data>,
        index: SymbolIndex,
    ) -> Option<SectionIndex> {
        let symbol = symbols.get(index)?;
        match symbol.record().symbol_type {
            goff::ESD_ST_ED | goff::ESD_ST_PR => symbol.section(),
            _ => None,
        }
    }

    pub(super) fn get(&self, index: SectionIndex) -> Option<&GoffSectionInternal<'data>> {
        self.sections.get(index.0)
    }

    pub(super) fn iter(&self) -> slice::Iter<'_, GoffSectionInternal<'data>> {
        self.sections.iter()
    }
}

/// A section in a [`GoffFile`].
#[derive(Debug)]
pub(super) struct GoffSectionInternal<'data> {
    symbol: GoffSymbolIndex,
    text: Vec<LogicalRecord<'data, goff::TextRecord>>,
    relocations: Vec<goff::Relocation>,
}

/// An iterator for the sections in a [`GoffFile`].
#[derive(Debug)]
pub struct GoffSectionIterator<'data, 'file, R = &'data [u8]>
where
    R: ReadRef<'data>,
{
    pub(super) file: &'file GoffFile<'data, R>,
    pub(super) iter: iter::Enumerate<slice::Iter<'file, GoffSectionInternal<'data>>>,
}

impl<'data, 'file, R> Iterator for GoffSectionIterator<'data, 'file, R>
where
    R: ReadRef<'data>,
{
    type Item = GoffSection<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        let (index, section) = self.iter.next()?;
        Some(GoffSection::new(self.file, SectionIndex(index), section))
    }
}

/// A reference to a section in a [`GoffFile`].
///
/// Most functionality is provided by the [`ObjectSection`] trait implementation.
pub struct GoffSection<'data, 'file, R = &'data [u8]>
where
    R: ReadRef<'data>,
{
    index: SectionIndex,
    file: &'file GoffFile<'data, R>,
    section: &'file GoffSectionInternal<'data>,
    symbol: &'file GoffSymbolInternal<'data>,
}

impl<'data, 'file, R> fmt::Debug for GoffSection<'data, 'file, R>
where
    R: ReadRef<'data>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoffSection")
            .field("esdid", &self.symbol.esdid())
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl<'data, 'file, R: ReadRef<'data>> GoffSection<'data, 'file, R> {
    pub(super) fn new(
        file: &'file GoffFile<'data, R>,
        index: SectionIndex,
        section: &'file GoffSectionInternal<'data>,
    ) -> Self {
        GoffSection {
            index,
            file,
            section,
            symbol: file.symbols.get_by_index(section.symbol),
        }
    }

    /// Get the raw GOFF ESD record.
    pub fn goff_record(&self) -> &'data goff::SymbolRecord {
        self.symbol.record()
    }

    /// Get the raw EBCDIC-encoded name bytes of this section.
    ///
    /// Use [`ObjectSection::decoded_name_bytes`] to convert to UTF-8 bytes.
    pub fn goff_name_bytes(&self) -> &'file [u8] {
        self.symbol.name().as_bytes()
    }

    pub(super) fn goff_name(&self) -> &'file EbcdicStr {
        self.symbol.name()
    }

    /// Returns raw GOFF TXT records that reference this section.
    pub fn goff_text(&self) -> &'file [LogicalRecord<'data, goff::TextRecord>] {
        &self.section.text
    }

    fn is_bss(&self) -> bool {
        let ed = self.symbol.record();
        self.section.text.is_empty()
            && self.symbol.length() != 0
            && ed.behavioral_attributes.text_record_style() == goff::TXT_RS_BYTE
            && ed.fill_byte() == Some(0)
    }
}

impl<'data, 'file, R> read::private::Sealed for GoffSection<'data, 'file, R> where R: ReadRef<'data> {}

// DC: ObjectSection trait at read/traits.rs
impl<'data, 'file, R> ObjectSection<'data> for GoffSection<'data, 'file, R>
where
    R: ReadRef<'data>,
{
    type RelocationIterator = GoffRelocationIterator<'data, 'file, R>;

    fn index(&self) -> SectionIndex {
        self.index
    }

    fn address(&self) -> u64 {
        0
    }

    fn size(&self) -> u64 {
        u64::from(self.symbol.length())
    }

    fn align(&self) -> u64 {
        match self.symbol.record().behavioral_attributes.alignment() {
            goff::ALIGN_BYTE => 1,
            goff::ALIGN_HALFWORD => 2,
            goff::ALIGN_FULLWORD => 4,
            goff::ALIGN_DOUBLEWORD => 8,
            goff::ALIGN_QUADWORD => 16,
            goff::ALIGN_32BYTE => 32,
            goff::ALIGN_64BYTE => 64,
            goff::ALIGN_128BYTE => 128,
            goff::ALIGN_256BYTE => 256,
            goff::ALIGN_512BYTE => 512,
            goff::ALIGN_1024BYTE => 1024,
            goff::ALIGN_2KB => 2048,
            goff::ALIGN_4KB => 4096,
            _ => 1, // Default to byte alignment
        }
    }

    fn file_range(&self) -> Option<(u64, u64)> {
        None
    }

    fn data(&self) -> Result<&'data [u8]> {
        Err(Error(
            "GOFF section data is non-contiguous, use uncompressed_data() instead",
        ))
    }

    fn data_range(&self, _address: u64, _size: u64) -> Result<Option<&'data [u8]>> {
        // GOFF sections do not have an address
        Ok(None)
    }

    fn compressed_file_range(&self) -> Result<CompressedFileRange> {
        Ok(CompressedFileRange::none(self.file_range()))
    }

    fn compressed_data(&self) -> Result<CompressedData<'data>> {
        Err(Error(
            "GOFF section data is non-contiguous, use uncompressed_data() instead",
        ))
    }

    fn uncompressed_data(&self) -> Result<Cow<'data, [u8]>> {
        if self.is_bss() {
            return Ok(Cow::Borrowed(&[]));
        }

        let ed = self.symbol.record();
        let record_style = ed.behavioral_attributes.text_record_style();
        let fill = ed.fill_byte().unwrap_or(0);
        let length = self.symbol.length() as usize;
        let mut data = Vec::new();
        // On success, `data` always has the section length. It is the caller's
        // responsibility to limit that for untrusted input.
        data.try_reserve_exact(length)
            .map_err(|_| Error("GOFF section data allocation failed"))?;
        for txt in &self.section.text {
            if txt.initial.element_esdid != ed.esdid {
                return Err(Error("Unsupported GOFF TXT record for PR"));
            }
            if txt.initial.text_encoding.get(BE) != 0 {
                return Err(Error("Unsupported GOFF TXT encoding"));
            }
            if txt.initial.record_style != record_style {
                return Err(Error("Invalid GOFF TXT record style or reserved bits"));
            }
            let mut offset = match record_style {
                // Records may be in any order, and later records overwrite
                // earlier ones.
                goff::TXT_RS_BYTE => txt.initial.offset.get(BE) as usize,
                // These have no offset, so simply extend in order.
                goff::TXT_RS_STRUCTURED | goff::TXT_RS_UNSTRUCTURED => data.len(),
                _ => return Err(Error("Unsupported GOFF TXT record style")),
            };
            for part in txt.txt_data_parts()? {
                let end = offset.saturating_add(part.len());
                if end > length {
                    return Err(Error("GOFF TXT data exceeds ED length"));
                }
                if end <= data.len() {
                    data[offset..end].copy_from_slice(part);
                } else {
                    data.resize(offset, fill);
                    data.extend_from_slice(part);
                }
                offset = end;
            }
        }
        if record_style == goff::TXT_RS_BYTE {
            data.resize(length, fill);
        } else if data.len() != length {
            return Err(Error("Incomplete GOFF TXT data"));
        }
        Ok(Cow::Owned(data))
    }

    fn name_bytes(&self) -> read::Result<&'data [u8]> {
        Err(Error(
            "GOFF section names are non-contiguous EBCDIC. Use decoded_name_bytes() instead",
        ))
    }

    fn name(&self) -> read::Result<&'data str> {
        Err(Error(
            "GOFF section names are non-contiguous EBCDIC. Use decoded_name() instead",
        ))
    }

    fn decoded_name_bytes(&self) -> read::Result<Cow<'data, [u8]>> {
        Ok(Cow::Owned(self.symbol.decoded_name().into_bytes()))
    }

    fn decoded_name(&self) -> read::Result<Cow<'data, str>> {
        Ok(Cow::Owned(self.symbol.decoded_name()))
    }

    fn segment_name_bytes(&self) -> Result<Option<&[u8]>> {
        Ok(None)
    }

    fn segment_name(&self) -> Result<Option<&str>> {
        Ok(None)
    }

    fn kind(&self) -> SectionKind {
        let flags = self.symbol.record().behavioral_attributes;
        if self.is_bss() {
            SectionKind::UninitializedData
        } else if flags.executable() == goff::EXEC_CODE {
            SectionKind::Text
        } else if flags.is_read_only() {
            SectionKind::ReadOnlyData
        } else {
            SectionKind::Data
        }
    }

    fn relocations(&self) -> Self::RelocationIterator {
        GoffRelocationIterator {
            file: self.file,
            relocations: self.section.relocations.iter(),
        }
    }

    fn relocation_map(&self) -> read::Result<RelocationMap> {
        unimplemented!(); // GOFF: not needed
    }

    fn flags(&self) -> SectionFlags {
        SectionFlags::Goff {
            flags: self.symbol.record().behavioral_attributes,
        }
    }
}
