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
    GoffFile, GoffRelocationIterator, GoffSymbolIndex, GoffSymbolInternal, GoffSymbolSection,
    GoffSymbolTableInternal, LogicalRecord,
};

/// A table of sections in a GOFF file.
#[derive(Debug)]
pub(super) struct GoffSectionTableInternal<'data> {
    sections: Vec<GoffSectionInternal>,
    subsections: Vec<GoffSubsection<'data>>,
}

impl<'data> GoffSectionTableInternal<'data> {
    pub(super) fn new() -> Self {
        GoffSectionTableInternal {
            sections: Vec::new(),
            subsections: Vec::new(),
        }
    }

    /// Finalize our representation of PR symbols within ED sections.
    ///
    /// `GoffSection::uncompressed_data` concatenates PR data without padding.
    /// Calculate the total length and assign offsets to subsections to match,
    /// so that symbols and relocations can be adjusted.
    pub(super) fn finalize(&mut self, symbols: &mut GoffSymbolTableInternal<'data>) -> Result<()> {
        for section in &mut self.sections {
            let mut offset = symbols
                .get_by_index(self.subsections[section.ed.0].symbol)
                .length();
            for pr in &section.prs {
                let pr = &mut self.subsections[pr.0];
                pr.offset = offset;
                symbols.set_offset(pr.symbol, offset);
                offset = offset
                    .checked_add(symbols.get_by_index(pr.symbol).length())
                    .read_error("Invalid GOFF PR length")?;
            }
            section.length = offset;
        }
        Ok(())
    }

    pub(super) fn add_esd(
        &mut self,
        symbols: &GoffSymbolTableInternal<'data>,
        symbol: &GoffSymbolInternal<'data>,
        symbol_index: GoffSymbolIndex,
    ) -> Option<GoffSymbolSection> {
        match symbol.record().symbol_type {
            // Only ED (Element Definition) represents user sections.
            // SD (Section Definition) is the compile unit, not a user section.
            goff::ESD_ST_ED => Some(self.add_section(symbol_index)),
            goff::ESD_ST_PR => {
                if symbol.is_undefined_pr() {
                    None
                } else {
                    let ed_section = Self::ed_section(symbols, symbol)?;
                    let subsection = self.add_subsection(symbol_index);
                    self.sections[ed_section.section.0].prs.push(subsection);
                    Some(GoffSymbolSection {
                        section: ed_section.section,
                        subsection,
                    })
                }
            }
            goff::ESD_ST_LD => Self::ed_section(symbols, symbol),
            _ => None,
        }
    }

    fn add_section(&mut self, symbol: GoffSymbolIndex) -> GoffSymbolSection {
        let section = SectionIndex(self.sections.len());
        let subsection = self.add_subsection(symbol);
        self.sections.push(GoffSectionInternal {
            length: 0,
            ed: subsection,
            prs: Vec::new(),
        });
        GoffSymbolSection {
            section,
            subsection,
        }
    }

    fn add_subsection(&mut self, symbol: GoffSymbolIndex) -> GoffSubsectionIndex {
        let subsection = GoffSubsectionIndex(self.subsections.len());
        self.subsections.push(GoffSubsection {
            symbol,
            offset: 0,
            text: Vec::new(),
            relocations: Vec::new(),
        });
        subsection
    }

    pub(super) fn add_txt(
        &mut self,
        symbols: &GoffSymbolTableInternal<'data>,
        record: LogicalRecord<'data, goff::TextRecord>,
    ) -> Result<()> {
        let txt_record = record.initial;
        let esdid = SymbolIndex(txt_record.element_esdid.get(BE) as usize);
        let subsection = Self::element_subsection(symbols, esdid)
            .read_error("Invalid element ESDID in GOFF TXT record")?;
        self.subsections[subsection.0].text.push(record);
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
            let subsection = Self::element_subsection(symbols, p_pointer)
                .read_error("Invalid P pointer in GOFF RLD entry")?;
            self.subsections[subsection.0].relocations.push(relocation);
        }
        Ok(())
    }

    /// Get the section for the ED parent of the given child symbol.
    ///
    /// Returns `None` for an invalid index, or if the parent is not an ED.
    fn ed_section(
        symbols: &GoffSymbolTableInternal<'data>,
        child: &GoffSymbolInternal<'data>,
    ) -> Option<GoffSymbolSection> {
        let symbol = symbols.get(child.parent_esdid())?;
        match symbol.record().symbol_type {
            goff::ESD_ST_ED => symbol.section(),
            _ => None,
        }
    }

    /// Get the subsection that owns the data for the given ED or PR symbol index.
    ///
    /// Returns `None` for an invalid index, or if the symbol is not an ED or PR.
    fn element_subsection(
        symbols: &GoffSymbolTableInternal<'data>,
        index: SymbolIndex,
    ) -> Option<GoffSubsectionIndex> {
        let symbol = symbols.get(index)?;
        match symbol.record().symbol_type {
            goff::ESD_ST_ED | goff::ESD_ST_PR => symbol.section().map(|x| x.subsection),
            _ => None,
        }
    }

    pub(super) fn get(&self, index: SectionIndex) -> Option<&GoffSectionInternal> {
        self.sections.get(index.0)
    }

    pub(super) fn iter(&self) -> slice::Iter<'_, GoffSectionInternal> {
        self.sections.iter()
    }

    fn subsection(&self, index: GoffSubsectionIndex) -> &GoffSubsection<'data> {
        // GoffSubsectionIndex is always valid.
        &self.subsections[index.0]
    }

    pub(super) fn relocations(&self, index: GoffSubsectionIndex) -> (u32, &[goff::Relocation]) {
        let subsection = self.subsection(index);
        (subsection.offset, &subsection.relocations)
    }
}

/// 0-based index into GoffSectionTableInternal::subsections that is always valid.
#[derive(Debug, Clone, Copy)]
pub(super) struct GoffSubsectionIndex(usize);

#[derive(Debug)]
struct GoffSubsection<'data> {
    symbol: GoffSymbolIndex,
    offset: u32,
    text: Vec<LogicalRecord<'data, goff::TextRecord>>,
    relocations: Vec<goff::Relocation>,
}

/// A section in a [`GoffFile`].
#[derive(Debug)]
pub(super) struct GoffSectionInternal {
    length: u32,
    ed: GoffSubsectionIndex,
    prs: Vec<GoffSubsectionIndex>,
}

/// An iterator for the sections in a [`GoffFile`].
#[derive(Debug)]
pub struct GoffSectionIterator<'data, 'file, R = &'data [u8]>
where
    R: ReadRef<'data>,
{
    pub(super) file: &'file GoffFile<'data, R>,
    pub(super) iter: iter::Enumerate<slice::Iter<'file, GoffSectionInternal>>,
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
    section: &'file GoffSectionInternal,
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
        section: &'file GoffSectionInternal,
    ) -> Self {
        let ed = file.sections.subsection(section.ed);
        GoffSection {
            index,
            file,
            section,
            symbol: file.symbols.get_by_index(ed.symbol),
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

    /// Returns raw GOFF TXT records that reference the ED of this section.
    ///
    /// This does not include TXT records that reference PRs within the ED.
    pub fn goff_text(&self) -> &'file [LogicalRecord<'data, goff::TextRecord>] {
        &self.file.sections.subsection(self.section.ed).text
    }

    fn is_bss(&self) -> bool {
        let is_empty = |index| self.file.sections.subsection(index).text.is_empty();
        let ed = self.symbol.record();
        self.section.length != 0
            && ed.behavioral_attributes.text_record_style() == goff::TXT_RS_BYTE
            && ed.fill_byte() == Some(0)
            && is_empty(self.section.ed)
            && self.section.prs.iter().copied().all(is_empty)
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
        u64::from(self.section.length)
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
        let mut data = Vec::new();
        // On success, `data` always has the section length. It is the caller's
        // responsibility to limit that for untrusted input.
        data.try_reserve_exact(self.section.length as usize)
            .map_err(|_| Error("GOFF section data allocation failed"))?;
        let mut add_subsection = |subsection: &GoffSubsection<'data>| {
            let symbol = self.file.symbols.get_by_index(subsection.symbol);
            let start = data.len();
            debug_assert_eq!(start, subsection.offset as usize);
            let end = start
                .checked_add(symbol.length() as usize)
                .read_error("GOFF section length too large")?;
            for txt in &subsection.text {
                if txt.initial.text_encoding.get(BE) != 0 {
                    return Err(Error("Unsupported GOFF TXT encoding"));
                }
                if txt.initial.record_style != record_style {
                    return Err(Error("Invalid GOFF TXT record style or reserved bits"));
                }
                let mut offset = match record_style {
                    // Records may be in any order, and later records overwrite
                    // earlier ones.
                    goff::TXT_RS_BYTE => start.saturating_add(txt.initial.offset.get(BE) as usize),
                    // These have no offset, so simply extend in order.
                    goff::TXT_RS_STRUCTURED | goff::TXT_RS_UNSTRUCTURED => data.len(),
                    _ => return Err(Error("Unsupported GOFF TXT record style")),
                };
                for part in txt.txt_data_parts()? {
                    let part_end = offset.saturating_add(part.len());
                    if part_end > end {
                        return Err(Error("GOFF TXT data exceeds ESD length"));
                    }
                    if part_end <= data.len() {
                        data[offset..part_end].copy_from_slice(part);
                    } else {
                        data.resize(offset, fill);
                        data.extend_from_slice(part);
                    }
                    offset = part_end;
                }
            }
            if record_style == goff::TXT_RS_BYTE {
                data.resize(end, fill);
            } else if data.len() != end {
                return Err(Error("Incomplete GOFF TXT data"));
            }
            Ok(())
        };
        add_subsection(self.file.sections.subsection(self.section.ed))?;
        for pr in &self.section.prs {
            add_subsection(self.file.sections.subsection(*pr))?;
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
        if flags.loading_behavior() == goff::LOAD_NONE {
            SectionKind::Other
        } else if self.is_bss() {
            SectionKind::UninitializedData
        } else if flags.executable() == goff::EXEC_CODE {
            // TODO: check for any LD children with goff::EXEC_CODE
            SectionKind::Text
        } else if flags.is_read_only() {
            SectionKind::ReadOnlyData
        } else {
            SectionKind::Data
        }
    }

    fn relocations(&self) -> Self::RelocationIterator {
        GoffRelocationIterator::new(self.file, self.section.ed, &self.section.prs)
    }

    fn relocation_map(&self) -> read::Result<RelocationMap> {
        RelocationMap::new(self.file, self)
    }

    fn flags(&self) -> SectionFlags {
        let record = self.symbol.record();
        SectionFlags::Goff {
            flags: record.flags,
            fill_byte_value: record.fill_byte_value,
            namespace: record.namespace,
            behavioral_attributes: record.behavioral_attributes,
        }
    }
}
