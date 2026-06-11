//! OMF file implementation for the unified read API.

use alloc::vec::Vec;

use crate::read::{
    self, Architecture, CodeView, Error, Export, FileFlags, Import, NoDynamicRelocationIterator,
    Object, ObjectKind, ObjectSection, ReadRef, Result, SectionIndex, SectionKind, SymbolIndex,
    SymbolKind,
};
use crate::{omf, SubArchitecture};

use super::{
    OmfComdat, OmfComdatData, OmfComdatIterator, OmfComdatSelection, OmfDataChunk, OmfFixup,
    OmfGroup, OmfSection, OmfSectionIterator, OmfSegment, OmfSegmentIterator, OmfSegmentRef,
    OmfSymbol, OmfSymbolClass, OmfSymbolIterator, OmfSymbolTable,
};

/// An OMF object file.
///
/// This handles both 16-bit and 32-bit OMF variants.
///
/// OMF doesn't have a notion of sections, so this implementation maps both
/// segments (`SEGDEF`) and COMDATs (`COMDAT`) to sections in the unified API.
#[derive(Debug)]
pub struct OmfFile<'data, R: ReadRef<'data> = &'data [u8]> {
    pub(super) data: R,
    /// The module name from THEADR/LHEADR record
    pub(super) module_name: Option<&'data str>,
    /// Sections, in record order. This contains an entry for each SEGDEF
    /// record, as well as a synthesized entry for each COMDAT and each
    /// Borland virtual segment (COMDEF).
    pub(super) sections: Vec<OmfSegment<'data>>,
    /// Maps SEGDEF index (0-based) to an index into `sections`.
    pub(super) segdefs: Vec<usize>,
    /// Maps Borland virtual segment index (0-based) to an index into `sections`.
    pub(super) virtual_segdefs: Vec<usize>,
    /// All symbols (publics, externals, communals, locals) in occurrence order
    pub(super) symbols: Vec<OmfSymbol<'data>>,
    /// Maps external-name table index (1-based) to SymbolIndex
    pub(super) external_order: Vec<SymbolIndex>,
    /// COMDAT sections
    pub(super) comdats: Vec<OmfComdatData<'data>>,
    /// Name table (LNAMES/LLNAMES)
    pub(super) names: Vec<&'data [u8]>,
    /// Group definitions
    pub(super) groups: Vec<OmfGroup>,
}

impl<'data, R: ReadRef<'data>> read::private::Sealed for OmfFile<'data, R> {}

impl<'data, R: ReadRef<'data>> OmfFile<'data, R> {
    /// Parse an OMF file from raw data
    pub fn parse(data: R) -> Result<Self> {
        let mut file = OmfFile {
            data,
            module_name: None,
            sections: Vec::new(),
            segdefs: Vec::new(),
            virtual_segdefs: Vec::new(),
            symbols: Vec::new(),
            external_order: Vec::new(),
            comdats: Vec::new(),
            names: Vec::new(),
            groups: Vec::new(),
        };

        file.parse_records()?;
        file.finish_symbols();
        Ok(file)
    }

    /// Compute symbol kinds and sizes that depend on the complete section list.
    fn finish_symbols(&mut self) {
        let kinds_and_sizes: Vec<(SymbolKind, u64)> = self
            .symbols
            .iter()
            .map(|sym| {
                let kind = if let Some(section) = sym.section {
                    Self::symbol_kind_from_section_kind(
                        self.section_kind(section.0.wrapping_sub(1)),
                    )
                } else if matches!(
                    sym.class,
                    OmfSymbolClass::Communal | OmfSymbolClass::LocalCommunal
                ) {
                    SymbolKind::Data
                } else {
                    SymbolKind::Unknown
                };
                let size = match sym.class {
                    // The size of a COMDAT symbol is the size of its section.
                    OmfSymbolClass::Comdat | OmfSymbolClass::LocalComdat => sym
                        .section
                        .and_then(|section| self.sections.get(section.0.wrapping_sub(1)))
                        .map_or(0, |section| section.length),
                    _ => sym.size,
                };
                (kind, size)
            })
            .collect();

        for (sym, (kind, size)) in self.symbols.iter_mut().zip(kinds_and_sizes) {
            sym.kind = kind;
            sym.size = size;
        }
    }

    fn symbol_kind_from_section_kind(section_kind: SectionKind) -> SymbolKind {
        match section_kind {
            SectionKind::Text => SymbolKind::Text,
            SectionKind::Data
            | SectionKind::ReadOnlyData
            | SectionKind::UninitializedData
            | SectionKind::Common => SymbolKind::Data,
            _ => SymbolKind::Unknown,
        }
    }

    /// Get the section kind for a section (0-based index into `sections`).
    pub(super) fn section_kind(&self, section_index: usize) -> SectionKind {
        let Some(section) = self.sections.get(section_index) else {
            return SectionKind::Unknown;
        };

        // COMDAT sections may have a kind determined by their allocation type.
        if let Some(kind) = section.kind {
            return kind;
        }

        let section_name = section.name;
        let class_name = section.class;

        // Reserved names for debug sections
        if section_name.starts_with(b"$$") {
            return SectionKind::Debug;
        }

        // Substring matches for common class names
        if class_name.windows(4).any(|w| w == b"CODE") {
            SectionKind::Text
        } else if class_name.windows(4).any(|w| w == b"DATA") {
            if section_name.windows(5).any(|w| w == b"CONST") {
                SectionKind::ReadOnlyData
            } else {
                SectionKind::Data
            }
        } else if class_name.windows(3).any(|w| w == b"BSS")
            || class_name.windows(5).any(|w| w == b"STACK")
        {
            SectionKind::UninitializedData
        } else if class_name.starts_with(b"DEB") || class_name == b"DWARF" {
            SectionKind::Debug
        } else if class_name == b"COMMON" {
            SectionKind::Common
        } else {
            SectionKind::Unknown
        }
    }

    /// Translate a 1-based segment index into a 0-based index into `sections`.
    ///
    /// Indices with bit 14 set are a Borland extension that references
    /// virtual segments defined by COMDEF records.
    pub(super) fn segdef_section(&self, segment_index: u16) -> Result<usize> {
        let (index, segdefs) = if segment_index & 0x4000 != 0 {
            (segment_index & !0x4000, &self.virtual_segdefs)
        } else {
            (segment_index, &self.segdefs)
        };
        index
            .checked_sub(1)
            .and_then(|i| segdefs.get(i as usize).copied())
            .ok_or(Error("Invalid OMF segment index"))
    }

    fn parse_records(&mut self) -> Result<()> {
        // The data record (LEDATA/LIDATA/COMDAT) that a FIXUPP record applies to:
        // a 0-based index into `sections` and the base data offset within it.
        let mut last_data: Option<(usize, u32)> = None;

        // Thread storage for FIXUPP parsing
        let mut frame_threads: [Option<ThreadDef>; 4] = [None; 4];
        let mut target_threads: [Option<ThreadDef>; 4] = [None; 4];

        let mut offset = 0;
        while let Ok(record_header) = self.data.read_at::<omf::RecordHeader>(offset) {
            let record_type = record_header.record_type;
            let record_length = record_header.length.get(crate::endian::LittleEndian);
            let record_data = self
                .data
                .read_bytes_at(offset, record_length as u64 + 3)
                .map_err(|_| Error("Truncated OMF record data"))?;

            if offset == 0
                && !matches!(
                    record_type,
                    omf::record_type::THEADR | omf::record_type::LHEADR
                )
            {
                return Err(Error(
                    "Invalid OMF file: first record must be THEADR or LHEADR",
                ));
            }

            // Verify checksum
            if !omf::verify_checksum(record_data) {
                return Err(Error("Invalid OMF record checksum"));
            }

            // Exclude the header and checksum
            let inner_data = &record_data[3..2 + record_length as usize];

            // Process record based on type
            match record_type {
                omf::record_type::THEADR | omf::record_type::LHEADR => {
                    self.parse_header(inner_data)?;
                }
                omf::record_type::LNAMES | omf::record_type::LLNAMES => {
                    self.parse_names(inner_data)?;
                }
                omf::record_type::SEGDEF | omf::record_type::SEGDEF32 => {
                    self.parse_segdef(inner_data, record_type == omf::record_type::SEGDEF32)?;
                }
                omf::record_type::GRPDEF => {
                    self.parse_grpdef(inner_data)?;
                }
                omf::record_type::PUBDEF | omf::record_type::PUBDEF32 => {
                    self.parse_pubdef(
                        inner_data,
                        record_type == omf::record_type::PUBDEF32,
                        OmfSymbolClass::Public,
                    )?;
                }
                omf::record_type::LPUBDEF | omf::record_type::LPUBDEF32 => {
                    self.parse_pubdef(
                        inner_data,
                        record_type == omf::record_type::LPUBDEF32,
                        OmfSymbolClass::LocalPublic,
                    )?;
                }
                omf::record_type::EXTDEF => {
                    self.parse_extdef(inner_data, OmfSymbolClass::External)?;
                }
                omf::record_type::LEXTDEF | omf::record_type::LEXTDEF32 => {
                    self.parse_extdef(inner_data, OmfSymbolClass::LocalExternal)?;
                }
                omf::record_type::CEXTDEF => {
                    self.parse_cextdef(inner_data)?;
                }
                omf::record_type::COMDEF => {
                    self.parse_comdef(inner_data, OmfSymbolClass::Communal)?;
                }
                omf::record_type::LCOMDEF => {
                    self.parse_comdef(inner_data, OmfSymbolClass::LocalCommunal)?;
                }
                omf::record_type::COMDAT | omf::record_type::COMDAT32 => {
                    let target =
                        self.parse_comdat(inner_data, record_type == omf::record_type::COMDAT32)?;
                    last_data = Some(target);
                }
                omf::record_type::LEDATA | omf::record_type::LEDATA32 => {
                    let target =
                        self.parse_ledata(inner_data, record_type == omf::record_type::LEDATA32)?;
                    last_data = Some(target);
                }
                omf::record_type::LIDATA | omf::record_type::LIDATA32 => {
                    let target =
                        self.parse_lidata(inner_data, record_type == omf::record_type::LIDATA32)?;
                    last_data = Some(target);
                }
                omf::record_type::FIXUPP | omf::record_type::FIXUPP32 => {
                    self.parse_fixupp(
                        inner_data,
                        record_type == omf::record_type::FIXUPP32,
                        last_data,
                        &mut frame_threads,
                        &mut target_threads,
                    )?;
                }
                omf::record_type::MODEND | omf::record_type::MODEND32 => {
                    // End of module
                    break;
                }
                _ => {
                    // Skip unknown record types
                }
            }

            offset += record_length as u64 + 3;
        }

        if offset == 0 {
            return Err(Error("No OMF records found"));
        }

        Ok(())
    }

    fn parse_header(&mut self, data: &'data [u8]) -> Result<()> {
        if let Some((name, _)) = read_counted_string(data) {
            self.module_name = core::str::from_utf8(name).ok();
        }
        Ok(())
    }

    fn parse_names(&mut self, data: &'data [u8]) -> Result<()> {
        let mut offset = 0;
        while offset < data.len() {
            if let Some((name, size)) = read_counted_string(&data[offset..]) {
                self.names.push(name);
                offset += size;
            } else {
                break;
            }
        }
        Ok(())
    }

    fn parse_segdef(&mut self, data: &'data [u8], is_32bit: bool) -> Result<()> {
        let mut offset = 0;

        // Parse ACBP byte
        if offset >= data.len() {
            return Err(Error("Truncated SEGDEF record"));
        }
        let acbp = data[offset];
        offset += 1;

        let alignment = match (acbp >> 5) & 0x07 {
            0 => omf::SegmentAlignment::Absolute,
            1 => omf::SegmentAlignment::Byte,
            2 => omf::SegmentAlignment::Word,
            3 => omf::SegmentAlignment::Paragraph,
            4 => omf::SegmentAlignment::Page,
            5 => omf::SegmentAlignment::DWord,
            6 => omf::SegmentAlignment::Page4K,
            _ => return Err(Error("Invalid segment alignment")),
        };

        let combination = match (acbp >> 2) & 0x07 {
            0 => omf::SegmentCombination::Private,
            2 | 4 | 7 => omf::SegmentCombination::Public,
            5 => omf::SegmentCombination::Stack,
            6 => omf::SegmentCombination::Common,
            _ => return Err(Error("Invalid segment combination")),
        };

        let big = (acbp & 0x02) != 0;
        let use32 = (acbp & 0x01) != 0;

        // Skip frame number and offset for absolute segments
        if alignment == omf::SegmentAlignment::Absolute {
            offset += 3; // frame (2) + offset (1)
        }

        // Parse segment length. The size of this field is determined by the
        // record type alone; the P (use32) bit describes the default operand
        // size of the segment, not the record layout.
        let mut length = if is_32bit {
            if offset + 4 > data.len() {
                return Err(Error("Truncated SEGDEF record"));
            }
            let length = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as u64;
            offset += 4;
            length
        } else {
            if offset + 2 > data.len() {
                return Err(Error("Truncated SEGDEF record"));
            }
            let length = u16::from_le_bytes([data[offset], data[offset + 1]]) as u64;
            offset += 2;
            length
        };
        // The B bit indicates a segment of the maximum size (64K, or 4G for SEGDEF32).
        if big && length == 0 {
            length = if is_32bit { 1 << 32 } else { 1 << 16 };
        }

        // Parse segment name index
        let (name_index, size) =
            read_index(&data[offset..]).ok_or(Error("Invalid segment name index"))?;
        offset += size;

        // Parse class name index
        let (class_index, size) =
            read_index(&data[offset..]).ok_or(Error("Invalid class name index"))?;
        offset += size;

        // Parse overlay name index
        let (overlay_index, _) =
            read_index(&data[offset..]).ok_or(Error("Invalid overlay name index"))?;

        self.segdefs.push(self.sections.len());
        self.sections.push(OmfSegment {
            name: self.get_name(name_index).unwrap_or_default(),
            class: self.get_name(class_index).unwrap_or_default(),
            name_index,
            class_index,
            overlay_index,
            alignment,
            combination,
            use32,
            length,
            kind: None,
            comdat: false,
            data_chunks: Vec::new(),
            relocations: Vec::new(),
        });

        Ok(())
    }

    fn parse_grpdef(&mut self, data: &'data [u8]) -> Result<()> {
        let mut offset = 0;

        // Parse group name index
        let (name_index, size) = read_index(data).ok_or(Error("Invalid group name index"))?;
        offset += size;

        let mut segments = Vec::new();

        // Parse segment indices
        while offset < data.len() {
            if data[offset] == 0xFF {
                // Segment index follows
                offset += 1;
                let (seg_index, size) =
                    read_index(&data[offset..]).ok_or(Error("Invalid segment index in group"))?;
                offset += size;
                segments.push(seg_index);
            } else {
                break;
            }
        }

        self.groups.push(OmfGroup {
            name_index,
            segments,
        });

        Ok(())
    }

    fn parse_pubdef(
        &mut self,
        data: &'data [u8],
        is_32bit: bool,
        class: OmfSymbolClass,
    ) -> Result<()> {
        let mut offset = 0;

        // Parse group index
        let (_group_index, size) = read_index(data).ok_or(Error("Invalid group index"))?;
        offset += size;

        // Parse segment index
        let (segment_index, size) =
            read_index(&data[offset..]).ok_or(Error("Invalid segment index"))?;
        offset += size;

        // Read frame number if segment index is 0 (for absolute symbols)
        let frame_number = if segment_index == 0 {
            if offset + 2 > data.len() {
                return Err(Error("Invalid frame number in PUBDEF"));
            }
            let frame = u16::from_le_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            frame
        } else {
            0
        };

        let section = if segment_index == 0 {
            None
        } else {
            Some(SectionIndex(self.segdef_section(segment_index)? + 1))
        };

        // Parse public definitions
        while offset < data.len() {
            // Parse name
            let Some((name, size)) = read_counted_string(&data[offset..]) else {
                break;
            };
            offset += size;

            // Parse offset
            let pub_offset = if is_32bit {
                if offset + 4 > data.len() {
                    break;
                }
                let off = u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                offset += 4;
                off
            } else {
                if offset + 2 > data.len() {
                    break;
                }
                let off = u16::from_le_bytes([data[offset], data[offset + 1]]) as u32;
                offset += 2;
                off
            };

            // Parse type index
            let (type_index, size) = read_index(&data[offset..])
                .ok_or(Error("Invalid type index in PUBDEF/LPUBDEF record"))?;
            offset += size;

            self.symbols.push(OmfSymbol {
                index: SymbolIndex(self.symbols.len()),
                name,
                class,
                section,
                absolute: segment_index == 0,
                frame_number,
                offset: pub_offset as u64,
                size: 0,
                type_index,
                kind: SymbolKind::Unknown, // Will be computed later
            });
        }

        Ok(())
    }

    fn parse_extdef(&mut self, data: &'data [u8], class: OmfSymbolClass) -> Result<()> {
        let mut offset = 0;

        while offset < data.len() {
            // Parse name
            let Some((name, size)) = read_counted_string(&data[offset..]) else {
                break;
            };
            offset += size;

            // Parse type index
            let (type_index, size) = read_index(&data[offset..])
                .ok_or(Error("Invalid type index in EXTDEF/LEXTDEF record"))?;
            offset += size;

            self.push_external(name, class, type_index);
        }

        Ok(())
    }

    /// Parse a CEXTDEF record, which references COMDAT symbols by name index.
    fn parse_cextdef(&mut self, data: &'data [u8]) -> Result<()> {
        let mut offset = 0;

        while offset < data.len() {
            // Parse name index (into LNAMES)
            let (name_index, size) =
                read_index(&data[offset..]).ok_or(Error("Invalid name index in CEXTDEF record"))?;
            offset += size;

            // Parse type index
            let (type_index, size) =
                read_index(&data[offset..]).ok_or(Error("Invalid type index in CEXTDEF record"))?;
            offset += size;

            let name = self
                .get_name(name_index)
                .ok_or(Error("Invalid name index in CEXTDEF record"))?;
            self.push_external(name, OmfSymbolClass::ComdatExternal, type_index);
        }

        Ok(())
    }

    /// Add a symbol that contributes to the external-name table.
    fn push_external(&mut self, name: &'data [u8], class: OmfSymbolClass, type_index: u16) {
        let index = SymbolIndex(self.symbols.len());
        self.symbols.push(OmfSymbol {
            index,
            name,
            class,
            section: None,
            absolute: false,
            frame_number: 0,
            offset: 0,
            size: 0,
            type_index,
            kind: SymbolKind::Unknown,
        });
        self.external_order.push(index);
    }

    fn parse_comdef(&mut self, data: &'data [u8], class: OmfSymbolClass) -> Result<()> {
        let mut offset = 0;

        while offset < data.len() {
            // Parse name
            let Some((name, size)) = read_counted_string(&data[offset..]) else {
                break;
            };
            offset += size;

            // Parse type index
            let (type_index, size) = read_index(&data[offset..])
                .ok_or(Error("Invalid type index in COMDEF/LCOMDEF record"))?;
            offset += size;

            // Parse data type and communal length
            if offset >= data.len() {
                break;
            }
            let data_type = data[offset];
            offset += 1;

            let (communal_length, base_segment) = match data_type {
                0x61 => {
                    // FAR data - number of elements followed by element size
                    let (num_elements, size1) = read_communal_length(&data[offset..])
                        .ok_or(Error("Invalid number of elements in FAR COMDEF"))?;
                    offset += size1;
                    let (element_size, size2) = read_communal_length(&data[offset..])
                        .ok_or(Error("Invalid element size in FAR COMDEF"))?;
                    offset += size2;
                    ((num_elements as u64) * (element_size as u64), None)
                }
                0x62 => {
                    // NEAR data - size in bytes
                    let (size_val, size_bytes) = read_communal_length(&data[offset..])
                        .ok_or(Error("Invalid size in NEAR COMDEF"))?;
                    offset += size_bytes;
                    (size_val as u64, None)
                }
                // Borland extension: the data type is a segment index, and a
                // single size in bytes follows. This defines a virtual
                // segment that contains the symbol's data, which can be
                // referenced by other records using a segment index with
                // bit 14 set.
                0x00..=0x5F => {
                    let (size_val, size_bytes) = read_communal_length(&data[offset..])
                        .ok_or(Error("Invalid size in COMDEF"))?;
                    offset += size_bytes;
                    let base_segment = self.segdef_section(data_type as u16).ok();
                    (size_val as u64, Some(base_segment))
                }
                _ => {
                    return Err(Error("Invalid data type in COMDEF/LCOMDEF record"));
                }
            };

            let index = SymbolIndex(self.symbols.len());
            if let Some(base_segment) = base_segment {
                // Synthesize a section for the Borland virtual segment, which
                // behaves like a COMDAT.
                let section_index = self.sections.len();
                self.virtual_segdefs.push(section_index);
                self.sections.push(OmfSegment {
                    name,
                    class: base_segment.map_or(&[][..], |i| self.sections[i].class),
                    name_index: 0,
                    class_index: base_segment.map_or(0, |i| self.sections[i].class_index),
                    overlay_index: 0,
                    alignment: base_segment
                        .map_or(omf::SegmentAlignment::Byte, |i| self.sections[i].alignment),
                    combination: omf::SegmentCombination::Private,
                    use32: base_segment.is_some_and(|i| self.sections[i].use32),
                    length: communal_length,
                    kind: None,
                    comdat: true,
                    data_chunks: Vec::new(),
                    relocations: Vec::new(),
                });

                self.symbols.push(OmfSymbol {
                    index,
                    name,
                    class,
                    section: Some(SectionIndex(section_index + 1)),
                    absolute: false,
                    frame_number: 0,
                    offset: 0,
                    size: communal_length,
                    type_index,
                    kind: SymbolKind::Unknown, // Will be computed later
                });

                self.comdats.push(OmfComdatData {
                    name,
                    section: section_index,
                    symbol: index,
                    selection: OmfComdatSelection::UseAny,
                });
            } else {
                self.symbols.push(OmfSymbol {
                    index,
                    name,
                    class,
                    section: None,
                    absolute: false,
                    frame_number: 0,
                    offset: 0,
                    size: communal_length,
                    type_index,
                    kind: SymbolKind::Data,
                });
            }

            // Communal symbols contribute to the external-name table
            self.external_order.push(index);
        }

        Ok(())
    }

    fn parse_comdat(&mut self, data: &'data [u8], is_32bit: bool) -> Result<(usize, u32)> {
        let mut offset = 0;

        // Parse flags byte
        if offset >= data.len() {
            return Err(Error("Truncated COMDAT record"));
        }
        let flags = data[offset];
        offset += 1;
        let continuation = (flags & 0x01) != 0;
        let iterated = (flags & 0x02) != 0;
        let local = (flags & 0x04) != 0;

        // Parse attributes byte
        if offset >= data.len() {
            return Err(Error("Truncated COMDAT record"));
        }
        let attributes = data[offset];
        offset += 1;

        // Low nibble is the allocation type
        let allocation_type = attributes & 0x0F;
        // High nibble is the selection criteria
        let selection = match (attributes >> 4) & 0x0F {
            0x00 => OmfComdatSelection::Explicit, // No match allowed
            0x01 => OmfComdatSelection::UseAny,   // Pick any
            0x02 => OmfComdatSelection::SameSize, // Same size
            _ => OmfComdatSelection::ExactMatch,  // Exact match
        };

        // Parse align byte
        if offset >= data.len() {
            return Err(Error("Truncated COMDAT record"));
        }
        let align = data[offset];
        offset += 1;

        // Parse enumerated data offset
        let data_offset = if is_32bit {
            if offset + 4 > data.len() {
                return Err(Error("Truncated COMDAT record"));
            }
            let off = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            offset += 4;
            off
        } else {
            if offset + 2 > data.len() {
                return Err(Error("Truncated COMDAT record"));
            }
            let off = u16::from_le_bytes([data[offset], data[offset + 1]]) as u32;
            offset += 2;
            off
        };

        // Parse type index
        let (_type_index, size) =
            read_index(&data[offset..]).ok_or(Error("Invalid type index in COMDAT record"))?;
        offset += size;

        // Parse the public base, which is present only for explicit allocation
        let mut base_segment = None;
        if allocation_type == 0x00 {
            let (_group_index, size) =
                read_index(&data[offset..]).ok_or(Error("Invalid group index in COMDAT record"))?;
            offset += size;
            let (segment_index, size) = read_index(&data[offset..])
                .ok_or(Error("Invalid segment index in COMDAT record"))?;
            offset += size;
            if segment_index == 0 {
                // Skip frame number
                if offset + 2 > data.len() {
                    return Err(Error("Truncated COMDAT record"));
                }
                offset += 2;
            } else {
                base_segment = Some(self.segdef_section(segment_index)?);
            }
        }

        // Parse public name - this is an index into LNAMES
        let (name_index, size) =
            read_index(&data[offset..]).ok_or(Error("Invalid name index in COMDAT record"))?;
        offset += size;
        let name = self
            .get_name(name_index)
            .ok_or(Error("Invalid name index in COMDAT record"))?;

        // Remaining data is the COMDAT content
        let chunk = if iterated {
            OmfDataChunk::Iterated {
                data: &data[offset..],
                is_32bit,
            }
        } else {
            OmfDataChunk::Direct(&data[offset..])
        };
        let chunk_end = data_offset as u64 + chunk.expanded_len()?;

        // Continuation records (and repeated COMDAT records for the same name)
        // add data to the previously defined COMDAT.
        if continuation {
            let comdat = self
                .comdats
                .iter()
                .rev()
                .find(|comdat| comdat.name == name)
                .ok_or(Error("COMDAT continuation without a previous COMDAT"))?;
            let section_index = comdat.section;
            let section = &mut self.sections[section_index];
            section.data_chunks.push((data_offset, chunk));
            if chunk_end > section.length {
                section.length = chunk_end;
            }
            return Ok((section_index, data_offset));
        }

        // Determine the section kind, alignment, and use32 from the
        // allocation type, falling back to the base segment for explicit
        // allocation.
        let (kind, use32) = match allocation_type {
            0x00 => (None, base_segment.is_some_and(|i| self.sections[i].use32)),
            0x01 => (Some(SectionKind::Text), false), // Far code
            0x02 => (Some(SectionKind::Data), false), // Far data
            0x03 => (Some(SectionKind::Text), true),  // Code32
            0x04 => (Some(SectionKind::Data), true),  // Data32
            _ => (None, false),
        };
        let alignment = match align {
            0 => base_segment.map_or(omf::SegmentAlignment::Byte, |i| self.sections[i].alignment),
            1 => omf::SegmentAlignment::Byte,
            2 => omf::SegmentAlignment::Word,
            3 => omf::SegmentAlignment::Paragraph,
            4 => omf::SegmentAlignment::Page,
            5 => omf::SegmentAlignment::DWord,
            6 => omf::SegmentAlignment::Page4K,
            _ => omf::SegmentAlignment::Byte,
        };

        // Synthesize a section for the COMDAT.
        let section_index = self.sections.len();
        self.sections.push(OmfSegment {
            name,
            class: base_segment.map_or(&[][..], |i| self.sections[i].class),
            name_index,
            class_index: base_segment.map_or(0, |i| self.sections[i].class_index),
            overlay_index: 0,
            alignment,
            combination: omf::SegmentCombination::Private,
            use32,
            length: chunk_end,
            kind,
            comdat: true,
            data_chunks: alloc::vec![(data_offset, chunk)],
            relocations: Vec::new(),
        });

        // Synthesize a symbol for the COMDAT.
        let symbol_index = SymbolIndex(self.symbols.len());
        self.symbols.push(OmfSymbol {
            index: symbol_index,
            name,
            class: if local {
                OmfSymbolClass::LocalComdat
            } else {
                OmfSymbolClass::Comdat
            },
            section: Some(SectionIndex(section_index + 1)),
            absolute: false,
            frame_number: 0,
            offset: 0,
            size: 0, // Will be computed later
            type_index: 0,
            kind: SymbolKind::Unknown, // Will be computed later
        });

        self.comdats.push(OmfComdatData {
            name,
            section: section_index,
            symbol: symbol_index,
            selection,
        });

        Ok((section_index, data_offset))
    }

    fn parse_ledata(&mut self, data: &'data [u8], is_32bit: bool) -> Result<(usize, u32)> {
        let mut offset = 0;

        // Parse segment index
        let (segment_index, size) =
            read_index(data).ok_or(Error("Invalid segment index in LEDATA"))?;
        offset += size;
        let section_index = self.segdef_section(segment_index)?;

        // Parse data offset
        let data_offset = if is_32bit {
            if offset + 4 > data.len() {
                return Err(Error("Truncated LEDATA record"));
            }
            let off = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            offset += 4;
            off
        } else {
            if offset + 2 > data.len() {
                return Err(Error("Truncated LEDATA record"));
            }
            let off = u16::from_le_bytes([data[offset], data[offset + 1]]) as u32;
            offset += 2;
            off
        };

        // Store the data chunk reference
        if offset < data.len() {
            self.sections[section_index]
                .data_chunks
                .push((data_offset, OmfDataChunk::Direct(&data[offset..])));
        }

        Ok((section_index, data_offset))
    }

    fn parse_lidata(&mut self, data: &'data [u8], is_32bit: bool) -> Result<(usize, u32)> {
        let mut offset = 0;

        // Read segment index
        let (segment_index, size) =
            read_index(&data[offset..]).ok_or(Error("Invalid segment index in LIDATA"))?;
        offset += size;
        let section_index = self.segdef_section(segment_index)?;

        // Read data offset
        let data_offset = if is_32bit {
            if offset + 4 > data.len() {
                return Err(Error("Truncated LIDATA record"));
            }
            let off = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            offset += 4;
            off
        } else {
            if offset + 2 > data.len() {
                return Err(Error("Truncated LIDATA record"));
            }
            let off = u16::from_le_bytes([data[offset], data[offset + 1]]) as u32;
            offset += 2;
            off
        };

        // Store the unexpanded data; it is expanded on demand.
        if offset < data.len() {
            let chunk = OmfDataChunk::Iterated {
                data: &data[offset..],
                is_32bit,
            };
            // Validate the iterated data blocks.
            chunk.expanded_len()?;
            self.sections[section_index]
                .data_chunks
                .push((data_offset, chunk));
        }

        Ok((section_index, data_offset))
    }

    fn parse_fixupp(
        &mut self,
        data: &'data [u8],
        is_32bit: bool,
        last_data: Option<(usize, u32)>,
        frame_threads: &mut [Option<ThreadDef>; 4],
        target_threads: &mut [Option<ThreadDef>; 4],
    ) -> Result<()> {
        let mut offset = 0;

        while offset < data.len() {
            let b = data[offset];
            offset += 1;

            if (b & 0x80) == 0 {
                // THREAD subrecord
                let is_frame = (b & 0x40) != 0; // D-bit
                let method = (b >> 2) & 0x07; // Method bits
                let thread_num = (b & 0x03) as usize; // Thread number (0-3)

                let index = if method < 3 {
                    // Methods 0-2 have an index
                    let (idx, size) = read_index(&data[offset..])
                        .ok_or(Error("Invalid index in THREAD subrecord"))?;
                    offset += size;
                    idx
                } else if method == 3 {
                    // Method 3 has a raw frame number
                    if offset + 2 > data.len() {
                        return Err(Error("Invalid frame number in THREAD subrecord"));
                    }
                    let frame_num = u16::from_le_bytes([data[offset], data[offset + 1]]);
                    offset += 2;
                    frame_num
                } else {
                    0
                };

                // Store the thread definition
                let thread_def = ThreadDef { method, index };
                if is_frame {
                    frame_threads[thread_num] = Some(thread_def);
                } else {
                    target_threads[thread_num] = Some(thread_def);
                }
            } else {
                // FIXUP subrecord
                let (section_index, data_offset) = last_data.ok_or(Error(
                    "FIXUP subrecord without preceding LEDATA/LIDATA/COMDAT",
                ))?;

                if offset + 1 > data.len() {
                    return Err(Error("Truncated FIXUP location"));
                }
                let locat = data[offset] as u32 | (((b as u32) & 0x03) << 8);
                offset += 1;

                // The M bit determines segment-relative vs self-relative.
                let is_segment_relative = (b & 0x40) != 0;

                let location = match (b >> 2) & 0x0F {
                    0 => omf::FixupLocation::LowByte,
                    1 => omf::FixupLocation::Offset,
                    2 => omf::FixupLocation::Base,
                    3 => omf::FixupLocation::Pointer,
                    4 => omf::FixupLocation::HighByte,
                    5 => omf::FixupLocation::LoaderOffset,
                    9 => omf::FixupLocation::Offset32,
                    11 => omf::FixupLocation::Pointer48,
                    13 => omf::FixupLocation::LoaderOffset32,
                    _ => return Err(Error("Invalid FIXUP location type")),
                };

                // Parse fix data byte
                if offset >= data.len() {
                    return Err(Error("Truncated FIXUP fix data"));
                }
                let fix_data = data[offset];
                offset += 1;

                // Check F-bit (bit 7 of fix_data)
                let frame_via_thread = (fix_data & 0x80) != 0;
                let (frame_method, frame_index) = if frame_via_thread {
                    // F=1: Use frame thread
                    let thread_num = ((fix_data >> 4) & 0x03) as usize;
                    match frame_threads[thread_num] {
                        Some(thread) => {
                            let method = FrameMethod::parse(thread.method)
                                .ok_or(Error("Invalid frame method in thread"))?;
                            (method, thread.index)
                        }
                        None => return Err(Error("Undefined frame thread in FIXUP")),
                    }
                } else {
                    // F=0: Read frame datum
                    let method = FrameMethod::parse((fix_data >> 4) & 0x07)
                        .ok_or(Error("Invalid frame method in FIXUP"))?;
                    let index = match method {
                        FrameMethod::SegmentIndex
                        | FrameMethod::GroupIndex
                        | FrameMethod::ExternalIndex => {
                            let (idx, size) = read_index(&data[offset..])
                                .ok_or(Error("Truncated FIXUP frame datum: missing index data"))?;
                            offset += size;
                            idx
                        }
                        FrameMethod::FrameNumber => {
                            if offset + 2 > data.len() {
                                return Err(Error(
                                    "Truncated FIXUP frame datum: missing frame number",
                                ));
                            }
                            let frame_num = u16::from_le_bytes([data[offset], data[offset + 1]]);
                            offset += 2;
                            frame_num
                        }
                        FrameMethod::Location | FrameMethod::Target => 0,
                    };
                    (method, index)
                };

                // Check T-bit (bit 3 of fix_data)
                let target_via_thread = (fix_data & 0x08) != 0;
                let (target_method, target_index) = if target_via_thread {
                    // T=1: Use target thread
                    let thread_num = (fix_data & 0x03) as usize;
                    match target_threads[thread_num] {
                        Some(thread) => {
                            // Only the low 2 bits of the thread method apply to targets
                            let method = TargetMethod::parse(thread.method & 0x03)
                                .ok_or(Error("Invalid target method in thread"))?;
                            (method, thread.index)
                        }
                        None => return Err(Error("Undefined target thread in FIXUP")),
                    }
                } else {
                    // T=0: Read target datum
                    let method = TargetMethod::parse(fix_data & 0x03)
                        .ok_or(Error("Invalid target method in FIXUP"))?;
                    let index = match method {
                        TargetMethod::SegmentIndex
                        | TargetMethod::GroupIndex
                        | TargetMethod::ExternalIndex => {
                            let (idx, size) = read_index(&data[offset..])
                                .ok_or(Error("Truncated FIXUP target datum: missing index data"))?;
                            offset += size;
                            idx
                        }
                        TargetMethod::FrameNumber => {
                            if offset + 2 > data.len() {
                                return Err(Error(
                                    "Truncated FIXUP target datum: missing frame number",
                                ));
                            }
                            let frame_num = u16::from_le_bytes([data[offset], data[offset + 1]]);
                            offset += 2;
                            frame_num
                        }
                    };
                    (method, index)
                };

                // Parse target displacement if present (P=0)
                let has_displacement = (fix_data & 0x04) == 0;
                let target_displacement = if has_displacement {
                    if is_32bit {
                        if offset + 4 > data.len() {
                            return Err(Error("Truncated FIXUP 32-bit displacement"));
                        }
                        let disp = u32::from_le_bytes([
                            data[offset],
                            data[offset + 1],
                            data[offset + 2],
                            data[offset + 3],
                        ]);
                        offset += 4;
                        disp
                    } else {
                        if offset + 2 > data.len() {
                            return Err(Error("Truncated FIXUP 16-bit displacement"));
                        }
                        let disp = u16::from_le_bytes([data[offset], data[offset + 1]]) as u32;
                        offset += 2;
                        disp
                    }
                } else {
                    0
                };

                self.sections[section_index].relocations.push(OmfFixup {
                    offset: data_offset + locat,
                    location,
                    frame_method,
                    target_method,
                    frame_index,
                    target_index,
                    target_displacement,
                    is_segment_relative,
                });
            }
        }

        Ok(())
    }

    /// Get the module name from the THEADR/LHEADR record.
    pub fn module_name(&self) -> Option<&'data str> {
        self.module_name
    }

    /// Get the parsed sections, which include both segments and COMDATs.
    pub fn raw_sections(&self) -> &[OmfSegment<'data>] {
        &self.sections
    }

    /// Get symbol by external-name index (1-based, as used in FIXUPP records)
    pub(super) fn external_symbol(&self, external_index: u16) -> Option<&OmfSymbol<'data>> {
        let symbol_index = self
            .external_order
            .get(external_index.checked_sub(1)? as usize)?;
        self.symbols.get(symbol_index.0)
    }

    /// Get a name by index (1-based)
    pub fn get_name(&self, index: u16) -> Option<&'data [u8]> {
        let name_index = index.checked_sub(1)?;
        self.names.get(name_index as usize).copied()
    }

    /// Get a group's name by group index (1-based)
    pub(super) fn group_name(&self, index: u16) -> Option<&'data [u8]> {
        let group = self.groups.get(index.checked_sub(1)? as usize)?;
        self.get_name(group.name_index)
    }

    /// Get all symbols (for iteration)
    pub fn raw_symbols(&self) -> &[OmfSymbol<'data>] {
        &self.symbols
    }
}

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
        if idx < self.sections.len() {
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
        self.symbols
            .get(index.0)
            .cloned()
            .ok_or(Error("Symbol index out of bounds"))
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
            index: self.symbols.len(), // Empty iterator
        }
    }

    fn dynamic_symbol_table(&self) -> Option<Self::SymbolTable<'_>> {
        None
    }

    fn dynamic_relocations(&self) -> Option<Self::DynamicRelocationIterator<'_>> {
        None
    }

    fn imports(&self) -> Result<Vec<Import<'data>>> {
        // TODO: this could return undefined symbols, but not needed yet.
        Ok(Vec::new())
    }

    fn exports(&self) -> Result<Vec<Export<'data>>> {
        // TODO: this could return global symbols, but not needed yet.
        Ok(Vec::new())
    }

    fn has_debug_symbols(&self) -> bool {
        self.sections()
            .any(|section| section.kind() == SectionKind::Debug)
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

    fn pdb_info(&self) -> Result<Option<CodeView<'_>>> {
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

/// Thread definition for FIXUPP parsing
#[derive(Debug, Clone, Copy)]
struct ThreadDef {
    /// 3-bit method (frame or target method)
    method: u8,
    /// Index value (meaning depends on method)
    index: u16,
}

/// Target method types for fixups
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum TargetMethod {
    /// Segment index
    SegmentIndex,
    /// Group index
    GroupIndex,
    /// External index
    ExternalIndex,
    /// Frame number (absolute)
    FrameNumber,
}

impl TargetMethod {
    fn parse(method: u8) -> Option<Self> {
        Some(match method {
            0 => TargetMethod::SegmentIndex,
            1 => TargetMethod::GroupIndex,
            2 => TargetMethod::ExternalIndex,
            3 => TargetMethod::FrameNumber,
            _ => return None,
        })
    }
}

/// Frame method types for fixups
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum FrameMethod {
    /// Segment index
    SegmentIndex,
    /// Group index
    GroupIndex,
    /// External index
    ExternalIndex,
    /// Frame number (absolute)
    FrameNumber,
    /// Location (use the frame containing the fixup location)
    Location,
    /// Target (use the target's frame)
    Target,
}

impl FrameMethod {
    fn parse(method: u8) -> Option<Self> {
        Some(match method {
            0 => FrameMethod::SegmentIndex,
            1 => FrameMethod::GroupIndex,
            2 => FrameMethod::ExternalIndex,
            3 => FrameMethod::FrameNumber,
            4 => FrameMethod::Location,
            5 => FrameMethod::Target,
            _ => return None,
        })
    }
}

/// Expand iterated data blocks (from LIDATA or COMDAT records) into a newly
/// allocated buffer.
///
/// The data may contain multiple consecutive iterated data blocks.
pub(super) fn expand_iterated_data(data: &[u8], is_32bit: bool) -> Result<Vec<u8>> {
    let expanded_size = usize::try_from(iterated_data_expanded_len(data, is_32bit)?)
        .map_err(|_| Error("LIDATA expanded size overflow"))?;
    let mut result = alloc::vec![0u8; expanded_size];
    let mut offset = 0;
    let mut write_offset = 0;
    while offset < data.len() {
        offset += expand_iterated_block(&data[offset..], is_32bit, &mut result, &mut write_offset)?;
    }
    debug_assert_eq!(write_offset, expanded_size);
    Ok(result)
}

/// Return the total expanded size of consecutive iterated data blocks.
pub(super) fn iterated_data_expanded_len(data: &[u8], is_32bit: bool) -> Result<u64> {
    let mut offset = 0;
    let mut expanded = 0u64;
    while offset < data.len() {
        let (consumed, block_expanded) = iterated_block_expanded_len(&data[offset..], is_32bit)?;
        offset += consumed;
        expanded = expanded
            .checked_add(block_expanded)
            .ok_or(Error("LIDATA expanded size overflow"))?;
    }
    Ok(expanded)
}

/// Read the repeat count and block count of an iterated data block.
///
/// Returns the counts and the number of bytes consumed.
fn read_iterated_block_header(data: &[u8], is_32bit: bool) -> Result<(u32, u16, usize)> {
    let mut offset = 0;
    let repeat_count = if is_32bit {
        if data.len() < 4 {
            return Err(Error("Truncated LIDATA block"));
        }
        offset += 4;
        u32::from_le_bytes([data[0], data[1], data[2], data[3]])
    } else {
        if data.len() < 2 {
            return Err(Error("Truncated LIDATA block"));
        }
        offset += 2;
        u16::from_le_bytes([data[0], data[1]]) as u32
    };
    if data.len() < offset + 2 {
        return Err(Error("Truncated LIDATA block"));
    }
    let block_count = u16::from_le_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    Ok((repeat_count, block_count, offset))
}

/// Expand a single iterated data block, returning the number of bytes consumed.
fn expand_iterated_block(
    data: &[u8],
    is_32bit: bool,
    output: &mut [u8],
    write_offset: &mut usize,
) -> Result<usize> {
    let (repeat_count, block_count, mut offset) = read_iterated_block_header(data, is_32bit)?;

    if block_count == 0 {
        // Leaf block: 1-byte length followed by data bytes.
        if offset >= data.len() {
            return Err(Error("Truncated LIDATA block"));
        }
        let data_length = data[offset] as usize;
        offset += 1;
        if offset + data_length > data.len() {
            return Err(Error("Truncated LIDATA block"));
        }
        let block_data = &data[offset..offset + data_length];
        offset += data_length;

        for _ in 0..repeat_count {
            let end = *write_offset + data_length;
            if end > output.len() {
                return Err(Error("LIDATA expanded size mismatch"));
            }
            output[*write_offset..end].copy_from_slice(block_data);
            *write_offset = end;
        }
    } else {
        // Nested blocks: expand one iteration, then repeat it.
        let iteration_start = *write_offset;
        for _ in 0..block_count {
            if offset >= data.len() {
                return Err(Error("Truncated LIDATA block"));
            }
            offset += expand_iterated_block(&data[offset..], is_32bit, output, write_offset)?;
        }
        let iteration_len = *write_offset - iteration_start;

        for _ in 1..repeat_count {
            let dest_start = *write_offset;
            let dest_end = dest_start + iteration_len;
            if dest_end > output.len() {
                return Err(Error("LIDATA expanded size mismatch"));
            }
            output.copy_within(iteration_start..iteration_start + iteration_len, dest_start);
            *write_offset = dest_end;
        }
    }

    Ok(offset)
}

/// Return the consumed and expanded size of a single iterated data block.
fn iterated_block_expanded_len(data: &[u8], is_32bit: bool) -> Result<(usize, u64)> {
    let (repeat_count, block_count, mut offset) = read_iterated_block_header(data, is_32bit)?;

    let single_iteration = if block_count == 0 {
        // Leaf block: 1-byte length followed by data bytes.
        if offset >= data.len() {
            return Err(Error("Truncated LIDATA block"));
        }
        let data_length = data[offset] as usize;
        offset += 1;
        if offset + data_length > data.len() {
            return Err(Error("Truncated LIDATA block"));
        }
        offset += data_length;
        data_length as u64
    } else {
        let mut single_iteration = 0u64;
        for _ in 0..block_count {
            if offset >= data.len() {
                return Err(Error("Truncated LIDATA block"));
            }
            let (consumed, expanded) = iterated_block_expanded_len(&data[offset..], is_32bit)?;
            offset += consumed;
            single_iteration = single_iteration
                .checked_add(expanded)
                .ok_or(Error("LIDATA expanded size overflow"))?;
        }
        single_iteration
    };

    let expanded = single_iteration
        .checked_mul(repeat_count as u64)
        .ok_or(Error("LIDATA expanded size overflow"))?;
    Ok((offset, expanded))
}

/// Helper to read an OMF index (1 or 2 bytes)
fn read_index(data: &[u8]) -> Option<(u16, usize)> {
    if data.is_empty() {
        return None;
    }

    let first_byte = data[0];
    if first_byte & 0x80 == 0 {
        // 1-byte index
        Some((first_byte as u16, 1))
    } else if data.len() >= 2 {
        // 2-byte index
        let high = (first_byte & 0x7F) as u16;
        let low = data[1] as u16;
        Some((high << 8 | low, 2))
    } else {
        None
    }
}

/// Helper to read a counted string (length byte followed by string)
fn read_counted_string(data: &[u8]) -> Option<(&[u8], usize)> {
    if data.is_empty() {
        return None;
    }

    let length = data[0] as usize;
    if data.len() > length {
        Some((&data[1..1 + length], 1 + length))
    } else {
        None
    }
}

/// Read a COMDEF communal length.
///
/// Returns the value and number of bytes consumed.
fn read_communal_length(data: &[u8]) -> Option<(u32, usize)> {
    let first_byte = *data.first()?;
    match first_byte {
        // Single byte value (0-127)
        0..=0x80 => Some((first_byte as u32, 1)),
        // 0x81 followed by a 16-bit little-endian value
        0x81 => {
            let bytes = data.get(1..3)?;
            Some((u16::from_le_bytes([bytes[0], bytes[1]]) as u32, 3))
        }
        // 0x84 followed by a 24-bit little-endian value
        0x84 => {
            let bytes = data.get(1..4)?;
            Some((u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]), 4))
        }
        // 0x88 followed by a 32-bit little-endian value
        0x88 => {
            let bytes = data.get(1..5)?;
            Some((
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                5,
            ))
        }
        _ => None,
    }
}
