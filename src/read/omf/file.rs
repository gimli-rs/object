//! OMF file implementation for the unified read API.

use alloc::vec::Vec;

use crate::read::{
    self, Architecture, ByteString, CodeView, Error, Export, FileFlags, Import,
    NoDynamicRelocationIterator, Object, ObjectKind, ObjectSection, ReadRef, Result, SectionIndex,
    SymbolIndex,
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
#[derive(Debug)]
pub struct OmfFile<'data, R: ReadRef<'data> = &'data [u8]> {
    pub(super) data: R,
    /// The module name from THEADR/LHEADR record
    pub(super) module_name: Option<&'data str>,
    /// Segment definitions
    pub(super) segments: Vec<OmfSegment<'data>>,
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
            segments: Vec::new(),
            symbols: Vec::new(),
            external_order: Vec::new(),
            comdats: Vec::new(),
            names: Vec::new(),
            groups: Vec::new(),
        };

        file.parse_records()?;
        file.assign_symbol_kinds();
        Ok(file)
    }

    fn assign_symbol_kinds(&mut self) {
        // Compute kinds for symbols based on their segments
        let kinds: Vec<read::SymbolKind> = self
            .symbols
            .iter()
            .map(|sym| match sym.class {
                OmfSymbolClass::Public | OmfSymbolClass::LocalPublic => {
                    if sym.segment_index > 0 && (sym.segment_index as usize) <= self.segments.len()
                    {
                        let segment_idx = (sym.segment_index - 1) as usize;
                        let section_kind = self.segment_section_kind(segment_idx);
                        Self::symbol_kind_from_section_kind(section_kind)
                    } else {
                        read::SymbolKind::Unknown
                    }
                }
                OmfSymbolClass::Communal | OmfSymbolClass::LocalCommunal => read::SymbolKind::Data,
                _ => read::SymbolKind::Unknown,
            })
            .collect();

        // Apply computed kinds
        for (sym, kind) in self.symbols.iter_mut().zip(kinds) {
            sym.kind = kind;
        }
    }

    fn symbol_kind_from_section_kind(section_kind: read::SectionKind) -> read::SymbolKind {
        match section_kind {
            read::SectionKind::Text => read::SymbolKind::Text,
            read::SectionKind::Data | read::SectionKind::ReadOnlyData => read::SymbolKind::Data,
            read::SectionKind::UninitializedData => read::SymbolKind::Data,
            _ => read::SymbolKind::Unknown,
        }
    }

    /// Get the section kind for a segment (reusing logic from OmfSection)
    pub(super) fn segment_section_kind(&self, segment_index: usize) -> read::SectionKind {
        if segment_index >= self.segments.len() {
            return read::SectionKind::Unknown;
        }

        let segment = &self.segments[segment_index];

        // Check segment name first for special cases
        if let Some(seg_name) = self.get_name(segment.name_index) {
            // Segments named CONST are always read-only regardless of class
            match seg_name {
                b"CONST" | b"_CONST" | b"CONST2" | b"RDATA" | b"_RDATA" => {
                    return read::SectionKind::ReadOnlyData;
                }
                _ => {}
            }

            // Check for debug sections by name
            if seg_name.starts_with(b"$$") {
                // Watcom-style debug sections
                return read::SectionKind::Debug;
            }
            if seg_name == b".drectve" || seg_name == b".DRECTVE" {
                return read::SectionKind::Linker;
            }

            // Check other common names
            let name_upper = seg_name.to_ascii_uppercase();
            if name_upper == b"_TEXT" || name_upper == b"CODE" || name_upper == b".TEXT" {
                return read::SectionKind::Text;
            } else if name_upper == b"_DATA" || name_upper == b"DATA" || name_upper == b".DATA" {
                return read::SectionKind::Data;
            } else if name_upper == b"_BSS"
                || name_upper == b"BSS"
                || name_upper == b".BSS"
                || name_upper == b"STACK"
            {
                return read::SectionKind::UninitializedData;
            }
        }

        // Determine kind from class name
        if let Some(class_name) = self.get_name(segment.class_index) {
            // Check for exact matches first (most common case)
            match class_name {
                b"CODE" | b"_TEXT" | b"TEXT" => return read::SectionKind::Text,
                b"CONST" | b"_CONST" | b"CONST2" | b"RDATA" | b"_RDATA" => {
                    return read::SectionKind::ReadOnlyData;
                }
                b"BSS" | b"_BSS" => return read::SectionKind::UninitializedData,
                b"STACK" | b"_STACK" => return read::SectionKind::UninitializedData,
                b"DEBUG" | b"_DEBUG" | b"DEBSYM" | b"DEBTYP" => return read::SectionKind::Debug,
                b"DATA" | b"_DATA" => {
                    // DATA sections with no actual data are treated as uninitialized
                    if segment.data_chunks.is_empty() {
                        return read::SectionKind::UninitializedData;
                    } else {
                        return read::SectionKind::Data;
                    }
                }
                _ => {}
            }

            // Check for case-insensitive substring matches for less common variations
            let class_upper = class_name.to_ascii_uppercase();
            if class_upper.windows(4).any(|w| w == b"CODE") {
                return read::SectionKind::Text;
            } else if class_upper.windows(5).any(|w| w == b"CONST") {
                return read::SectionKind::ReadOnlyData;
            } else if class_upper.windows(3).any(|w| w == b"BSS")
                || class_upper.windows(5).any(|w| w == b"STACK")
            {
                return read::SectionKind::UninitializedData;
            } else if class_upper.windows(5).any(|w| w == b"DEBUG") {
                return read::SectionKind::Debug;
            } else if class_upper.windows(4).any(|w| w == b"DATA") {
                // DATA sections with no actual data are treated as uninitialized
                if segment.data_chunks.is_empty() {
                    return read::SectionKind::UninitializedData;
                } else {
                    return read::SectionKind::Data;
                }
            }
        }

        // Final fallback based on whether segment has data
        if segment.data_chunks.is_empty() {
            read::SectionKind::UninitializedData
        } else {
            read::SectionKind::Unknown
        }
    }

    fn parse_records(&mut self) -> Result<()> {
        let len = self
            .data
            .len()
            .map_err(|_| Error("Failed to get data length"))?;
        let data = self
            .data
            .read_bytes_at(0, len)
            .map_err(|_| Error("Failed to read OMF data"))?;
        let mut offset = 0;

        // First record must be THEADR or LHEADR
        if data.is_empty() {
            return Err(Error("Empty OMF file"));
        }

        let first_type = data[0];
        if first_type != omf::record_type::THEADR && first_type != omf::record_type::LHEADR {
            return Err(Error(
                "Invalid OMF file: first record must be THEADR or LHEADR",
            ));
        }

        let mut current_segment: Option<usize> = None;
        let mut current_data_offset: Option<u32> = None;

        // Thread storage for FIXUPP parsing
        let mut frame_threads: [Option<ThreadDef>; 4] = [None; 4];
        let mut target_threads: [Option<ThreadDef>; 4] = [None; 4];

        while offset < data.len() {
            // Read record header
            if offset + 3 > data.len() {
                break;
            }

            let record_type = data[offset];
            let length = u16::from_le_bytes([data[offset + 1], data[offset + 2]]) as usize;

            // Length includes the checksum byte at the end
            if offset + 3 + length > data.len() {
                return Err(Error("Truncated OMF record"));
            }

            // Record data excludes the checksum
            let record_data = &data[offset + 3..offset + 3 + length - 1];
            let checksum = data[offset + 3 + length - 1];

            // Verify checksum
            if !Self::verify_checksum(record_type, length, record_data, checksum) {
                return Err(Error("Invalid OMF record checksum"));
            }

            // Process record based on type
            match record_type {
                omf::record_type::THEADR | omf::record_type::LHEADR => {
                    self.parse_header(record_data)?;
                }
                omf::record_type::LNAMES | omf::record_type::LLNAMES => {
                    self.parse_names(record_data)?;
                }
                omf::record_type::SEGDEF | omf::record_type::SEGDEF32 => {
                    self.parse_segdef(record_data, record_type == omf::record_type::SEGDEF32)?;
                }
                omf::record_type::GRPDEF => {
                    self.parse_grpdef(record_data)?;
                }
                omf::record_type::PUBDEF | omf::record_type::PUBDEF32 => {
                    self.parse_pubdef(
                        record_data,
                        record_type == omf::record_type::PUBDEF32,
                        OmfSymbolClass::Public,
                    )?;
                }
                omf::record_type::LPUBDEF | omf::record_type::LPUBDEF32 => {
                    self.parse_pubdef(
                        record_data,
                        record_type == omf::record_type::LPUBDEF32,
                        OmfSymbolClass::LocalPublic,
                    )?;
                }
                omf::record_type::EXTDEF => {
                    self.parse_extdef(record_data, OmfSymbolClass::External)?;
                }
                omf::record_type::LEXTDEF | omf::record_type::LEXTDEF32 => {
                    self.parse_extdef(record_data, OmfSymbolClass::LocalExternal)?;
                }
                omf::record_type::CEXTDEF => {
                    self.parse_extdef(record_data, OmfSymbolClass::ComdatExternal)?;
                }
                omf::record_type::COMDEF => {
                    self.parse_comdef(record_data, OmfSymbolClass::Communal)?;
                }
                omf::record_type::LCOMDEF => {
                    self.parse_comdef(record_data, OmfSymbolClass::LocalCommunal)?;
                }
                omf::record_type::COMDAT | omf::record_type::COMDAT32 => {
                    self.parse_comdat(record_data, record_type == omf::record_type::COMDAT32)?;
                }
                omf::record_type::COMENT => {
                    self.parse_comment(record_data)?;
                }
                omf::record_type::LEDATA | omf::record_type::LEDATA32 => {
                    let (seg_idx, offset) =
                        self.parse_ledata(record_data, record_type == omf::record_type::LEDATA32)?;
                    current_segment = Some(seg_idx);
                    current_data_offset = Some(offset);
                }
                omf::record_type::LIDATA | omf::record_type::LIDATA32 => {
                    let (seg_idx, offset) =
                        self.parse_lidata(record_data, record_type == omf::record_type::LIDATA32)?;
                    current_segment = Some(seg_idx);
                    current_data_offset = Some(offset);
                }
                omf::record_type::FIXUPP | omf::record_type::FIXUPP32 => {
                    if let (Some(seg_idx), Some(data_offset)) =
                        (current_segment, current_data_offset)
                    {
                        self.parse_fixupp(
                            record_data,
                            record_type == omf::record_type::FIXUPP32,
                            seg_idx,
                            data_offset,
                            &mut frame_threads,
                            &mut target_threads,
                        )?;
                    } else {
                        return Err(Error(
                            "FIXUPP/FIXUPP32 record encountered without preceding LEDATA/LIDATA",
                        ));
                    }
                }
                omf::record_type::MODEND | omf::record_type::MODEND32 => {
                    // End of module
                    break;
                }
                _ => {
                    // Skip unknown record types
                }
            }

            offset += 3 + length; // header + data (which includes checksum)
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
            2 => omf::SegmentCombination::Public,
            5 => omf::SegmentCombination::Stack,
            6 => omf::SegmentCombination::Common,
            _ => return Err(Error("Invalid segment combination")),
        };

        let use32 = (acbp & 0x01) != 0;

        // Skip frame number and offset for absolute segments
        if alignment == omf::SegmentAlignment::Absolute {
            offset += 3; // frame (2) + offset (1)
        }

        // Parse segment length
        let length = if is_32bit || use32 {
            if offset + 4 > data.len() {
                return Err(Error("Truncated SEGDEF record"));
            }
            let length = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            offset += 4;
            length
        } else {
            if offset + 2 > data.len() {
                return Err(Error("Truncated SEGDEF record"));
            }
            let length = u16::from_le_bytes([data[offset], data[offset + 1]]) as u32;
            offset += 2;
            length
        };

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

        self.segments.push(OmfSegment {
            name_index,
            class_index,
            overlay_index,
            alignment,
            combination,
            use32,
            length,
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
        let (group_index, size) = read_index(data).ok_or(Error("Invalid group index"))?;
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
                symbol_index: self.symbols.len(),
                name,
                class,
                group_index,
                segment_index,
                frame_number,
                offset: pub_offset,
                type_index,
                kind: read::SymbolKind::Unknown, // Will be computed later
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
                .ok_or(Error("Invalid type index in EXTDEF/LEXTDEF/CEXTDEF record"))?;
            offset += size;

            let sym_idx = self.symbols.len();
            self.symbols.push(OmfSymbol {
                symbol_index: sym_idx,
                name,
                class,
                group_index: 0,
                segment_index: 0,
                frame_number: 0,
                offset: 0,
                type_index,
                kind: read::SymbolKind::Unknown,
            });

            // Add to external_order for symbols that contribute to external-name table
            self.external_order.push(read::SymbolIndex(sym_idx));
        }

        Ok(())
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

            let communal_length = match data_type {
                0x61 => {
                    // FAR data - number of elements followed by element size
                    let (num_elements, size1) = read_encoded_value(&data[offset..])
                        .ok_or(Error("Invalid number of elements in FAR COMDEF"))?;
                    offset += size1;
                    let (element_size, size2) = read_encoded_value(&data[offset..])
                        .ok_or(Error("Invalid element size in FAR COMDEF"))?;
                    offset += size2;
                    num_elements * element_size
                }
                0x62 => {
                    // NEAR data - size in bytes
                    let (size_val, size_bytes) = read_encoded_value(&data[offset..])
                        .ok_or(Error("Invalid size in NEAR COMDEF"))?;
                    offset += size_bytes;
                    size_val
                }
                _ => {
                    // Unknown data type, skip
                    continue;
                }
            };

            let sym_idx = self.symbols.len();
            self.symbols.push(OmfSymbol {
                symbol_index: sym_idx,
                name,
                class,
                group_index: 0,
                segment_index: 0,
                frame_number: 0,
                offset: communal_length, // Store size in offset field
                type_index,
                kind: read::SymbolKind::Data,
            });

            // Add to external_order for symbols that contribute to external-name table
            self.external_order.push(read::SymbolIndex(sym_idx));
        }

        Ok(())
    }

    fn parse_comdat(&mut self, data: &'data [u8], is_32bit: bool) -> Result<()> {
        let mut offset = 0;

        // Parse flags byte
        if offset >= data.len() {
            return Err(Error("Truncated COMDAT record"));
        }
        let _flags = data[offset];
        offset += 1;

        // Parse attributes byte
        if offset >= data.len() {
            return Err(Error("Truncated COMDAT record"));
        }
        let attributes = data[offset];
        offset += 1;

        // Extract selection criteria from high nibble of attributes
        let selection = match (attributes >> 4) & 0x0F {
            0x00 => OmfComdatSelection::Explicit,   // No match
            0x01 => OmfComdatSelection::UseAny,     // Pick any
            0x02 => OmfComdatSelection::SameSize,   // Same size
            0x03 => OmfComdatSelection::ExactMatch, // Exact match
            _ => OmfComdatSelection::UseAny,
        };

        // Extract allocation type from low nibble of attributes
        let allocation_type = attributes & 0x0F;

        // Parse align/segment index field
        let (segment_index, size) =
            read_index(&data[offset..]).ok_or(Error("Invalid COMDAT segment index"))?;
        offset += size;

        // Determine alignment - if segment index is 0-7, it's actually an alignment value
        let alignment = if segment_index <= 7 {
            match segment_index {
                0 => omf::SegmentAlignment::Absolute, // Use value from SEGDEF
                1 => omf::SegmentAlignment::Byte,
                2 => omf::SegmentAlignment::Word,
                3 => omf::SegmentAlignment::Paragraph,
                4 => omf::SegmentAlignment::Page,
                5 => omf::SegmentAlignment::DWord,
                6 => omf::SegmentAlignment::Page4K,
                _ => omf::SegmentAlignment::Byte,
            }
        } else {
            omf::SegmentAlignment::Byte // Default alignment
        };

        // Parse data offset
        let _data_offset = if is_32bit {
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

        // Parse public base (only if allocation type is 0x00 - Explicit)
        if allocation_type == 0x00 {
            // Has public base (Base Group, Base Segment, Base Frame)
            let (_group_index, size) =
                read_index(&data[offset..]).ok_or(Error("Invalid group index in COMDAT record"))?;
            offset += size;
            let (_seg_idx, size) = read_index(&data[offset..])
                .ok_or(Error("Invalid segment index in COMDAT record"))?;
            offset += size;
            if _seg_idx == 0 {
                if offset + 2 <= data.len() {
                    offset += 2; // Skip frame number
                }
            }
        }

        // Parse public name - this is an index into LNAMES
        let (name_index, size) =
            read_index(&data[offset..]).ok_or(Error("Invalid name index in COMDAT record"))?;
        offset += size;

        // Look up the name from the names table
        let name = name_index
            .checked_sub(1)
            .and_then(|i| self.names.get(i as usize).copied())
            .unwrap_or(b"");

        // Remaining data is the COMDAT content
        let comdat_data = &data[offset..];

        self.comdats.push(OmfComdatData {
            name,
            segment_index,
            selection,
            alignment,
            data: comdat_data,
        });

        Ok(())
    }

    fn parse_comment(&mut self, data: &'data [u8]) -> Result<()> {
        if data.len() < 2 {
            return Ok(()); // Ignore truncated comments
        }

        let _comment_type = data[0]; // Usually 0x00 for non-purge, 0x40 for purge
        let _comment_class = data[1];

        Ok(())
    }

    fn parse_ledata(&mut self, data: &'data [u8], is_32bit: bool) -> Result<(usize, u32)> {
        let mut offset = 0;

        // Parse segment index
        let (segment_index, size) =
            read_index(data).ok_or(Error("Invalid segment index in LEDATA"))?;
        offset += size;

        if segment_index == 0 || segment_index > self.segments.len() as u16 {
            return Err(Error("Invalid segment index in LEDATA"));
        }

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

        // Store reference to data chunk
        let seg_idx = (segment_index - 1) as usize;
        let segment = &mut self.segments[seg_idx];

        // Store the data chunk reference
        if offset < data.len() {
            segment
                .data_chunks
                .push((data_offset, OmfDataChunk::Direct(&data[offset..])));
        }

        Ok((seg_idx, data_offset))
    }

    fn parse_fixupp(
        &mut self,
        data: &'data [u8],
        is_32bit: bool,
        seg_idx: usize,
        data_offset: u32,
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
                if offset + 1 > data.len() {
                    return Err(Error("Truncated FIXUP location"));
                }
                let locat = data[offset] as u32 | (((b as u32) & 0x03) << 8);
                offset += 1;

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
                    _ => continue, // Skip unknown fixup types
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
                            let method = match thread.method {
                                0 => FrameMethod::SegmentIndex,
                                1 => FrameMethod::GroupIndex,
                                2 => FrameMethod::ExternalIndex,
                                3 => FrameMethod::FrameNumber,
                                4 => FrameMethod::Location,
                                5 => FrameMethod::Target,
                                _ => return Err(Error("Invalid frame method in thread")),
                            };
                            (method, thread.index)
                        }
                        None => return Err(Error("Undefined frame thread in FIXUP")),
                    }
                } else {
                    // F=0: Read frame datum
                    let method_bits = (fix_data >> 4) & 0x07;
                    let method = match method_bits {
                        0 => FrameMethod::SegmentIndex,
                        1 => FrameMethod::GroupIndex,
                        2 => FrameMethod::ExternalIndex,
                        3 => FrameMethod::FrameNumber,
                        4 => FrameMethod::Location,
                        5 => FrameMethod::Target,
                        _ => return Err(Error("Invalid frame method in FIXUP")),
                    };
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
                            // Only check the low 2 bits of method for target
                            let method = match thread.method & 0x03 {
                                0 => TargetMethod::SegmentIndex,
                                1 => TargetMethod::GroupIndex,
                                2 => TargetMethod::ExternalIndex,
                                3 => TargetMethod::FrameNumber,
                                _ => return Err(Error("Invalid target method in thread")),
                            };
                            (method, thread.index)
                        }
                        None => return Err(Error("Undefined target thread in FIXUP")),
                    }
                } else {
                    // T=0: Read target datum
                    // Only check the low 2 bits of method for target
                    let method = match fix_data & 0x03 {
                        0 => TargetMethod::SegmentIndex,
                        1 => TargetMethod::GroupIndex,
                        2 => TargetMethod::ExternalIndex,
                        3 => TargetMethod::FrameNumber,
                        _ => return Err(Error("Invalid frame method in FIXUP")),
                    };
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
                        if offset + 4 <= data.len() {
                            let disp = u32::from_le_bytes([
                                data[offset],
                                data[offset + 1],
                                data[offset + 2],
                                data[offset + 3],
                            ]);
                            offset += 4;
                            disp
                        } else {
                            return Err(Error("Truncated FIXUP 32-bit displacement"));
                        }
                    } else if offset + 2 <= data.len() {
                        let disp = u16::from_le_bytes([data[offset], data[offset + 1]]) as u32;
                        offset += 2;
                        disp
                    } else {
                        return Err(Error("Truncated FIXUP 16-bit displacement"));
                    }
                } else {
                    0
                };

                // Extract M-bit (bit 6 of fix_data)
                let is_segment_relative = (fix_data & 0x40) != 0;
                self.segments[seg_idx].relocations.push(OmfFixup {
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

    fn parse_lidata(&mut self, data: &'data [u8], is_32bit: bool) -> Result<(usize, u32)> {
        let mut offset = 0;

        // Read segment index
        let (segment_index, size) =
            read_index(&data[offset..]).ok_or(Error("Invalid segment index in LIDATA"))?;
        offset += size;

        if segment_index == 0 || segment_index > self.segments.len() as u16 {
            return Err(Error("Invalid segment index in LIDATA"));
        }

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

        // For LIDATA, we need to store the unexpanded data and expand on demand
        let seg_idx = (segment_index - 1) as usize;
        if offset < data.len() {
            self.segments[seg_idx]
                .data_chunks
                .push((data_offset, OmfDataChunk::Iterated(&data[offset..])));
        }

        Ok((seg_idx, data_offset))
    }

    /// Get the module name
    pub fn module_name(&self) -> Option<&'data str> {
        self.module_name
    }

    /// Get the segments as a slice
    pub fn segments_slice(&self) -> &[OmfSegment<'data>] {
        &self.segments
    }

    /// Get symbol by external-name index (1-based, as used in FIXUPP records)
    pub fn external_symbol(&self, external_index: u16) -> Option<&OmfSymbol<'data>> {
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

    /// Get all symbols (for iteration)
    pub fn all_symbols(&self) -> &[OmfSymbol<'data>] {
        &self.symbols
    }

    /// Verify the checksum of an OMF record
    ///
    /// The checksum is calculated so that the sum of all bytes in the record,
    /// including the checksum byte itself, equals 0 (modulo 256).
    fn verify_checksum(record_type: u8, length: usize, body: &[u8], checksum: u8) -> bool {
        // Some compilers write a 0 byte rather than computing the checksum,
        // so we accept that as valid
        if checksum == 0 {
            return true;
        }

        let mut sum = u32::from(record_type);
        // Add length bytes (little-endian)
        sum = sum.wrapping_add((length & 0xff) as u32);
        sum = sum.wrapping_add((length >> 8) as u32);
        // Add all body bytes
        for &byte in body {
            sum = sum.wrapping_add(u32::from(byte));
        }
        // Add checksum byte
        sum = sum.wrapping_add(u32::from(checksum));

        // The sum should be 0 (modulo 256)
        (sum & 0xff) == 0
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

    fn imports(&self) -> Result<Vec<Import<'data>>> {
        Ok(self
            .all_symbols()
            .iter()
            .filter(|sym| {
                matches!(
                    sym.class,
                    OmfSymbolClass::External | OmfSymbolClass::ComdatExternal
                )
            })
            .map(|ext| Import {
                library: ByteString(b""),
                name: ByteString(ext.name),
            })
            .collect())
    }

    fn exports(&self) -> Result<Vec<Export<'data>>> {
        Ok(self
            .all_symbols()
            .iter()
            .filter(|sym| sym.class == OmfSymbolClass::Public)
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
#[repr(u8)]
pub(super) enum TargetMethod {
    /// Segment index
    SegmentIndex = 0,
    /// Group index
    GroupIndex = 1,
    /// External index
    ExternalIndex = 2,
    /// Frame number (absolute)
    FrameNumber = 3,
}

/// Frame method types for fixups
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub(super) enum FrameMethod {
    /// Segment index
    SegmentIndex = 0,
    /// Group index
    GroupIndex = 1,
    /// External index
    ExternalIndex = 2,
    /// Frame number (absolute)
    FrameNumber = 3,
    /// Location (use fixup location)
    Location = 4,
    /// Target (use target's frame)
    Target = 5,
}

/// Expand a LIDATA block into its uncompressed form
pub(super) fn expand_lidata_block(data: &[u8]) -> Result<Vec<u8>> {
    let (consumed, expanded_size) = lidata_block_expanded_size(data)?;
    let mut result = vec![0u8; expanded_size];
    let mut write_offset = 0usize;
    let consumed_by_expand = expand_lidata_block_into(data, &mut result, &mut write_offset)?;

    debug_assert_eq!(write_offset, expanded_size);
    debug_assert_eq!(consumed_by_expand, consumed);

    Ok(result)
}

fn expand_lidata_block_into(
    data: &[u8],
    output: &mut [u8],
    write_offset: &mut usize,
) -> Result<usize> {
    let mut offset = 0;

    let (repeat_count, size) =
        read_encoded_value(&data[offset..]).ok_or(Error("Invalid repeat count in LIDATA block"))?;
    offset += size;

    if repeat_count == 0 {
        return lidata_block_size(data);
    }

    let repeat_count = repeat_count as usize;

    let (block_count, size) =
        read_encoded_value(&data[offset..]).ok_or(Error("Invalid block count in LIDATA block"))?;
    offset += size;

    if block_count == 0 {
        if offset >= data.len() {
            return Ok(offset);
        }

        let data_length = data[offset] as usize;
        offset += 1;

        if offset + data_length > data.len() {
            return Err(Error("Truncated LIDATA block"));
        }

        let block_data = &data[offset..offset + data_length];
        offset += data_length;

        for _ in 0..repeat_count {
            let end = write_offset
                .checked_add(data_length)
                .ok_or(Error("LIDATA expanded size overflow"))?;
            if end > output.len() {
                return Err(Error("LIDATA expanded size mismatch"));
            }
            output[*write_offset..end].copy_from_slice(block_data);
            *write_offset = end;
        }
    } else {
        let mut block_offset = offset;
        let iteration_start = *write_offset;

        for _ in 0..block_count {
            let block_size = lidata_block_size(&data[block_offset..])?;
            let block_consumed =
                expand_lidata_block_into(&data[block_offset..], output, write_offset)?;

            debug_assert_eq!(block_size, block_consumed);
            block_offset = block_offset
                .checked_add(block_size)
                .ok_or(Error("LIDATA block size overflow"))?;
            if block_offset > data.len() {
                return Err(Error("Truncated LIDATA block"));
            }
        }

        let iteration_len = *write_offset - iteration_start;

        for _ in 1..repeat_count {
            let dest_start = *write_offset;
            let dest_end = dest_start
                .checked_add(iteration_len)
                .ok_or(Error("LIDATA expanded size overflow"))?;
            if dest_end > output.len() {
                return Err(Error("LIDATA expanded size mismatch"));
            }
            if iteration_len != 0 {
                output.copy_within(iteration_start..iteration_start + iteration_len, dest_start);
            }
            *write_offset = dest_end;
        }

        offset = block_offset;
    }

    Ok(offset)
}

fn lidata_block_expanded_size(data: &[u8]) -> Result<(usize, usize)> {
    let mut offset = 0;

    let (repeat_count, size) =
        read_encoded_value(&data[offset..]).ok_or(Error("Invalid repeat count in LIDATA block"))?;
    offset += size;

    if repeat_count == 0 {
        let consumed = lidata_block_size(data)?;
        if consumed > data.len() {
            return Err(Error("Truncated LIDATA block"));
        }
        return Ok((consumed, 0));
    }

    let (block_count, size) =
        read_encoded_value(&data[offset..]).ok_or(Error("Invalid block count in LIDATA block"))?;
    offset += size;

    if block_count == 0 {
        if offset >= data.len() {
            return Ok((offset, 0));
        }

        let data_length = data[offset] as usize;
        offset += 1;

        if offset + data_length > data.len() {
            return Err(Error("Truncated LIDATA block"));
        }

        offset += data_length;

        let expanded = data_length
            .checked_mul(repeat_count as usize)
            .ok_or(Error("LIDATA expanded size overflow"))?;
        Ok((offset, expanded))
    } else {
        let mut block_offset = offset;
        let mut single_iteration = 0usize;

        for _ in 0..block_count {
            let (consumed, expanded) = lidata_block_expanded_size(&data[block_offset..])?;
            block_offset = block_offset
                .checked_add(consumed)
                .ok_or(Error("LIDATA block size overflow"))?;
            if block_offset > data.len() {
                return Err(Error("Truncated LIDATA block"));
            }
            single_iteration = single_iteration
                .checked_add(expanded)
                .ok_or(Error("LIDATA expanded size overflow"))?;
        }

        let expanded = single_iteration
            .checked_mul(repeat_count as usize)
            .ok_or(Error("LIDATA expanded size overflow"))?;

        Ok((block_offset, expanded))
    }
}

/// Helper function to calculate LIDATA block size
fn lidata_block_size(data: &[u8]) -> Result<usize> {
    let mut offset = 0;

    // Read repeat count
    let (_, size) =
        read_encoded_value(&data[offset..]).ok_or(Error("Invalid repeat count in LIDATA block"))?;
    offset += size;

    // Read block count
    let (block_count, size) =
        read_encoded_value(&data[offset..]).ok_or(Error("Invalid block count in LIDATA block"))?;
    offset += size;

    if block_count == 0 {
        // Leaf block
        if offset >= data.len() {
            return Ok(offset);
        }
        let data_length = data[offset] as usize;
        offset += 1 + data_length;
    } else {
        // Nested blocks
        for _ in 0..block_count {
            offset += lidata_block_size(&data[offset..])?;
        }
    }

    Ok(offset)
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

/// Read an encoded value (used in LIDATA for repeat counts and block counts)
/// Returns the value and number of bytes consumed
fn read_encoded_value(data: &[u8]) -> Option<(u32, usize)> {
    if data.is_empty() {
        return None;
    }

    let first_byte = data[0];
    if first_byte < 0x80 {
        // Single byte value (0-127)
        Some((first_byte as u32, 1))
    } else if first_byte == 0x81 {
        // Two byte value: 0x81 followed by 16-bit little-endian value
        if data.len() >= 3 {
            let value = u16::from_le_bytes([data[1], data[2]]) as u32;
            Some((value, 3))
        } else {
            None
        }
    } else if first_byte == 0x84 {
        // Three byte value: 0x84 followed by 24-bit little-endian value
        if data.len() >= 4 {
            let value = u32::from_le_bytes([data[1], data[2], data[3], 0]);
            Some((value, 4))
        } else {
            None
        }
    } else if first_byte == 0x88 {
        // Four byte value: 0x88 followed by 32-bit little-endian value
        if data.len() >= 5 {
            let value = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            Some((value, 5))
        } else {
            None
        }
    } else {
        // Unknown encoding
        None
    }
}
