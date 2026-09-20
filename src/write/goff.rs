use crate::endian::{BigEndian as BE, U16, U32};
use crate::goff;
use crate::goff::SIZEOF_ENTRY_POINT_NAME;
use crate::write::util::*;
use crate::write::*;
#[cfg(not(feature = "std"))]
use alloc::collections::btree_map::BTreeMap as HashMap;
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::collections::hash_map::HashMap;

// EBCDIC-encoded constant strings
const EBCDIC_RUSTCU: &[u8] = &[0x99, 0xA4, 0xA2, 0xA3, 0x83, 0xA4]; // "rustcu"
const EBCDIC_C_WSA64: &[u8] = &[0xC3, 0x5F, 0xE6, 0xE2, 0xC1, 0xF6, 0xF4]; // "C_WSA64"
const EBCDIC_C_CODE64: &[u8] = &[0xC3, 0x5F, 0xC3, 0xD6, 0xC4, 0xC5, 0xF6, 0xF4]; // "C_CODE64"

impl<'a> Object<'a> {
    /// Get symbols that belong to a specific section.
    fn symbols_in_section(&self, section_id: SectionId) -> Vec<(SymbolId, &Symbol)> {
        self.symbols
            .iter()
            .enumerate()
            .filter(|(_, s)| s.section == SymbolSection::Section(section_id))
            .map(|(i, s)| (SymbolId(i), s))
            .collect()
    }

    /// Get all undefined symbols.
    fn undefined_symbols(&self) -> Vec<(SymbolId, &Symbol)> {
        self.symbols
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_undefined())
            .map(|(i, s)| (SymbolId(i), s))
            .collect()
    }

    /// Write goff file
    pub(crate) fn goff_write(&self, buffer: &mut dyn WritableBuffer) -> Result<()> {
        let mut writer = Writer::new(buffer);
        writer.write_hdr();

        // Write compilation unit SD
        writer.cu_esdid = writer.write_compilation_unit(EBCDIC_RUSTCU);

        // Write undefined symbols (external references) FIRST
        // This ensures their ESDIDs are available when processing relocations
        for (symbol_id, symbol) in self.undefined_symbols() {
            writer.write_undefined_symbol(symbol, symbol_id)?;
        }

        // Process sections with their symbols
        for (section_index, section) in self.sections.iter().enumerate() {
            let section_id = SectionId(section_index);

            // Skip empty sections
            if section.data.is_empty() && self.symbols_in_section(section_id).is_empty() {
                continue;
            }

            // Write ED for section
            let ed_esdid = writer.get_or_create_section_ed(section, section_id)?;

            // Write defined symbols in this section
            for (symbol_id, symbol) in self.symbols_in_section(section_id) {
                if !symbol.is_undefined() {
                    writer.write_defined_symbol(symbol, symbol_id, ed_esdid)?;
                }
            }

            // Write section data if present
            if !section.data.is_empty() {
                let record_style = writer.select_txt_record_style(section);
                writer.write_text(ed_esdid, &section.data, record_style);
            }

            // Collect relocations for this section
            for reloc in &section.relocations {
                writer.add_relocation(reloc, section_id, ed_esdid)?;
            }
        }

        // Write all collected relocations
        writer.write_relocations()?;

        writer.write_end();
        Ok(())
    }

    /// Returns GOFF section info
    pub(crate) fn goff_section_info(
        &self,
        section: StandardSection,
    ) -> (&'static [u8], &'static [u8], SectionKind, SectionFlags) {
        match section {
            StandardSection::Text => (&[], EBCDIC_C_CODE64, SectionKind::Text, SectionFlags::None),
            StandardSection::Data => (&[], EBCDIC_C_WSA64, SectionKind::Data, SectionFlags::None),
            StandardSection::ReadOnlyData | StandardSection::ReadOnlyString => (
                &[],
                EBCDIC_C_CODE64,
                SectionKind::ReadOnlyData,
                SectionFlags::None,
            ),
            StandardSection::ReadOnlyDataWithRel => (
                &[],
                EBCDIC_C_WSA64,
                SectionKind::ReadOnlyDataWithRel,
                SectionFlags::None,
            ),
            StandardSection::UninitializedData => (
                &[],
                EBCDIC_C_WSA64,
                SectionKind::UninitializedData,
                SectionFlags::None,
            ),
            StandardSection::Tls => {
                // Unsupported section.
                (&[], &[], SectionKind::Tls, SectionFlags::None)
            }
            StandardSection::UninitializedTls => {
                // Unsupported section.
                (&[], &[], SectionKind::UninitializedTls, SectionFlags::None)
            }
            StandardSection::TlsVariables => {
                // Unsupported section.
                (&[], &[], SectionKind::TlsVariables, SectionFlags::None)
            }
            StandardSection::GnuProperty => {
                // Unsupported section.
                (&[], &[], SectionKind::Note, SectionFlags::None)
            }
            StandardSection::EhFrame => {
                // Unsupported section
                (&[], &[], SectionKind::Unknown, SectionFlags::None)
            }
        }
    }

    pub(crate) fn goff_translate_relocation(
        &mut self,
        _relocation: &mut RelocationInternal,
    ) -> Result<()> {
        // GOFF relocations are handled during write by the GOFF writer
        // No translation needed here as flags are already in generic format
        Ok(())
    }

    pub(crate) fn goff_adjust_addend(
        &mut self,
        _relocation: &mut RelocationInternal,
    ) -> Result<bool> {
        // GOFF uses explicit addends in RLD records
        // Return false to indicate addends are explicit, not implicit
        Ok(false)
    }
}

/// Tracks symbol hierarchy and relationships in GOFF.
#[derive(Debug, Clone, Default)]
struct SymbolHierarchy {
    children: Vec<u32>,
    symbol_id: Option<SymbolId>,
}

/// A pending relocation to be written to RLD records.
#[derive(Debug, Clone)]
struct PendingRelocation {
    /// Flags for this relocation (6 bytes)
    flags: [u8; 6],
    /// R-pointer (reference ESDID)
    r_pointer: u32,
    /// P-pointer (location ESDID)
    p_pointer: u32,
    /// Offset within P-pointer element
    offset: u32,
}

/// Builder for constructing GOFF relocation flags.
#[derive(Debug, Clone)]
pub struct RelocationFlagsBuilder {
    /// Byte 0: Compression and mode flags
    compression_and_mode: u8,
    /// Byte 1: R-Pointer indicators (reference type and referent type)
    r_pointer_indicators: u8,
    /// Byte 2: Action/operation flags
    action_flags: u8,
    /// Byte 3: Reserved
    reserved: u8,
    /// Byte 4: Target field byte length
    target_field_length: u8,
    /// Byte 5: Bit-level field specifications
    bit_field_specs: u8,
}

impl RelocationFlagsBuilder {
    /// Create a new builder with default values.
    pub fn new() -> Self {
        Self {
            compression_and_mode: 0,
            r_pointer_indicators: 0,
            action_flags: 0,
            reserved: 0,
            target_field_length: 0,
            bit_field_specs: 0,
        }
    }

    /// Set the reference type (upper 4 bits of byte 1).
    /// 0=R-address, 1=R-Offset, 2=R-Length, 6=R-Relative-Immediate
    pub fn with_reference_type(mut self, ref_type: u8) -> Self {
        self.r_pointer_indicators = (self.r_pointer_indicators & 0x0F) | ((ref_type & 0x0F) << 4);
        self
    }

    /// Set the referent type (lower 4 bits of byte 1).
    /// 0=Label, 1=Element, 2=Class, 3=Part
    pub fn with_referent_type(mut self, ref_type: u8) -> Self {
        self.r_pointer_indicators = (self.r_pointer_indicators & 0xF0) | (ref_type & 0x0F);
        self
    }

    /// Set the action/operation (upper 7 bits of byte 2).
    /// 0=add, 1=subtract
    pub fn with_action(mut self, action: u8) -> Self {
        self.action_flags = (self.action_flags & 0x01) | ((action & 0x7F) << 1);
        self
    }

    /// Set the target field byte length (byte 4).
    pub fn with_target_length(mut self, length: u8) -> Self {
        self.target_field_length = length;
        self
    }

    /// Build the final 6-byte flags array.
    pub fn build(self) -> [u8; 6] {
        [
            self.compression_and_mode,
            self.r_pointer_indicators,
            self.action_flags,
            self.reserved,
            self.target_field_length,
            self.bit_field_specs,
        ]
    }
}

impl Default for RelocationFlagsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A helper for writing GOFF files.
pub struct Writer<'a> {
    buffer: &'a mut dyn WritableBuffer,

    next_esdid: u32,
    cu_esdid: u32, // ESD id for compile unit

    logical_record_count: u32,
    continuation_record_count: u32,

    // Symbol hierarchy tracking
    symbol_hierarchy: HashMap<u32, SymbolHierarchy>,
    // Map section ID to ED ESDID
    section_to_ed: HashMap<SectionId, u32>,

    // Relocation tracking
    relocations: Vec<PendingRelocation>,
}

impl<'a> Writer<'a> {
    /// Create a new `Writer`.
    pub fn new(buffer: &'a mut dyn WritableBuffer) -> Self {
        Writer {
            buffer,

            next_esdid: 1,
            cu_esdid: 0,
            logical_record_count: 0,
            continuation_record_count: 0,
            symbol_hierarchy: HashMap::new(),
            section_to_ed: HashMap::new(),
            relocations: Vec::new(),
        }
    }

    // Write module header ("HDR") record.
    pub fn write_hdr(&mut self) {
        let header = goff::HeaderRecord64 {
            ptv: goff::GOFF_HDR_BYTES,
            reserved1: [0u8; 45],
            archlvl: U32::new(BE, 1),
            reserved2: [0u8; 28],
        };
        self.logical_record_count += 1;
        self.buffer.write_pod(&header);
    }

    // Write module end ("END") record.
    pub fn write_end(&mut self) {
        self.logical_record_count += 1;
        let fileend = goff::EndRecord64 {
            ptv: goff::GOFF_END_BYTES,
            flags: 0,
            amode: 0,
            reserved1: [0u8; 3],
            record_cnt: U32::new(BE, self.logical_record_count), // count includes this END record.
            esdid: U32::new(BE, 0),
            reserved2: [0u8; 4],
            offset: U32::new(BE, 0),
            name_length: U16::new(BE, 0),
            entry_name: [0u8; SIZEOF_ENTRY_POINT_NAME],
        };
        self.buffer.write_pod(&fileend);
    }

    pub fn write_er_to_text(&mut self, symbol_name: &[u8]) -> u32 {
        let mut er = self.get_esd_record(goff::ESD_ST_ER, goff::ESD_NS_NORMAL_NAME, self.cu_esdid);

        // External reference to code: executable, export scope
        let attrs = default_attrs()
            .with_executable(goff::EXEC_CODE)
            .with_binding_scope(goff::ESD_BSC_IMPORT_EXPORT)
            .with_alignment(goff::ALIGN_32BYTE);
        er.behavioral_attributes = attrs;

        self.write_esd_record(&er, symbol_name)
    }

    pub fn write_er_to_data(&mut self, symbol_name: &[u8]) -> u32 {
        self.write_wsa_symbol(symbol_name, 0)
    }

    pub fn write_wsa_symbol(&mut self, symbol_name: &[u8], symbol_length: u32) -> u32 {
        // Emit parent C_WSA64 ED symbol (data section).
        let mut ed = self.get_esd_record(goff::ESD_ST_ED, goff::ESD_NS_PARTS, self.cu_esdid);
        ed.sym_flags = 0x80; // Fill byte present

        let ed_attrs = data_attrs()
            .with_binding_algorithm(goff::ESD_BA_MERGE)
            .with_executable(goff::EXEC_DATA)
            .with_binding_scope(goff::ESD_BSC_IMPORT_EXPORT)
            .with_alignment(goff::ALIGN_HALFWORD);
        ed.behavioral_attributes = ed_attrs;
        let ed_esdid = self.write_esd_record(&ed, EBCDIC_C_WSA64);

        // Emit PR child symbol using write_pr method.
        let pr_attrs = default_attrs()
            .with_executable(goff::EXEC_DATA)
            .with_binding_strength(goff::ESD_BST_WEAK)
            .with_binding_scope(goff::ESD_BSC_IMPORT_EXPORT)
            .with_alignment(goff::ALIGN_HALFWORD);

        self.write_pr(symbol_name, ed_esdid, symbol_length, pr_attrs)
    }

    pub fn write_debug_section_symbol(&mut self, section_name: &[u8], section_length: u32) -> u32 {
        // Emit ED symbol for debug section.
        let mut ed = self.get_esd_record(goff::ESD_ST_ED, goff::ESD_NS_PARTS, self.cu_esdid);
        ed.sym_flags = 0x80; // Fill byte present
        ed.length = U32::new(BE, section_length);

        // Debug sections are read-only data that must be loaded
        let attrs = readonly_data_attrs()
            .with_binding_algorithm(goff::ESD_BA_MERGE)
            .with_executable(goff::EXEC_DATA)
            .with_loading_behavior(goff::LOAD_INITIAL)
            .with_alignment(goff::ALIGN_BYTE);
        ed.behavioral_attributes = attrs;

        self.write_esd_record(&ed, section_name)
    }

    /// Write an SD (Section Definition) record.
    ///
    /// SD records define control sections (compilation units).
    pub fn write_sd(&mut self, name: &[u8], attributes: goff::BehavioralAttributes) -> u32 {
        let mut sd = self.get_esd_record(
            goff::ESD_ST_SD,
            goff::ESD_NS_PROGRAM_MANAGEMENT_BINDER,
            0, // No parent for SD
        );
        sd.behavioral_attributes = attributes;
        self.write_esd_record(&sd, name)
    }

    /// Write an ED (Element Definition) record.
    ///
    /// ED records define elements (code/data sections).
    pub fn write_ed(
        &mut self,
        name: &[u8],
        parent_esdid: u32,
        length: u32,
        attributes: goff::BehavioralAttributes,
    ) -> u32 {
        let mut ed = self.get_esd_record(goff::ESD_ST_ED, goff::ESD_NS_NORMAL_NAME, parent_esdid);
        ed.length = U32::new(BE, length);
        ed.sym_flags = 0x80; // Fill byte present
        ed.behavioral_attributes = attributes;
        self.write_esd_record(&ed, name)
    }

    /// Write an LD (Label Definition) record.
    ///
    /// LD records define labels within sections (function/variable names).
    pub fn write_ld(
        &mut self,
        name: &[u8],
        parent_esdid: u32,
        offset: u32,
        scope: goff::BindingScope,
    ) -> u32 {
        let mut ld = self.get_esd_record(goff::ESD_ST_LD, goff::ESD_NS_NORMAL_NAME, parent_esdid);
        ld.offset = U32::new(BE, offset);

        let attrs = default_attrs().with_binding_scope(scope);
        ld.behavioral_attributes = attrs;

        self.write_esd_record(&ld, name)
    }

    /// Write a PR (Part Reference) record.
    ///
    /// PR records reference parts of elements (data within sections).
    pub fn write_pr(
        &mut self,
        name: &[u8],
        parent_esdid: u32,
        length: u32,
        attributes: goff::BehavioralAttributes,
    ) -> u32 {
        let mut pr = self.get_esd_record(goff::ESD_ST_PR, goff::ESD_NS_PARTS, parent_esdid);
        pr.length = U32::new(BE, length);
        pr.behavioral_attributes = attributes;
        self.write_esd_record(&pr, name)
    }

    /// Write an ER (External Reference) record with weak binding.
    pub fn write_er_weak(&mut self, name: &[u8], parent_esdid: u32, is_code: bool) -> u32 {
        let mut er = self.get_esd_record(goff::ESD_ST_ER, goff::ESD_NS_NORMAL_NAME, parent_esdid);

        let attrs = default_attrs()
            .with_executable(if is_code {
                goff::EXEC_CODE
            } else {
                goff::EXEC_DATA
            })
            .with_binding_strength(goff::ESD_BST_WEAK)
            .with_binding_scope(goff::ESD_BSC_IMPORT_EXPORT);
        er.behavioral_attributes = attrs;

        self.write_esd_record(&er, name)
    }

    /// Add a symbol to the hierarchy tracking system.
    fn add_symbol_to_hierarchy(
        &mut self,
        esdid: u32,
        parent_esdid: u32,
        symbol_id: Option<SymbolId>,
    ) {
        let hierarchy = SymbolHierarchy {
            children: Vec::new(),
            symbol_id,
        };

        // Add to parent's children list
        if parent_esdid != 0 {
            if let Some(parent) = self.symbol_hierarchy.get_mut(&parent_esdid) {
                parent.children.push(esdid);
            }
        }

        self.symbol_hierarchy.insert(esdid, hierarchy);
    }

    /// Get or create an ED for a section.
    fn get_or_create_section_ed(
        &mut self,
        section: &Section<'_>,
        section_id: SectionId,
    ) -> Result<u32> {
        // Check if ED already exists for this section
        if let Some(&ed_esdid) = self.section_to_ed.get(&section_id) {
            return Ok(ed_esdid);
        }

        // Determine section attributes and create ED based on kind
        let ed_esdid = match section.kind {
            SectionKind::Text => {
                let attrs = code_attrs().with_binding_scope(goff::ESD_BSC_MODULE);
                self.write_ed(
                    &section.name,
                    self.cu_esdid,
                    section.data.len() as u32,
                    attrs,
                )
            }
            SectionKind::Data => {
                let attrs = data_attrs().with_binding_scope(goff::ESD_BSC_MODULE);
                self.write_ed(
                    &section.name,
                    self.cu_esdid,
                    section.data.len() as u32,
                    attrs,
                )
            }
            SectionKind::ReadOnlyData => {
                let attrs = readonly_data_attrs().with_binding_scope(goff::ESD_BSC_MODULE);
                self.write_ed(
                    &section.name,
                    self.cu_esdid,
                    section.data.len() as u32,
                    attrs,
                )
            }
            SectionKind::Debug => {
                // Debug sections need special handling with ESD_NS_PARTS namespace
                self.write_debug_section_symbol(&section.name, section.data.len() as u32)
            }
            _ => {
                return Err(Error(format!(
                    "Unsupported section kind {:?}",
                    section.kind
                )));
            }
        };

        // Track the ED
        self.add_symbol_to_hierarchy(ed_esdid, self.cu_esdid, None);

        self.section_to_ed.insert(section_id, ed_esdid);

        Ok(ed_esdid)
    }

    /// Write a compilation unit SD.
    fn write_compilation_unit(&mut self, cu_name: &[u8]) -> u32 {
        let attrs = default_attrs().with_binding_scope(goff::ESD_BSC_SECTION);

        let sd_esdid = self.write_sd(cu_name, attrs);

        // Track the SD
        self.add_symbol_to_hierarchy(sd_esdid, 0, None);

        sd_esdid
    }

    pub fn get_esd_record(
        &self,
        symbol_type: goff::SymbolType,
        namespace_id: goff::EsdNameSpace,
        parent_esdid: u32,
    ) -> goff::SymbolRecord64 {
        goff::SymbolRecord64 {
            ptv: goff::GOFF_ESD_BYTES,
            symbol_type,
            esdid: U32::new(BE, self.next_esdid),
            parent_esdid: U32::new(BE, parent_esdid),
            reserved1: U32::new(BE, 0),
            offset: U32::new(BE, 0),
            reserved2: U32::new(BE, 0),
            length: U32::new(BE, 0),
            ea_esdid: U32::new(BE, 0),
            ea_data_offset: U32::new(BE, 0),
            reserved3: U32::new(BE, 0),
            namespace_id,
            sym_flags: 0,
            fill_byte_value: 0,
            reserved4: 0,
            ada_esdid: U32::new(BE, 0),
            priority: U32::new(BE, 0),
            reserved5: [0u8; 8],
            behavioral_attributes: Default::default(),
            name_length: U16::new(BE, 0),
            name: [0u8; goff::SIZEOF_ESD_DATA],
        }
    }

    pub fn write_esd_record(&mut self, record: &goff::SymbolRecord64, name: &[u8]) -> u32 {
        let mut esd_record = *record;
        let mut record_name_len = name.len();
        let mut ptv = goff::GOFF_ESD_BYTES;
        if record_name_len > goff::SIZEOF_ESD_DATA {
            record_name_len = goff::SIZEOF_ESD_DATA;
            ptv[1] |= 0x1;
        }
        esd_record.ptv = ptv;
        esd_record.name_length = U16::new(BE, name.len() as u16);
        esd_record.name[..record_name_len].copy_from_slice(&name[..record_name_len]);

        self.next_esdid += 1;

        self.logical_record_count += 1;
        self.buffer.write_pod(&esd_record);
        self.write_continuation_records(goff::GOFF_ESD_BYTES, name, name.len() - record_name_len);

        self.next_esdid - 1
    }

    pub fn write_continuation_records(
        &mut self,
        record_type: [u8; 3],
        data: &[u8],
        mut data_remaining_amount: usize,
    ) {
        while data_remaining_amount > 0 {
            let mut ptv = record_type;
            ptv[1] |= 0x2;

            let start = data.len() - data_remaining_amount;
            let mut end = data.len();
            if data_remaining_amount > goff::SIZEOF_CONTINUATION_RECORD_DATA {
                ptv[1] |= 0x1;
                end = start + goff::SIZEOF_CONTINUATION_RECORD_DATA;
            }

            let mut cont_record = goff::ContinuationRecord64 {
                ptv,
                data: [0u8; goff::SIZEOF_CONTINUATION_RECORD_DATA],
            };
            let record_data_amount = end - start;
            cont_record.data[..record_data_amount].copy_from_slice(&data[start..end]);
            data_remaining_amount -= record_data_amount;

            self.continuation_record_count += 1;
            self.buffer.write_pod(&cont_record);
        }
    }

    pub fn write_text(&mut self, esdid: u32, data: &[u8], record_style: u8) {
        // The maximum number of bytes that can be included in a RLD or TXT record and
        // their continuations is a SIGNED 16 bit int despite what the spec says. The
        // number of bytes we allow ourselves to attach to a card is thus limited to
        // 32K-1 bytes.
        let max_logical_length = 32 * 1024 - 1;

        let mut data_remaining_amount = data.len();
        let mut offset = 0_usize;
        while data_remaining_amount > 0 {
            let logical_write_len = if data_remaining_amount > max_logical_length {
                max_logical_length
            } else {
                data_remaining_amount
            };
            let mut ptv = goff::GOFF_TXT_BYTES;
            let mut record_data_len = logical_write_len;
            if record_data_len > goff::SIZEOF_TXT_DATA {
                record_data_len = goff::SIZEOF_TXT_DATA;
                ptv[1] |= 0x1;
            }

            let mut record = goff::TextRecord64 {
                ptv,
                record_style: goff::TextRecordStyle(record_style),
                element_esdid: U32::new(BE, esdid),
                reserved1: U32::new(BE, 0),
                offset: U32::new(BE, offset as u32),
                true_length: U32::new(BE, 0),
                text_encoding: U16::new(BE, 0),
                data_length: U16::new(BE, logical_write_len as u16),
                data: [0u8; goff::SIZEOF_TXT_DATA],
            };
            record.data[..record_data_len].copy_from_slice(&data[offset..offset + record_data_len]);
            self.logical_record_count += 1;
            self.buffer.write_pod(&record);
            self.write_continuation_records(
                goff::GOFF_TXT_BYTES,
                &data[offset..offset + logical_write_len],
                logical_write_len - record_data_len,
            );

            offset += logical_write_len;
            data_remaining_amount -= logical_write_len;
        }
    }

    /// Select the appropriate TXT record style based on section properties.
    fn select_txt_record_style(&self, _section: &Section<'_>) -> u8 {
        // Default to byte-style for all sections
        goff::TXT_RS_BYTE.0
    }

    /// Write a defined symbol with proper hierarchy (LD or PR).
    fn write_defined_symbol(
        &mut self,
        symbol: &Symbol,
        symbol_id: SymbolId,
        parent_ed_esdid: u32,
    ) -> Result<u32> {
        // Determine binding scope based on symbol properties
        let scope = if symbol.is_local() {
            goff::ESD_BSC_SECTION
        } else if symbol.scope == SymbolScope::Dynamic {
            goff::ESD_BSC_IMPORT_EXPORT
        } else {
            goff::ESD_BSC_MODULE
        };

        // Write LD (Label Definition) for the symbol
        let ld_esdid = self.write_ld(&symbol.name, parent_ed_esdid, symbol.value as u32, scope);

        // Track the LD
        self.add_symbol_to_hierarchy(ld_esdid, parent_ed_esdid, Some(symbol_id));

        Ok(ld_esdid)
    }

    /// Write an undefined symbol (external reference).
    fn write_undefined_symbol(&mut self, symbol: &Symbol, symbol_id: SymbolId) -> Result<u32> {
        let is_code = match symbol.kind {
            SymbolKind::Text => true,
            SymbolKind::Data => false,
            _ => {
                // Default to data for unknown kinds
                false
            }
        };

        // Check if it's a weak reference
        let esdid = if symbol.weak {
            self.write_er_weak(&symbol.name, self.cu_esdid, is_code)
        } else {
            // Use existing methods for compatibility
            if is_code {
                self.write_er_to_text(&symbol.name)
            } else {
                self.write_er_to_data(&symbol.name)
            }
        };

        // Track the ER
        self.add_symbol_to_hierarchy(esdid, self.cu_esdid, Some(symbol_id));

        Ok(esdid)
    }

    /// Find the ESDID for a given symbol ID.
    fn find_symbol_esdid(&self, symbol_id: SymbolId) -> Result<u32> {
        for (esdid, hierarchy) in &self.symbol_hierarchy {
            if hierarchy.symbol_id == Some(symbol_id) {
                return Ok(*esdid);
            }
        }
        Err(Error(format!("Symbol ESDID not found for {:?}", symbol_id)))
    }

    /// Map a symbol ID to an ESDID (R-pointer).
    fn map_symbol_to_esdid(&self, symbol_id: SymbolId) -> Result<u32> {
        self.find_symbol_esdid(symbol_id)
    }

    /// Build relocation flags based on relocation properties.
    fn build_relocation_flags(&self, flags: &RelocationFlags, size: u8) -> Result<[u8; 6]> {
        let mut builder = RelocationFlagsBuilder::new();

        // Map relocation flags to GOFF reference type and action
        match flags {
            RelocationFlags::Generic {
                kind,
                encoding: _,
                size: _,
            } => {
                match kind {
                    RelocationKind::Absolute => {
                        builder = builder
                            .with_reference_type(0) // R-address
                            .with_action(0); // Add
                    }
                    RelocationKind::Relative => {
                        builder = builder
                            .with_reference_type(6) // R-Relative-Immediate
                            .with_action(1); // Subtract
                    }
                    RelocationKind::Got => {
                        builder = builder
                            .with_reference_type(0) // R-address
                            .with_action(0); // Add
                    }
                    RelocationKind::PltRelative => {
                        builder = builder
                            .with_reference_type(6) // R-Relative-Immediate
                            .with_action(1); // Subtract
                    }
                    RelocationKind::GotRelative => {
                        builder = builder
                            .with_reference_type(6) // R-Relative-Immediate
                            .with_action(1); // Subtract
                    }
                    RelocationKind::SectionOffset => {
                        builder = builder
                            .with_reference_type(1) // R-Offset
                            .with_action(0); // Add
                    }
                    _ => {
                        return Err(Error(format!("Unsupported relocation kind: {:?}", kind)));
                    }
                }
            }
            _ => {
                return Err(Error("Unsupported relocation flags type for GOFF".into()));
            }
        }

        // Set target field length (convert bits to bytes)
        builder = builder.with_target_length(size / 8);

        // Set referent type to Label (0) - most common case
        builder = builder.with_referent_type(0);

        Ok(builder.build())
    }

    /// Add a relocation to the pending list.
    pub fn add_relocation(
        &mut self,
        reloc: &RelocationInternal,
        _section_id: SectionId,
        p_pointer: u32,
    ) -> Result<()> {
        // Map symbol to R-pointer
        let r_pointer = self.map_symbol_to_esdid(reloc.symbol)?;

        // Extract size from flags
        let size = match &reloc.flags {
            RelocationFlags::Generic { size, .. } => *size,
            _ => 32, // Default to 32-bit
        };

        // Build relocation flags
        let flags = self.build_relocation_flags(&reloc.flags, size)?;

        // Add to pending relocations
        self.relocations.push(PendingRelocation {
            flags,
            r_pointer,
            p_pointer,
            offset: reloc.offset as u32,
        });

        Ok(())
    }

    /// Write a single relocation item to a buffer.
    fn write_relocation_item(
        &self,
        buffer: &mut Vec<u8>,
        flags: &[u8; 6],
        reloc: &PendingRelocation,
    ) -> Result<()> {
        // Write flags (6 bytes)
        buffer.extend_from_slice(flags);

        // Write reserved (2 bytes)
        buffer.extend_from_slice(&[0u8; 2]);

        // Write R-pointer if not compressed
        if (flags[0] & 0x80) == 0 {
            buffer.extend_from_slice(&reloc.r_pointer.to_be_bytes());
        }

        // Write P-pointer if not compressed
        if (flags[0] & 0x40) == 0 {
            buffer.extend_from_slice(&reloc.p_pointer.to_be_bytes());
        }

        // Write offset if not compressed
        if (flags[0] & 0x20) == 0 {
            buffer.extend_from_slice(&reloc.offset.to_be_bytes());
        }

        Ok(())
    }

    /// Write RLD records from a data buffer.
    fn write_rld_records(&mut self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let first_chunk = data.len().min(goff::SIZEOF_RELOCATION_DATA);
        let remainder = &data[first_chunk..];

        let mut ptv = goff::GOFF_RLD_BYTES;
        if !remainder.is_empty() {
            ptv[1] |= 0x01; // Set "is_continued" flag — overflow goes into ContinuationRecord64s
        }

        let mut record = goff::RelocationRecord64 {
            ptv,
            reserved: 0,
            // Length covers the total data across this record and all its continuations.
            length: U16::new(BE, data.len() as u16),
            data: [0u8; goff::SIZEOF_RELOCATION_DATA],
        };
        record.data[..first_chunk].copy_from_slice(&data[..first_chunk]);

        self.logical_record_count += 1;
        self.buffer.write_pod(&record);

        if !remainder.is_empty() {
            self.write_continuation_records(goff::GOFF_RLD_BYTES, data, remainder.len());
        }

        Ok(())
    }

    /// Write all pending relocations as RLD records.
    pub fn write_relocations(&mut self) -> Result<()> {
        if self.relocations.is_empty() {
            return Ok(());
        }

        // Sort relocations by P-pointer, then offset for better compression
        self.relocations.sort_by_key(|r| (r.p_pointer, r.offset));

        let mut rld_data = Vec::new();
        let mut prev_r_pointer: Option<u32> = None;
        let mut prev_p_pointer: Option<u32> = None;
        let mut prev_offset: Option<u32> = None;

        for reloc in &self.relocations {
            // Apply compression flags
            let mut flags = reloc.flags;

            // Only compress if we have previous values (not the first relocation)
            if let Some(prev) = prev_r_pointer {
                if reloc.r_pointer == prev {
                    flags[0] |= 0x80; // Same R-ID
                }
            }

            if let Some(prev) = prev_p_pointer {
                if reloc.p_pointer == prev {
                    flags[0] |= 0x40; // Same P-ID
                }
            }

            if let Some(prev) = prev_offset {
                if reloc.offset == prev {
                    flags[0] |= 0x20; // Same Offset
                }
            }

            // Write relocation item
            self.write_relocation_item(&mut rld_data, &flags, reloc)?;

            // Update previous values for next iteration
            prev_r_pointer = Some(reloc.r_pointer);
            prev_p_pointer = Some(reloc.p_pointer);
            prev_offset = Some(reloc.offset);
        }

        // Write RLD records (max 74 bytes per record)
        self.write_rld_records(&rld_data)?;

        Ok(())
    }
}

/// Get default attributes suitable for 64-bit z/Architecture.
fn default_attrs() -> goff::BehavioralAttributes {
    goff::BehavioralAttributes::default()
        .with_amode(goff::AMODE_64)
        .with_rmode(goff::RMODE_64)
        .with_text_record_style(goff::TXT_RS_BYTE)
        .with_binding_algorithm(goff::ESD_BA_CONCATENATE)
        .with_tasking_behavior(goff::TASK_UNSPEC)
        .with_read_only(false)
        .with_executable(goff::EXEC_UNSPEC)
        .with_binding_strength(goff::ESD_BST_STRONG)
        .with_loading_behavior(goff::LOAD_INITIAL)
        .with_common(false)
        .with_indirect(false)
        .with_binding_scope(goff::ESD_BSC_UNSPEC)
        .with_xplink(false)
        .with_alignment(goff::ALIGN_BYTE)
}

/// Create attributes suitable for code sections.
fn code_attrs() -> goff::BehavioralAttributes {
    default_attrs()
        .with_read_only(true)
        .with_executable(goff::EXEC_CODE)
        .with_alignment(goff::ALIGN_DOUBLEWORD)
}

/// Create attributes suitable for data sections.
fn data_attrs() -> goff::BehavioralAttributes {
    default_attrs()
        .with_executable(goff::EXEC_DATA)
        .with_alignment(goff::ALIGN_DOUBLEWORD)
}

/// Create attributes suitable for read-only data sections.
fn readonly_data_attrs() -> goff::BehavioralAttributes {
    default_attrs()
        .with_read_only(true)
        .with_executable(goff::EXEC_DATA)
        .with_alignment(goff::ALIGN_DOUBLEWORD)
}
