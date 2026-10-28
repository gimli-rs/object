use alloc::vec::Vec;
use core::mem;

use crate::ebcdic::{EbcdicArray, EbcdicStr, EbcdicString};
use crate::endian::{BigEndian as BE, U16, U32};
use crate::goff;
use crate::write::util::*;
use crate::write::*;

const C_WSA64: [u8; 7] = *b"C_WSA64";
const C_CODE64: [u8; 8] = *b"C_CODE64";
const EBCDIC_RUSTCU: EbcdicArray<6> = EbcdicArray::from_ascii(*b"rustcu");
const EBCDIC_C_WSA64: EbcdicArray<7> = EbcdicArray::from_ascii(C_WSA64);

/// The maximum number of bytes that can be included in a TXT or RLD record and its
/// continuations.
///
/// This is a SIGNED 16 bit int despite what the spec says, so the number of bytes we
/// allow ourselves to attach to a record is limited to 32K-1 bytes.
const MAX_LOGICAL_LENGTH: usize = 32 * 1024 - 1;

impl<'a> Object<'a> {
    /// Write goff file
    pub(crate) fn goff_write(&self, buffer: &mut dyn WritableBuffer) -> Result<()> {
        let mut writer = Writer::new(buffer, self.symbols.len(), self.sections.len());
        writer.write_hdr();

        // Write compilation unit SD
        writer.cu_esdid = writer.write_compilation_unit(&EBCDIC_RUSTCU);

        // Process sections
        for (section_index, section) in self.sections.iter().enumerate() {
            let flags = self.section_flags(section);
            writer.write_section(section, SectionId(section_index), flags)?;
        }

        for (symbol_index, symbol) in self.symbols.iter().enumerate() {
            let flags = self.symbol_flags(symbol);
            writer.write_symbol(symbol, SymbolId(symbol_index), flags)?;
        }

        // Collect relocations for all sections after all symbols are written.
        for (section_index, section) in self.sections.iter().enumerate() {
            let ed_esdid = writer.section_esdid[section_index];
            for reloc in &section.relocations {
                writer.add_relocation(reloc, ed_esdid)?;
            }
        }

        writer.write_relocations();
        writer.write_end();
        Ok(())
    }

    /// Returns GOFF section info
    pub(crate) fn goff_section_info(
        &self,
        section: StandardSection,
    ) -> (&'static [u8], &'static [u8], SectionKind, SectionFlags) {
        match section {
            StandardSection::Text => (&[], &C_CODE64, SectionKind::Text, SectionFlags::None),
            StandardSection::Data => (&[], &C_WSA64, SectionKind::Data, SectionFlags::None),
            StandardSection::ReadOnlyData | StandardSection::ReadOnlyString => (
                &[],
                &C_CODE64,
                SectionKind::ReadOnlyData,
                SectionFlags::None,
            ),
            StandardSection::ReadOnlyDataWithRel => (
                &[],
                &C_WSA64,
                SectionKind::ReadOnlyDataWithRel,
                SectionFlags::None,
            ),
            StandardSection::UninitializedData => (
                &[],
                &C_WSA64,
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

    pub(crate) fn goff_section_flags(&self, section: &Section<'_>) -> SectionFlags {
        let (namespace, behavioral_attributes) = match section.kind {
            SectionKind::Text => (goff::ESD_NS_NORMAL_NAME, code_attrs()),
            SectionKind::Data => (goff::ESD_NS_NORMAL_NAME, data_attrs()),
            SectionKind::ReadOnlyData => (goff::ESD_NS_NORMAL_NAME, readonly_data_attrs()),
            SectionKind::Debug => (goff::ESD_NS_PARTS, debug_attrs()),
            _ => return SectionFlags::None,
        };

        SectionFlags::Goff {
            flags: goff::ESD_SF_FILL_BYTE_PRESENCE,
            fill_byte_value: 0,
            namespace,
            behavioral_attributes,
        }
    }

    pub(crate) fn goff_symbol_flags(&self, symbol: &Symbol) -> SymbolFlags<SectionId, SymbolId> {
        let (symbol_type, namespace, attrs);
        match (symbol.kind, symbol.section) {
            (SymbolKind::Text, SymbolSection::Section(_)) => {
                symbol_type = goff::ESD_ST_LD;
                namespace = goff::ESD_NS_NORMAL_NAME;
                attrs = default_attrs().with_executable(goff::EXEC_CODE);
            }
            (SymbolKind::Data, SymbolSection::Section(_)) => {
                symbol_type = goff::ESD_ST_LD;
                namespace = goff::ESD_NS_NORMAL_NAME;
                attrs = default_attrs().with_executable(goff::EXEC_DATA);
            }
            (SymbolKind::Label, SymbolSection::Section(_)) => {
                symbol_type = goff::ESD_ST_LD;
                namespace = goff::ESD_NS_NORMAL_NAME;
                attrs = default_attrs();
            }
            (SymbolKind::Text, SymbolSection::Undefined) => {
                symbol_type = goff::ESD_ST_ER;
                namespace = goff::ESD_NS_NORMAL_NAME;
                attrs = default_attrs().with_executable(goff::EXEC_CODE);
            }
            (SymbolKind::Data | SymbolKind::Unknown, SymbolSection::Undefined) => {
                symbol_type = goff::ESD_ST_PR;
                namespace = goff::ESD_NS_PARTS;
                attrs = default_attrs()
                    .with_executable(goff::EXEC_DATA)
                    .with_alignment(goff::ALIGN_HALFWORD);
            }
            _ => return SymbolFlags::None,
        };
        let scope = match (symbol.scope, symbol.section) {
            (SymbolScope::Compilation, SymbolSection::Undefined) => return SymbolFlags::None,
            (SymbolScope::Compilation, _) => goff::ESD_BSC_SECTION,
            (SymbolScope::Linkage, _) => goff::ESD_BSC_LIBRARY,
            (SymbolScope::Dynamic, _) => goff::ESD_BSC_IMPORT_EXPORT,
            (SymbolScope::Unknown, SymbolSection::Undefined) => goff::ESD_BSC_LIBRARY,
            (SymbolScope::Unknown, _) => return SymbolFlags::None,
        };
        let strength = if symbol.weak {
            goff::ESD_BST_WEAK
        } else {
            goff::ESD_BST_STRONG
        };
        SymbolFlags::Goff {
            symbol_type,
            flags: goff::SymbolFlags(0),
            namespace,
            behavioral_attributes: attrs
                .with_binding_scope(scope)
                .with_binding_strength(strength),
        }
    }

    pub(crate) fn goff_translate_relocation(
        &mut self,
        reloc: &mut RelocationInternal,
    ) -> Result<()> {
        use RelocationEncoding as E;
        use RelocationKind as K;

        let (kind, encoding, size) = if let RelocationFlags::Generic {
            kind,
            encoding,
            size,
        } = reloc.flags
        {
            (kind, encoding, size)
        } else {
            return Ok(());
        };

        let reference_type = match (kind, encoding) {
            (K::Absolute | K::Got, E::Generic) => goff::RLD_RT_ADDRESS,
            (K::Relative | K::PltRelative | K::GotRelative, E::S390xDbl) => {
                goff::RLD_RT_RELATIVE_IMMEDIATE
            }
            (K::SectionOffset, E::Generic) => goff::RLD_RT_OFFSET,
            _ => {
                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
            }
        };

        let flags = goff::RelocationFlags::default()
            .with_reference_type(reference_type)
            .with_byte_length(size / 8)
            .with_bit_length(size & 7)
            .with_action(goff::RLD_ACT_ADD);
        reloc.flags = RelocationFlags::Goff { flags };
        Ok(())
    }

    pub(crate) fn goff_adjust_addend(&mut self, reloc: &mut RelocationInternal) -> Result<bool> {
        let RelocationFlags::Goff { flags, .. } = reloc.flags else {
            return Err(Error(format!("unexpected relocation {:?}", reloc)));
        };
        match flags.fetch_store() {
            goff::RLD_FS_FETCH => {
                if flags.reference_type() == goff::RLD_RT_RELATIVE_IMMEDIATE {
                    // The field is a halfword count.
                    // TODO: this needs adjusting if the offset is from the start of the instruction
                    if reloc.addend % 2 != 0 {
                        return Err(Error(format!("invalid relocation addend {:?}", reloc)));
                    }
                    reloc.addend /= 2;
                }
                Ok(true)
            }
            goff::RLD_FS_STORE if reloc.addend == 0 => Ok(false),
            _ => Err(Error(format!("invalid relocation fetch/store {:?}", reloc))),
        }
    }

    pub(crate) fn goff_relocation_size(&self, reloc: &RelocationInternal) -> Result<u8> {
        let RelocationFlags::Goff { flags, .. } = reloc.flags else {
            return Err(Error(format!("unexpected relocation {:?}", reloc)));
        };
        u8::try_from(flags.total_bit_width())
            .map_err(|_| Error(format!("unsupported relocation size {:?}", reloc)))
    }
}

/// A helper for writing GOFF files.
struct Writer<'a> {
    buffer: &'a mut dyn WritableBuffer,

    next_esdid: u32,
    // ESD id for compile unit
    cu_esdid: u32,
    // ESD id for C_WSA64
    wsa_esdid: Option<u32>,

    logical_record_count: u32,

    // Map symbol ID to ESDID
    symbol_esdid: Vec<u32>,
    symbol_referent: Vec<goff::RelocationReferentType>,
    // Map section ID to ED ESDID
    section_esdid: Vec<u32>,

    // Relocation tracking
    relocations: Vec<goff::Relocation>,
}

impl<'a> Writer<'a> {
    /// Create a new `Writer`.
    fn new(buffer: &'a mut dyn WritableBuffer, symbol_count: usize, section_count: usize) -> Self {
        Writer {
            buffer,

            next_esdid: 1,
            cu_esdid: 0,
            wsa_esdid: None,
            logical_record_count: 0,
            symbol_esdid: vec![0; symbol_count],
            symbol_referent: vec![goff::RLD_RO_LABEL; symbol_count],
            section_esdid: vec![0; section_count],
            relocations: Vec::new(),
        }
    }

    // Write module header ("HDR") record.
    fn write_hdr(&mut self) {
        let header = goff::HeaderRecord {
            ptv: goff::HDR_PREFIX,
            reserved1: [0u8; 45],
            archlvl: U32::new(BE, 1),
            reserved2: [0u8; 28],
        };
        self.logical_record_count += 1;
        self.buffer.write_pod(&header);
    }

    // Write module end ("END") record.
    fn write_end(&mut self) {
        self.logical_record_count += 1;
        let fileend = goff::EndRecord {
            ptv: goff::END_PREFIX,
            flags: goff::FileFlags(0),
            amode: goff::AMODE_UNSPEC,
            reserved1: [0u8; 3],
            record_count: U32::new(BE, self.logical_record_count), // count includes this END record.
            esdid: U32::new(BE, 0),
            reserved2: [0u8; 4],
            offset: U32::new(BE, 0),
            name_length: U16::new(BE, 0),
            entry_name: [0u8; goff::SIZEOF_ENTRY_POINT_NAME],
        };
        self.buffer.write_pod(&fileend);
    }

    fn write_wsa_symbol(&mut self) -> u32 {
        if let Some(wsa_esdid) = self.wsa_esdid {
            return wsa_esdid;
        }
        // Emit parent C_WSA64 ED symbol (data section).
        let mut ed = self.get_esd_record(goff::ESD_ST_ED, goff::ESD_NS_PARTS, self.cu_esdid);
        ed.flags = goff::ESD_SF_FILL_BYTE_PRESENCE;
        ed.behavioral_attributes = default_attrs()
            .with_binding_algorithm(goff::ESD_BA_MERGE)
            .with_executable(goff::EXEC_DATA)
            .with_alignment(goff::ALIGN_HALFWORD);
        let ed_esdid = self.write_esd_record(&ed, &EBCDIC_C_WSA64);
        self.wsa_esdid = Some(ed_esdid);
        ed_esdid
    }

    fn write_section(
        &mut self,
        section: &Section<'_>,
        section_id: SectionId,
        flags: SectionFlags,
    ) -> Result<()> {
        let SectionFlags::Goff {
            flags,
            fill_byte_value,
            namespace,
            behavioral_attributes,
        } = flags
        else {
            return Err(Error(format!(
                "unimplemented section `{}` kind {:?}",
                section.name().unwrap_or(""),
                section.kind,
            )));
        };

        let alignment = goff::Alignment(section.align.trailing_zeros() as u8);
        if !section.align.is_power_of_two() || alignment > goff::ALIGN_4KB {
            return Err(Error(format!(
                "invalid section `{}` align {}",
                section.name().unwrap_or(""),
                section.align
            )));
        }

        let name = &encode_name(&section.name)?;
        let mut ed = self.get_esd_record(goff::ESD_ST_ED, namespace, self.cu_esdid);
        ed.length = U32::new(BE, section.size as u32);
        ed.flags = flags;
        ed.fill_byte_value = fill_byte_value;
        ed.behavioral_attributes = behavioral_attributes.with_alignment(alignment);
        let ed_esdid = self.write_esd_record(&ed, name);
        self.section_esdid[section_id.0] = ed_esdid;

        if !section.data.is_empty() {
            let record_style = behavioral_attributes.text_record_style();
            self.write_text(ed_esdid, &section.data, record_style);
        }
        Ok(())
    }

    /// Write a compilation unit SD.
    fn write_compilation_unit(&mut self, cu_name: &EbcdicStr) -> u32 {
        let mut sd =
            self.get_esd_record(goff::ESD_ST_SD, goff::ESD_NS_PROGRAM_MANAGEMENT_BINDER, 0);
        sd.behavioral_attributes = default_attrs().with_binding_scope(goff::ESD_BSC_SECTION);
        self.write_esd_record(&sd, cu_name)
    }

    fn get_esd_record(
        &self,
        symbol_type: goff::SymbolType,
        namespace: goff::SymbolNamespace,
        parent_esdid: u32,
    ) -> goff::SymbolRecord {
        goff::SymbolRecord {
            ptv: goff::ESD_PREFIX,
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
            namespace,
            flags: goff::SymbolFlags(0),
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

    fn write_esd_record(&mut self, record: &goff::SymbolRecord, name: &EbcdicStr) -> u32 {
        let mut esd_record = *record;
        let name = name.as_bytes();
        let record_name_len = name.len().min(goff::SIZEOF_ESD_DATA);
        esd_record.ptv = goff::ESD_PREFIX.with_continued(name.len() > record_name_len);
        esd_record.name_length = U16::new(BE, name.len() as u16);
        esd_record.name[..record_name_len].copy_from_slice(&name[..record_name_len]);

        self.next_esdid += 1;

        self.logical_record_count += 1;
        self.buffer.write_pod(&esd_record);
        self.write_continuation_records(goff::RT_ESD, &name[record_name_len..]);

        self.next_esdid - 1
    }

    fn write_continuation_records(&mut self, record_type: goff::RecordType, mut data: &[u8]) {
        while !data.is_empty() {
            let end = data.len().min(goff::SIZEOF_RECORD_DATA);
            let ptv = goff::RecordPrefix::new(record_type)
                .with_continuation()
                .with_continued(data.len() > end);

            let mut cont_record = goff::Record {
                ptv,
                data: [0u8; goff::SIZEOF_RECORD_DATA],
            };
            cont_record.data[..end].copy_from_slice(&data[..end]);
            data = &data[end..];

            self.buffer.write_pod(&cont_record);
        }
    }

    fn write_text(&mut self, esdid: u32, mut data: &[u8], record_style: goff::TextRecordStyle) {
        let mut offset = 0_usize;
        while !data.is_empty() {
            let logical_write_len = data.len().min(MAX_LOGICAL_LENGTH);
            let record_data_len = logical_write_len.min(goff::SIZEOF_TXT_DATA);
            let ptv = goff::TXT_PREFIX.with_continued(logical_write_len > record_data_len);

            let mut record = goff::TextRecord {
                ptv,
                record_style,
                element_esdid: U32::new(BE, esdid),
                reserved1: U32::new(BE, 0),
                offset: U32::new(BE, offset as u32),
                true_length: U32::new(BE, 0),
                text_encoding: U16::new(BE, 0),
                data_length: U16::new(BE, logical_write_len as u16),
                data: [0u8; goff::SIZEOF_TXT_DATA],
            };
            record.data[..record_data_len].copy_from_slice(&data[..record_data_len]);
            self.logical_record_count += 1;
            self.buffer.write_pod(&record);
            self.write_continuation_records(
                goff::RT_TXT,
                &data[record_data_len..logical_write_len],
            );

            offset += logical_write_len;
            data = &data[logical_write_len..];
        }
    }

    fn write_symbol(
        &mut self,
        symbol: &Symbol,
        symbol_id: SymbolId,
        symbol_flags: SymbolFlags<SectionId, SymbolId>,
    ) -> Result<()> {
        match (symbol.kind, symbol.section) {
            (SymbolKind::File, _) => return Ok(()),
            (SymbolKind::Section, SymbolSection::Section(section_id)) => {
                self.symbol_esdid[symbol_id.0] = self.section_esdid[section_id.0];
                self.symbol_referent[symbol_id.0] = goff::RLD_RO_ELEMENT;
                return Ok(());
            }
            _ => {}
        }

        let SymbolFlags::Goff {
            symbol_type,
            flags,
            namespace,
            behavioral_attributes,
        } = symbol_flags
        else {
            return Err(Error(format!(
                "unimplemented symbol `{}` kind {:?} scope {:?}",
                symbol.name().unwrap_or(""),
                symbol.kind,
                symbol.scope,
            )));
        };

        let (parent, offset, referent);
        match (symbol_type, symbol.section) {
            (goff::ESD_ST_LD, SymbolSection::Section(section_id)) => {
                parent = self.section_esdid[section_id.0];
                offset = symbol.value as u32;
                referent = goff::RLD_RO_LABEL;
            }
            (goff::ESD_ST_ER, SymbolSection::Undefined) => {
                parent = self.cu_esdid;
                offset = 0;
                referent = goff::RLD_RO_LABEL;
            }
            (goff::ESD_ST_PR, SymbolSection::Undefined) => {
                parent = self.write_wsa_symbol();
                offset = 0;
                referent = goff::RLD_RO_PART;
            }
            _ => {
                return Err(Error(format!(
                    "unimplemented symbol `{}` type {:?}",
                    symbol.name().unwrap_or(""),
                    symbol_type,
                )));
            }
        }

        let name = &encode_name(&symbol.name)?;

        let mut esd = self.get_esd_record(symbol_type, namespace, parent);
        esd.offset = U32::new(BE, offset);
        esd.flags = flags;
        esd.behavioral_attributes = behavioral_attributes;
        let esdid = self.write_esd_record(&esd, name);

        self.symbol_esdid[symbol_id.0] = esdid;
        self.symbol_referent[symbol_id.0] = referent;
        Ok(())
    }

    /// Add a relocation to the pending list.
    fn add_relocation(&mut self, reloc: &RelocationInternal, p_pointer: u32) -> Result<()> {
        let RelocationFlags::Goff { flags } = reloc.flags else {
            return Err(Error("invalid relocation flags".into()));
        };

        if reloc.subtractor.is_some() && flags.reference_type() == goff::RLD_RT_RELATIVE_IMMEDIATE {
            // Binder only supports RI instructions with one external symbol in their operands.
            return Err(Error(format!(
                "unsupported relocation subtractor {:?}",
                reloc
            )));
        }

        let r_pointer = self.symbol_esdid[reloc.symbol.0];
        if r_pointer == 0 {
            return Err(Error("Unsupported relocation symbol for GOFF".into()));
        }
        let flags = flags.with_referent_type(self.symbol_referent[reloc.symbol.0]);
        self.relocations.push(goff::Relocation {
            flags,
            r_pointer,
            p_pointer,
            offset: reloc.offset,
        });

        if let Some(subtractor) = reloc.subtractor {
            let r_pointer = self.symbol_esdid[subtractor.0];
            if r_pointer == 0 {
                return Err(Error(
                    "Unsupported relocation subtractor symbol for GOFF".into(),
                ));
            }
            let flags = flags
                .with_referent_type(self.symbol_referent[subtractor.0])
                .with_action(goff::RLD_ACT_SUBTRACT)
                .with_fetch_store(goff::RLD_FS_FETCH);
            self.relocations.push(goff::Relocation {
                flags,
                r_pointer,
                p_pointer,
                offset: reloc.offset,
            });
        }

        Ok(())
    }

    /// Write a single relocation item to a buffer.
    fn write_relocation_item(
        &self,
        buffer: &mut Vec<u8>,
        flags: goff::RelocationFlags,
        reloc: &goff::Relocation,
    ) {
        // Write fixed header
        buffer.write_pod(&flags);
        buffer.write_zeros(2);

        // Write R-pointer if not compressed
        if !flags.is_same_r_id() {
            buffer.write_pod(&U32::new(BE, reloc.r_pointer));
        }

        // Write P-pointer if not compressed
        if !flags.is_same_p_id() {
            buffer.write_pod(&U32::new(BE, reloc.p_pointer));
        }

        // Write offset if not compressed
        if !flags.is_same_offset() {
            buffer.write_pod(&U32::new(BE, reloc.offset as u32));
        }
    }

    /// Write one logical RLD record and its continuations from a data buffer.
    ///
    /// The caller must limit `data` to `MAX_LOGICAL_LENGTH` bytes.
    fn write_rld_record(&mut self, data: &[u8]) {
        let record_data_len = data.len().min(goff::SIZEOF_RELOCATION_DATA);
        let ptv = goff::RLD_PREFIX.with_continued(data.len() > record_data_len);

        let mut record = goff::RelocationRecord {
            ptv,
            reserved: 0,
            // Length covers the total data across this record and all its continuations.
            length: U16::new(BE, data.len() as u16),
            data: [0u8; goff::SIZEOF_RELOCATION_DATA],
        };
        record.data[..record_data_len].copy_from_slice(&data[..record_data_len]);

        self.logical_record_count += 1;
        self.buffer.write_pod(&record);
        self.write_continuation_records(goff::RT_RLD, &data[record_data_len..]);
    }

    /// Write all pending relocations as RLD records.
    fn write_relocations(&mut self) {
        let mut relocations = mem::take(&mut self.relocations);
        if relocations.is_empty() {
            return;
        }

        // Sort relocations by P-pointer, then offset for better compression.
        // This must be a stable sort to keep subtractor items after their primary item.
        relocations.sort_by_key(|r| (r.p_pointer, r.offset));

        let mut rld_data = Vec::new();
        let mut prev_r_pointer: Option<u32> = None;
        let mut prev_p_pointer: Option<u32> = None;
        let mut prev_offset: Option<u64> = None;

        for reloc in &relocations {
            // Record current length in case it overflows.
            let len = rld_data.len();

            // Apply compression flags
            let flags = reloc
                .flags
                .with_same_r_id(prev_r_pointer == Some(reloc.r_pointer))
                .with_same_p_id(prev_p_pointer == Some(reloc.p_pointer))
                .with_same_offset(prev_offset == Some(reloc.offset));

            // Write relocation item
            self.write_relocation_item(&mut rld_data, flags, reloc);

            // Start a new logical record if this item doesn't fit in the current one.
            if rld_data.len() > MAX_LOGICAL_LENGTH {
                self.write_rld_record(&rld_data[..len]);
                rld_data.clear();

                let flags = flags
                    .with_same_r_id(false)
                    .with_same_p_id(false)
                    .with_same_offset(false);
                self.write_relocation_item(&mut rld_data, flags, reloc);
            }

            // Update previous values for next iteration
            prev_r_pointer = Some(reloc.r_pointer);
            prev_p_pointer = Some(reloc.p_pointer);
            prev_offset = Some(reloc.offset);
        }

        self.write_rld_record(&rld_data);
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
}

/// Create attributes suitable for data sections.
fn data_attrs() -> goff::BehavioralAttributes {
    default_attrs().with_executable(goff::EXEC_DATA)
}

/// Create attributes suitable for read-only data sections.
fn readonly_data_attrs() -> goff::BehavioralAttributes {
    default_attrs()
        .with_read_only(true)
        .with_executable(goff::EXEC_DATA)
}

/// Create attributes suitable for debug sections.
fn debug_attrs() -> goff::BehavioralAttributes {
    default_attrs()
        .with_binding_algorithm(goff::ESD_BA_CONCATENATE)
        .with_loading_behavior(goff::LOAD_NONE)
}

fn encode_name(name: &[u8]) -> Result<EbcdicString> {
    if name.contains(&0) {
        return Err(Error(format!(
            "GOFF name `{}` contains a null byte",
            String::from_utf8_lossy(name)
        )));
    }
    EbcdicString::from_utf8(name).ok_or_else(|| {
        Error(format!(
            "GOFF name `{}` is not convertible to EBCDIC",
            String::from_utf8_lossy(name)
        ))
    })
}
