use super::*;
use object::BigEndian as BE;
use object::goff::*;
use object::pod;
use object::read::goff::*;

struct GoffState {
    esd_names: Vec<Option<String>>,
}

pub(super) fn print_goff(p: &mut Printer<'_>, data: &[u8]) {
    let Some(header) = HeaderRecord::parse(data).print_err(p) else {
        return;
    };
    writeln!(p.w(), "Format: GOFF").unwrap();
    print_hdr(p, header);

    let Some(mut records) = header.records(data).print_err(p) else {
        return;
    };
    let mut state = GoffState {
        esd_names: vec![None],
    };
    while let Some(Some(r)) = LogicalRecord::parse(&mut records).print_err(p) {
        match r.initial.ptv.record_type() {
            RT_ESD => print_esd(p, r.cast(), &mut state),
            RT_TXT => print_txt(p, r.cast(), &state),
            RT_RLD => print_rld(p, r.cast(), &state),
            RT_LEN => print_len(p, r.cast(), &state),
            RT_END => print_end(p, r.cast(), &state),
            _ => {
                p.group("Record", |p| {
                    p.field_hex("Type", r.initial.ptv.record_type());
                    print_continuations(p, r);
                });
            }
        }
    }
}

fn print_hdr(p: &mut Printer<'_>, r: &HeaderRecord) {
    if !p.options.file {
        return;
    }
    p.group("HdrRecord", |p| {
        p.field_reserved("Reserved1", &r.reserved1);
        p.field("ArchitectureLevel", r.archlvl.get(BE));
        p.field_reserved("Reserved2", &r.reserved2);
    });
}

fn print_esd(p: &mut Printer<'_>, r: LogicalRecord<'_, SymbolRecord>, state: &mut GoffState) {
    let esd = r.initial;
    state.esd_names.push(r.esd_name_utf8().print_err(p));

    if !p.options.symbols {
        return;
    }
    p.group("EsdRecord", |p| {
        p.field_consts("SymbolType", esd.symbol_type, SymbolType::NAMES);
        print_esdid(p, state, "Esdid", esd.esdid.get(BE));
        print_esdid(p, state, "ParentEsdid", esd.parent_esdid.get(BE));
        p.field_reserved("Reserved1", pod::bytes_of(&esd.reserved1));
        p.field_hex("Offset", esd.offset.get(BE));
        p.field_reserved("Reserved2", pod::bytes_of(&esd.reserved2));
        p.field_hex("Length", esd.length.get(BE));
        print_esdid(p, state, "ExtendedAttributeEsdid", esd.ea_esdid.get(BE));
        p.field_hex("ExtendedAttributeDataOffset", esd.ea_data_offset.get(BE));
        p.field_reserved("Reserved3", pod::bytes_of(&esd.reserved3));
        p.field_consts("Namespace", esd.namespace, SymbolNamespace::NAMES);
        p.field_flags("Flags", esd.flags, SymbolFlags::NAMES);
        p.field_hex("FillByteValue", esd.fill_byte_value);
        p.field_reserved("Reserved4", &[esd.reserved4]);
        print_esdid(p, state, "AssociatedDataEsdid", esd.ada_esdid.get(BE));
        p.field("Priority", esd.priority.get(BE));
        p.field_reserved("Reserved5", &esd.reserved5);
        print_ba(p, esd.symbol_type, esd.behavioral_attributes);
        p.field("NameLength", esd.name_length.get(BE));
        print_continuations(p, r);
    });
}

fn print_ba(p: &mut Printer<'_>, st: SymbolType, ba: BehavioralAttributes) {
    let flag_fields = |b: &mut BitFields<_, _>| {
        use BehavioralAttributes as BA;
        if ba.amode() != AMODE_UNSPEC || matches!(st, ESD_ST_LD | ESD_ST_ER) {
            b.field("Amode", BA::amode, BA::with_amode, Amode::NAMES);
        }
        if ba.rmode() != RMODE_UNSPEC || matches!(st, ESD_ST_ED) {
            b.field("Rmode", BA::rmode, BA::with_rmode, Rmode::NAMES);
        }
        if ba.text_record_style() != TXT_RS_BYTE || matches!(st, ESD_ST_ED) {
            b.field(
                "TextRecordStyle",
                BA::text_record_style,
                BA::with_text_record_style,
                TextRecordStyle::NAMES,
            );
        }
        if ba.binding_algorithm() != ESD_BA_CONCATENATE || matches!(st, ESD_ST_ED) {
            b.field(
                "BindingAlgorithm",
                BA::binding_algorithm,
                BA::with_binding_algorithm,
                BindingAlgorithm::NAMES,
            );
        }
        if ba.tasking_behavior() != TASK_UNSPEC || matches!(st, ESD_ST_SD) {
            b.field(
                "TaskingBehavior",
                BA::tasking_behavior,
                BA::with_tasking_behavior,
                TaskingBehavior::NAMES,
            );
        }
        b.flag("READ_ONLY", BA::is_read_only, BA::with_read_only);
        if ba.executable() != EXEC_UNSPEC || matches!(st, ESD_ST_ED | ESD_ST_LD | ESD_ST_ER) {
            b.field(
                "Executable",
                BA::executable,
                BA::with_executable,
                Executable::NAMES,
            );
        }
        if ba.duplicate_severity() != ESD_DSS_NO_WARNING || matches!(st, ESD_ST_PR) {
            b.field(
                "DuplicateSymbolSeverity",
                BA::duplicate_severity,
                BA::with_duplicate_severity,
                DuplicateSymbolSeverity::NAMES,
            );
        }
        if ba.binding_strength() != ESD_BST_STRONG || matches!(st, ESD_ST_LD | ESD_ST_ER) {
            b.field(
                "BindingStrength",
                BA::binding_strength,
                BA::with_binding_strength,
                BindingStrength::NAMES,
            );
        }
        if ba.loading_behavior() != LOAD_INITIAL || matches!(st, ESD_ST_ED) {
            b.field(
                "LoadingBehavior",
                BA::loading_behavior,
                BA::with_loading_behavior,
                LoadingBehavior::NAMES,
            );
        }
        b.flag("COMMON", BA::is_common, BA::with_common);
        b.flag("INDIRECT", BA::is_indirect, BA::with_indirect);
        if ba.binding_scope() != ESD_BSC_UNSPEC
            || matches!(st, ESD_ST_SD | ESD_ST_LD | ESD_ST_PR | ESD_ST_ER)
        {
            b.field(
                "BindingScope",
                BA::binding_scope,
                BA::with_binding_scope,
                BindingScope::NAMES,
            );
        }
        b.flag("XPLINK", BA::is_xplink, BA::with_xplink);
        if ba.alignment() != ALIGN_BYTE || matches!(st, ESD_ST_ED | ESD_ST_PR) {
            b.field(
                "Alignment",
                BA::alignment,
                BA::with_alignment,
                Alignment::NAMES,
            );
        }
    };
    print_bitfields(
        p,
        "BehavioralAttributes",
        ba,
        |x| x.0,
        BehavioralAttributes,
        flag_fields,
    );
}

fn print_txt(p: &mut Printer<'_>, r: LogicalRecord<'_, TextRecord>, state: &GoffState) {
    if !p.options.sections {
        return;
    }
    let txt = r.initial;
    p.group("TxtRecord", |p| {
        p.field_consts("RecordStyle", txt.record_style, TextRecordStyle::NAMES);
        print_esdid(p, state, "ElementEsdid", txt.element_esdid.get(BE));
        p.field_reserved("Reserved1", pod::bytes_of(&txt.reserved1));
        p.field_hex("Offset", txt.offset.get(BE));
        p.field_hex("TrueLength", txt.true_length.get(BE));
        p.field_hex("TextEncoding", txt.text_encoding.get(BE));
        p.field_hex("DataLength", txt.data_length.get(BE));
        print_continuations(p, r);
    });
}

fn print_rld(p: &mut Printer<'_>, r: LogicalRecord<'_, RelocationRecord>, state: &GoffState) {
    if !p.options.relocations {
        return;
    }
    let rld = r.initial;
    p.group("RldRecord", |p| {
        p.field_reserved("Reserved", &[rld.reserved]);
        p.field_hex("Length", rld.length.get(BE));
        print_continuations(p, r);
        if let Some(mut relocations) = r.rld_items().print_err(p) {
            while let Some(Some(relocation)) = relocations.next().print_err(p) {
                p.group("Relocation", |p| {
                    print_relocation(p, relocation, state);
                });
            }
        }
    });
}

fn print_relocation(p: &mut Printer<'_>, r: Relocation, state: &GoffState) {
    let flag_fields = |b: &mut BitFields<_, _>| {
        use RelocationFlags as R;
        b.flag("SAME_R_ID", R::is_same_r_id, R::with_same_r_id);
        b.flag("SAME_P_ID", R::is_same_p_id, R::with_same_p_id);
        b.flag("SAME_OFFSET", R::is_same_offset, R::with_same_offset);
        b.flag("OFFSET64", R::is_offset64, R::with_offset64);
        b.flag(
            "AMODE_SENSITIVE",
            R::is_amode_sensitive,
            R::with_amode_sensitive,
        );
        b.field(
            "ReferenceType",
            R::reference_type,
            R::with_reference_type,
            RelocationReferenceType::NAMES,
        );
        b.field(
            "ReferentType",
            R::referent_type,
            R::with_referent_type,
            RelocationReferentType::NAMES,
        );
        b.field("Action", R::action, R::with_action, RelocationAction::NAMES);
        b.field(
            "FetchStore",
            R::fetch_store,
            R::with_fetch_store,
            RelocationFetchStore::NAMES,
        );
        b.value("ByteLength", R::byte_length, R::with_byte_length);
        b.value("BitLength", R::bit_length, R::with_bit_length);
        b.flag("CONDITIONAL", R::is_conditional, R::with_conditional);
        b.value("BitOffset", R::bit_offset, R::with_bit_offset);
    };
    print_bitfields(p, "Flags", r.flags, |x| x.0, RelocationFlags, flag_fields);
    if !r.flags.is_same_r_id() {
        print_esdid(p, state, "RPointer", r.r_pointer);
    }
    if !r.flags.is_same_p_id() {
        print_esdid(p, state, "PPointer", r.p_pointer);
    }
    if !r.flags.is_same_offset() {
        p.field_hex("Offset", r.offset);
    }
}

fn print_len(p: &mut Printer<'_>, r: LogicalRecord<'_, LengthRecord>, state: &GoffState) {
    if !p.options.symbols {
        return;
    }
    let len = r.initial;
    p.group("LenRecord", |p| {
        p.field_reserved("Reserved", &len.reserved);
        p.field_hex("Length", len.length.get(BE));
        print_continuations(p, r);
        if let Some(items) = r.len_items().print_err(p) {
            for item in items {
                p.group("LengthItem", |p| {
                    print_esdid(p, state, "Esdid", item.esdid.get(BE));
                    p.field_reserved("Reserved", &item.reserved);
                    p.field_hex("Length", item.length.get(BE));
                });
            }
        }
    });
}

fn print_end(p: &mut Printer<'_>, r: LogicalRecord<'_, EndRecord>, state: &GoffState) {
    if !p.options.file {
        return;
    }
    let end = r.initial;
    p.group("EndRecord", |p| {
        p.field_flags("Flags", end.flags, FileFlags::NAMES);
        let entry = end.flags.entry() != ENTRY_NONE;
        if entry || end.amode != AMODE_UNSPEC {
            p.field_consts("EntryAmode", end.amode, Amode::NAMES);
        }
        p.field_reserved("Reserved1", &end.reserved1);
        p.field("RecordCount", end.record_count.get(BE));
        if entry || end.esdid.get(BE) != 0 {
            print_esdid(p, state, "EntryEsdid", end.esdid.get(BE));
        }
        p.field_reserved("Reserved2", &end.reserved2);
        if entry || end.offset.get(BE) != 0 {
            p.field_hex("EntryOffset", end.offset.get(BE));
        }
        let name_length = end.name_length.get(BE);
        if entry || name_length != 0 {
            p.field("EntryNameLength", name_length);
        }
        if entry
            && name_length != 0
            && let Some(name) = r.entry_name_utf8().print_err(p)
        {
            p.field_inline_string("EntryName", name.as_bytes());
        }
        print_continuations(p, r);
    });
}

fn print_continuations<T>(p: &mut Printer<'_>, r: LogicalRecord<'_, T>) {
    if !r.continuations.is_empty() {
        p.field("Continuations", r.continuations.len());
    }
}

fn print_esdid(p: &mut Printer<'_>, state: &GoffState, name: &str, esdid: u32) {
    p.field_name(name);
    write!(p.w, "{}", esdid).unwrap();
    if let Some(Some(esd_name)) = state.esd_names.get(esdid as usize) {
        write!(p.w, " (\"{}\")", esd_name).unwrap();
    }
    writeln!(p.w).unwrap();
}

fn print_bitfields<'a, 'b, T: Copy, const N: usize>(
    p: &'a mut Printer<'b>,
    name: &str,
    value: T,
    to_bytes: fn(T) -> [u8; N],
    from_bytes: fn([u8; N]) -> T,
    fields: impl FnOnce(&mut BitFields<'_, 'b, T, N>),
) {
    p.field_name(name);
    let mut sep = "";
    for (i, b) in to_bytes(value).iter().enumerate() {
        write!(p.w, "{}{}:{:02X}", sep, i, b).unwrap();
        sep = " ";
    }
    writeln!(p.w).unwrap();
    p.indent(|p| {
        let mut bit_fields = BitFields::new(p, value, to_bytes, from_bytes);
        fields(&mut bit_fields);
        bit_fields.finish();
    });
}

/// Helper for printing bit fields using getter and setter methods.
///
/// The setters are used to clear each field so that any remaining bits can be printed.
struct BitFields<'a, 'b, T, const N: usize> {
    p: &'a mut Printer<'b>,
    value: T,
    unused: [u8; N],
    to_bytes: fn(T) -> [u8; N],
    from_bytes: fn([u8; N]) -> T,
}

impl<'a, 'b, T: Copy, const N: usize> BitFields<'a, 'b, T, N> {
    fn new(
        p: &'a mut Printer<'b>,
        value: T,
        to_bytes: fn(T) -> [u8; N],
        from_bytes: fn([u8; N]) -> T,
    ) -> Self {
        BitFields {
            p,
            value,
            unused: to_bytes(value),
            to_bytes,
            from_bytes,
        }
    }

    fn mask(&self, clear: impl FnOnce(T) -> T) -> [u8; N] {
        (self.to_bytes)(clear((self.from_bytes)([0xff; N])))
    }

    fn raw(&mut self, mask: [u8; N]) {
        write!(self.p.w, " (").unwrap();
        let mut sep = "";
        for (i, (v, m)) in self.unused.iter_mut().zip(mask).enumerate() {
            if m != 0xff {
                write!(self.p.w, "{}{}:{:02x}", sep, i, *v & !m).unwrap();
                *v &= m;
                sep = " ";
            }
        }
        writeln!(self.p.w, ")").unwrap();
    }

    /// Always print the field.
    fn field<V>(
        &mut self,
        name: &str,
        get: fn(T) -> V,
        set: fn(T, V) -> T,
        consts: &ConstantNames<V>,
    ) -> &mut Self
    where
        V: Wrap + Copy + Default,
        V::Inner: fmt::Display + PartialEq,
    {
        let val = get(self.value);
        self.p.print_indent();
        if let Some(const_name) = consts.name(val) {
            write!(self.p.w, "{}", const_name).unwrap();
        } else {
            write!(self.p.w, "{}({})", name, val.into_inner()).unwrap();
        }
        self.raw(self.mask(|x| set(x, V::default())));
        self
    }

    /// Print the name if the flag is set.
    fn flag(&mut self, name: &str, get: fn(T) -> bool, set: fn(T, bool) -> T) -> &mut Self {
        if get(self.value) {
            self.p.print_indent();
            write!(self.p.w, "{}", name).unwrap();
            self.raw(self.mask(|x| set(x, false)));
        }
        self
    }

    /// Print the name and value if the value is non-zero.
    fn value(&mut self, name: &str, get: fn(T) -> u8, set: fn(T, u8) -> T) -> &mut Self {
        let val = get(self.value);
        if val != 0 {
            self.p.print_indent();
            write!(self.p.w, "{}({})", name, val).unwrap();
            self.raw(self.mask(|x| set(x, 0)));
        }
        self
    }

    /// Print any remaining bits.
    fn finish(&mut self) {
        if self.unused != [0; N] {
            self.p.print_indent();
            write!(self.p.w, "<other> (").unwrap();
            let mut sep = "";
            for (i, &val) in self.unused.iter().enumerate() {
                if val != 0 {
                    write!(self.p.w, "{}{}:{:02x}", sep, i, val).unwrap();
                    sep = " ";
                }
            }
            writeln!(self.p.w, ")").unwrap();
        }
    }
}
