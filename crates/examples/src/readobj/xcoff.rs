use super::*;
use object::read::xcoff::*;
use object::read::SectionIndex;
use object::xcoff::*;

pub(super) fn print_xcoff32(p: &mut Printer<'_>, data: &[u8]) {
    let mut offset = 0;
    if let Some(header) = FileHeader32::parse(data, &mut offset).print_err(p) {
        writeln!(p.w(), "Format: XCOFF 32-bit").unwrap();
        print_xcoff(p, header, data, offset);
    }
}

pub(super) fn print_xcoff64(p: &mut Printer<'_>, data: &[u8]) {
    let mut offset = 0;
    if let Some(header) = FileHeader64::parse(data, &mut offset).print_err(p) {
        writeln!(p.w(), "Format: XCOFF 64-bit").unwrap();
        print_xcoff(p, header, data, offset);
    }
}

fn print_xcoff<Xcoff: FileHeader>(
    p: &mut Printer<'_>,
    header: &Xcoff,
    data: &[u8],
    mut offset: u64,
) {
    print_file_header(p, header);
    if let Some(aux_header) = header.aux_header(data, &mut offset).print_err(p) {
        let sections = header.sections(data, &mut offset).print_err(p);
        let symbols = header.symbols(data).print_err(p);
        if let Some(aux_header) = aux_header {
            print_aux_header(p, aux_header);
        }
        if let Some(ref sections) = sections {
            print_sections(p, data, symbols.as_ref(), sections);
        }
        if let Some(ref symbols) = symbols {
            print_symbols(p, sections.as_ref(), symbols);
        }
    }
}

fn print_file_header<Xcoff: FileHeader>(p: &mut Printer<'_>, header: &Xcoff) {
    if !p.options.file {
        return;
    }
    p.group("FileHeader", |p| {
        p.field_hex("Magic", header.f_magic());
        p.field("NumberOfSections", header.f_nscns());
        p.field_hex("TimeDate", header.f_timdat());
        p.field_hex("SymbolPointer", header.f_symptr().into());
        p.field("NumberOfSymbols", header.f_nsyms());
        p.field_hex("SizeOfOptionalHeader", header.f_opthdr());
        p.field_hex("Flags", header.f_flags());
        p.flags(header.f_flags(), 0, FLAGS_F);
    });
}

fn print_aux_header<Header: AuxHeader>(p: &mut Printer<'_>, aux_header: &Header) {
    if !p.options.file {
        return;
    }
    p.group("AuxHeader", |p| {
        p.field_hex("Magic", aux_header.o_mflag());
        p.field_hex("Version", aux_header.o_vstamp());
        p.field_hex("TextSize", aux_header.o_tsize().into());
        p.field_hex("DataSize", aux_header.o_dsize().into());
        p.field_hex("UninitializedDataSize", aux_header.o_bsize().into());
        p.field_hex("EntryAddress", aux_header.o_entry().into());
        p.field_hex("TextAddress", aux_header.o_text_start().into());
        p.field_hex("DataAddress", aux_header.o_data_start().into());
        p.field_hex("TocAddress", aux_header.o_toc().into());
        p.field("EntrySectionNumber", aux_header.o_snentry());
        p.field("TextSectionNumber", aux_header.o_sntext());
        p.field("DataSectionNumber", aux_header.o_sndata());
        p.field("TocSectionNumber", aux_header.o_sntoc());
        p.field("LoaderSectionNumber", aux_header.o_snloader());
        p.field_hex("TextAlignment", aux_header.o_algntext());
        p.field_hex("DataAlignment", aux_header.o_algndata());
        p.field_hex("ModuleType", aux_header.o_modtype());
        p.field_hex("CpuFlags", aux_header.o_cpuflag());
        p.field_hex("CpuType", aux_header.o_cputype());
        p.field_hex("MaximumStack", aux_header.o_maxstack().into());
        p.field_hex("MaximumData", aux_header.o_maxdata().into());
        p.field_hex("Debugger", aux_header.o_debugger());
        p.field_hex("TextPageSize", aux_header.o_textpsize());
        p.field_hex("DataPageSize", aux_header.o_datapsize());
        p.field_hex("StackPageSize", aux_header.o_stackpsize());
        p.field_hex("Flags", aux_header.o_flags());
        p.field("TlsDataSectionNumber", aux_header.o_sntdata());
        p.field("TlsUninitializedDataSectionNumber", aux_header.o_snbss());
        if let Some(x64flags) = aux_header.o_x64flags() {
            p.field_hex("Flags64", x64flags);
        }
    });
}

fn print_sections<'data, Xcoff: FileHeader>(
    p: &mut Printer<'_>,
    data: &[u8],
    symbols: Option<&SymbolTable<'data, Xcoff>>,
    sections: &SectionTable<'data, Xcoff>,
) {
    if !p.options.sections {
        return;
    }
    for (index, section) in sections.iter().enumerate() {
        p.group("SectionHeader", |p| {
            p.field("Index", index + 1);
            p.field_inline_string("Name", section.name());
            p.field_hex("PhysicalAddress", section.s_paddr().into());
            p.field_hex("VirtualAddress", section.s_vaddr().into());
            p.field_hex("Size", section.s_size().into());
            p.field_hex("SectionDataPointer", section.s_scnptr().into());
            p.field_hex("RelocationPointer", section.s_relptr().into());
            p.field_hex("LineNumberPointer", section.s_lnnoptr().into());
            p.field("NumberOfRelocations", section.s_nreloc().into());
            p.field("NumberOfLineNumbers", section.s_nlnno().into());
            let flags = section.s_flags();
            p.field_enum("Type", flags as u16, FLAGS_STYP);
            if flags as u16 == STYP_DWARF {
                p.field_enum("SubType", flags & 0xffff_0000, FLAGS_SSUBTYP);
            }
            if let Some(relocations) = section.relocations(data).print_err(p) {
                for relocation in relocations {
                    p.group("Relocation", |p| {
                        p.field_hex("VirtualAddress", relocation.r_vaddr().into());
                        let index = relocation.r_symndx();
                        let name = symbols.and_then(|symbols| {
                            symbols
                                .symbol(index as usize)
                                .and_then(|symbol| symbol.name(symbols.strings()))
                                .print_err(p)
                        });
                        p.field_string_option("Symbol", index, name);
                        p.field_hex("Size", relocation.r_rsize());
                        p.field_enum("Type", relocation.r_rtype(), FLAGS_R);
                    });
                }
            }
        });
    }
}

fn print_symbols<'data, Xcoff: FileHeader>(
    p: &mut Printer<'_>,
    sections: Option<&SectionTable<'data, Xcoff>>,
    symbols: &SymbolTable<'data, Xcoff>,
) {
    if !p.options.symbols {
        return;
    }
    for (index, symbol) in symbols.iter() {
        p.group("Symbol", |p| {
            p.field("Index", index.0);
            let name = symbol.name(symbols.strings());
            if let Some(offset) = symbol.name_offset() {
                p.field_string("Name", offset, name);
            } else if let Ok(name) = name {
                p.field_inline_string("Name", name);
            }
            p.field_hex("Value", symbol.n_value().into());
            let section = symbol.n_scnum();
            if section <= 0 {
                p.field_enum_display("Section", section, FLAGS_N);
            } else {
                let section_name = sections.and_then(|sections| {
                    sections
                        .section(SectionIndex(section as usize))
                        .map(|section| section.name())
                        .print_err(p)
                });
                p.field_string_option("Section", section, section_name);
            }
            if symbol.n_sclass() == C_FILE {
                p.field_hex("SourceLanguage", symbol.n_type() >> 8);
                p.field_hex("CpuVersion", symbol.n_type() & 0xff);
            } else {
                let n_type = symbol.n_type();
                p.field_hex("Type", symbol.n_type());
                if n_type & SYM_V_MASK != 0 {
                    p.flags(symbol.n_type(), SYM_V_MASK, FLAGS_SYM_V);
                }
            }
            p.field_enum("StorageClass", symbol.n_sclass(), FLAGS_C);
            let numaux = symbol.n_numaux() as usize;
            p.field("NumberOfAuxSymbols", numaux);
            if symbol.has_aux_file() {
                for i in 1..=numaux {
                    if let Some(aux_file) = symbols.aux_file(index.0, i).print_err(p) {
                        p.group("FileAux", |p| {
                            p.field("Index", index.0 + i);
                            let name = aux_file.fname(symbols.strings());
                            if let Some(offset) = aux_file.name_offset() {
                                p.field_string("Name", offset, name);
                            } else if let Ok(name) = name {
                                p.field_inline_string("Name", name);
                            }
                            p.field_enum("Type", aux_file.x_ftype(), FLAGS_XFT);
                            if let Some(auxtype) = aux_file.x_auxtype() {
                                p.field_enum("AuxiliaryType", auxtype, FLAGS_AUX);
                            }
                        });
                    }
                }
            }
            if symbol.has_aux_csect() {
                if let Some(aux_csect) = symbols.aux_csect(index.0, numaux).print_err(p) {
                    p.group("CsectAux", |p| {
                        p.field("Index", index.0 + numaux);
                        p.field_hex("SectionLength", aux_csect.x_scnlen());
                        p.field_hex("ParameterHashOffset", aux_csect.x_parmhash());
                        p.field("ParameterHashSectionNumber", aux_csect.x_snhash());
                        p.field_hex("Alignment", aux_csect.alignment());
                        p.field_enum("Type", aux_csect.sym_type(), FLAGS_XTY);
                        p.field_enum("StorageMappingClass", aux_csect.x_smclas(), FLAGS_XMC);
                        if let Some(stab) = aux_csect.x_stab() {
                            p.field_hex("StabOffset", stab);
                        }
                        if let Some(snstab) = aux_csect.x_snstab() {
                            p.field("StabSectionNumber", snstab);
                        }
                        if let Some(auxtype) = aux_csect.x_auxtype() {
                            p.field_enum("AuxiliaryType", auxtype, FLAGS_AUX);
                        }
                    });
                }
            }
        });
    }
}

const FLAGS_F: &[Flag<u16>] = &flags!(
    F_RELFLG,
    F_EXEC,
    F_LNNO,
    F_FDPR_PROF,
    F_FDPR_OPTI,
    F_DSA,
    F_VARPG,
    F_DYNLOAD,
    F_SHROBJ,
    F_LOADONLY,
);
const FLAGS_STYP: &[Flag<u16>] = &flags!(
    STYP_REG,
    STYP_PAD,
    STYP_DWARF,
    STYP_TEXT,
    STYP_DATA,
    STYP_BSS,
    STYP_EXCEPT,
    STYP_INFO,
    STYP_TDATA,
    STYP_TBSS,
    STYP_LOADER,
    STYP_DEBUG,
    STYP_TYPCHK,
    STYP_OVRFLO,
);
const FLAGS_SSUBTYP: &[Flag<u32>] = &flags!(
    SSUBTYP_DWINFO,
    SSUBTYP_DWLINE,
    SSUBTYP_DWPBNMS,
    SSUBTYP_DWPBTYP,
    SSUBTYP_DWARNGE,
    SSUBTYP_DWABREV,
    SSUBTYP_DWSTR,
    SSUBTYP_DWRNGES,
    SSUBTYP_DWLOC,
    SSUBTYP_DWFRAME,
    SSUBTYP_DWMAC,
);
const FLAGS_N: &[Flag<i16>] = &flags!(N_DEBUG, N_ABS, N_UNDEF,);
const FLAGS_SYM_V: &[Flag<u16>] = &flags!(
    SYM_V_INTERNAL,
    SYM_V_HIDDEN,
    SYM_V_PROTECTED,
    SYM_V_EXPORTED,
);
const FLAGS_C: &[Flag<u8>] = &flags!(
    C_FILE, C_BINCL, C_EINCL, C_GSYM, C_STSYM, C_BCOMM, C_ECOMM, C_ENTRY, C_BSTAT, C_ESTAT, C_GTLS,
    C_STTLS, C_DWARF, C_LSYM, C_PSYM, C_RSYM, C_RPSYM, C_ECOML, C_FUN, C_EXT, C_WEAKEXT, C_NULL,
    C_STAT, C_BLOCK, C_FCN, C_HIDEXT, C_INFO, C_DECL, C_AUTO, C_REG, C_EXTDEF, C_LABEL, C_ULABEL,
    C_MOS, C_ARG, C_STRTAG, C_MOU, C_UNTAG, C_TPDEF, C_USTATIC, C_ENTAG, C_MOE, C_REGPARM, C_FIELD,
    C_EOS, C_ALIAS, C_HIDDEN, C_EFCN, C_TCSYM,
);
const FLAGS_XFT: &[Flag<u8>] = &flags!(XFT_FN, XFT_CT, XFT_CV, XFT_CD,);
const FLAGS_XTY: &[Flag<u8>] = &flags!(XTY_ER, XTY_SD, XTY_LD, XTY_CM,);
const FLAGS_XMC: &[Flag<u8>] = &flags!(
    XMC_PR, XMC_RO, XMC_DB, XMC_GL, XMC_XO, XMC_SV, XMC_SV64, XMC_SV3264, XMC_TI, XMC_TB, XMC_RW,
    XMC_TC0, XMC_TC, XMC_TD, XMC_DS, XMC_UA, XMC_BS, XMC_UC, XMC_TL, XMC_UL, XMC_TE,
);
const FLAGS_AUX: &[Flag<u8>] =
    &flags!(AUX_EXCEPT, AUX_FCN, AUX_SYM, AUX_FILE, AUX_CSECT, AUX_SECT,);
const FLAGS_R: &[Flag<u8>] = &flags!(
    R_POS, R_RL, R_RLA, R_NEG, R_REL, R_TOC, R_TRL, R_TRLA, R_GL, R_TCL, R_REF, R_BA, R_BR, R_RBA,
    R_RBR, R_TLS, R_TLS_IE, R_TLS_LD, R_TLS_LE, R_TLSM, R_TLSML, R_TOCU, R_TOCL,
);
