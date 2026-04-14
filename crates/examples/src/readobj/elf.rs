use super::*;
use object::elf::*;
use object::read::elf::*;
use object::read::{SectionIndex, StringTable, SymbolIndex};

pub(super) fn print_elf32(p: &mut Printer<'_>, data: &[u8]) {
    if let Some(elf) = FileHeader32::<Endianness>::parse(data).print_err(p) {
        writeln!(p.w(), "Format: ELF 32-bit").unwrap();
        print_elf(p, elf, data);
    }
}

pub(super) fn print_elf64(p: &mut Printer<'_>, data: &[u8]) {
    if let Some(elf) = FileHeader64::<Endianness>::parse(data).print_err(p) {
        writeln!(p.w(), "Format: ELF 64-bit").unwrap();
        print_elf(p, elf, data);
    }
}

fn print_elf<Elf: FileHeader<Endian = Endianness>>(p: &mut Printer<'_>, elf: &Elf, data: &[u8]) {
    if let Some(endian) = elf.endian().print_err(p) {
        print_file_header(p, endian, elf);
        if let Some(segments) = elf.program_headers(endian, data).print_err(p) {
            print_program_headers(p, endian, data, elf, segments);
        }
        if let Some(sections) = elf.sections(endian, data).print_err(p) {
            print_section_headers(p, endian, data, elf, &sections);
        }
    }
}

fn print_file_header<Elf: FileHeader>(p: &mut Printer<'_>, endian: Elf::Endian, elf: &Elf) {
    if !p.options.file {
        return;
    }
    p.group("FileHeader", |p| {
        p.group("Ident", |p| print_ident(p, elf.e_ident()));
        p.field_consts("Type", elf.e_type(endian), FileType::NAMES);
        p.field_consts("Machine", elf.e_machine(endian), Machine::NAMES);
        let version = elf.e_version(endian);
        if version < 256 {
            p.field_consts("Version", FileVersion(version as u8), FileVersion::NAMES);
        } else {
            p.field_hex("Version", version);
        }
        p.field_hex("Entry", elf.e_entry(endian).into());
        p.field_hex("ProgramHeaderOffset", elf.e_phoff(endian).into());
        p.field_hex("SectionHeaderOffset", elf.e_shoff(endian).into());
        p.field_flags("Flags", elf.e_flags(endian), constants(endian, elf).ef);
        p.field_hex("HeaderSize", elf.e_ehsize(endian));
        p.field_hex("ProgramHeaderEntrySize", elf.e_phentsize(endian));
        p.field("ProgramHeaderCount", elf.e_phnum(endian));
        p.field_hex("SectionHeaderEntrySize", elf.e_shentsize(endian));
        p.field("SectionHeaderCount", elf.e_shnum(endian));
        p.field("SectionHeaderStringTableIndex", elf.e_shstrndx(endian));
    });
}

fn print_ident(p: &mut Printer<'_>, ident: &Ident) {
    p.field("Magic", format!("{:X?}", ident.magic));
    p.field_consts("Class", ident.class, FileClass::NAMES);
    p.field_consts("Data", ident.data, DataEncoding::NAMES);
    p.field_consts("Version", ident.version, FileVersion::NAMES);
    p.field_consts("OsAbi", ident.os_abi, OsAbi::NAMES);
    p.field_hex("AbiVersion", ident.abi_version);
    p.field("Unused", format!("{:X?}", ident.padding));
}

fn print_program_headers<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    data: &[u8],
    elf: &Elf,
    segments: &[Elf::ProgramHeader],
) {
    let constants = constants(endian, elf);
    for segment in segments {
        let p_type = segment.p_type(endian);
        if !p.options.segments
            && !(p.options.elf_notes && p_type == PT_NOTE)
            && !(p.options.elf_dynamic && p_type == PT_DYNAMIC)
        {
            continue;
        }
        p.group("ProgramHeader", |p| {
            p.field_consts("Type", segment.p_type(endian), constants.pt);
            p.field_hex("Offset", segment.p_offset(endian).into());
            p.field_hex("VirtualAddress", segment.p_vaddr(endian).into());
            p.field_hex("PhysicalAddress", segment.p_paddr(endian).into());
            p.field_hex("FileSize", segment.p_filesz(endian).into());
            p.field_hex("MemorySize", segment.p_memsz(endian).into());
            p.field_flags("Flags", segment.p_flags(endian), constants.pf);
            p.field_hex("Align", segment.p_align(endian).into());

            match segment.p_type(endian) {
                PT_NOTE => print_segment_notes(p, endian, data, elf, segment),
                PT_DYNAMIC => print_segment_dynamic(p, endian, data, elf, segments, segment),
                PT_INTERP => {
                    if let Some(Some(data)) = segment.interpreter(endian, data).print_err(p) {
                        p.field_inline_string("Interpreter", data);
                    }
                }
                // TODO:
                //PT_SHLIB =>
                //PT_PHDR =>
                //PT_TLS =>
                //PT_GNU_EH_FRAME =>
                //PT_GNU_STACK =>
                //PT_GNU_RELRO =>
                //PT_GNU_PROPERTY =>
                _ => {}
            }
        });
    }
}

fn print_segment_notes<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    data: &[u8],
    elf: &Elf,
    segment: &Elf::ProgramHeader,
) {
    if !p.options.elf_notes {
        return;
    }
    if let Some(Some(notes)) = segment.notes(endian, data).print_err(p) {
        print_notes(p, endian, elf, notes);
    }
}

fn print_segment_dynamic<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    data: &[u8],
    elf: &Elf,
    segments: &[Elf::ProgramHeader],
    segment: &Elf::ProgramHeader,
) {
    if !p.options.elf_dynamic {
        return;
    }
    if let Some(Some(dynamic)) = segment.dynamic(endian, data).print_err(p) {
        // TODO: add a helper API for this and the other mandatory tags?
        let mut strtab = 0;
        let mut strsz = 0;
        for d in dynamic {
            let tag = d.d_tag(endian).into();
            if tag == DT_STRTAB {
                strtab = d.d_val(endian).into();
            } else if tag == DT_STRSZ {
                strsz = d.d_val(endian).into();
            }
        }
        let mut dynstr = StringTable::default();
        // TODO: print error if DT_STRTAB/DT_STRSZ are invalid
        for s in segments {
            if let Ok(Some(data)) = s.data_range(endian, data, strtab, strsz) {
                dynstr = StringTable::new(data, 0, data.len() as u64);
                break;
            }
        }

        print_dynamic(p, endian, elf, dynamic, dynstr);
    }
}

fn print_section_headers<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    data: &[u8],
    elf: &Elf,
    sections: &SectionTable<Elf>,
) {
    let constants = constants(endian, elf);
    for (index, section) in sections.enumerate() {
        let sh_type = section.sh_type(endian);
        if !p.options.sections
            && !(p.options.symbols && sh_type == SHT_SYMTAB)
            && !(p.options.relocations && sh_type == SHT_REL)
            && !(p.options.relocations && sh_type == SHT_RELA)
            && !(p.options.relocations && sh_type == SHT_CREL)
            && !(p.options.elf_dynamic && sh_type == SHT_DYNAMIC)
            && !(p.options.elf_dynamic_symbols && sh_type == SHT_DYNSYM)
            && !(p.options.elf_notes && sh_type == SHT_NOTE)
            && !(p.options.elf_versions && sh_type == SHT_GNU_VERDEF)
            && !(p.options.elf_versions && sh_type == SHT_GNU_VERNEED)
            && !(p.options.elf_versions && sh_type == SHT_GNU_VERSYM)
            && !(p.options.elf_attributes && sh_type == SHT_GNU_ATTRIBUTES)
        {
            continue;
        }
        p.group("SectionHeader", |p| {
            p.field("Index", index.0);
            p.field_string(
                "Name",
                section.sh_name(endian),
                sections.section_name(endian, section),
            );

            p.field_consts("Type", section.sh_type(endian), constants.sht);
            p.field_flags("Flags", section.sh_flags(endian), constants.shf);
            p.field_hex("Address", section.sh_addr(endian).into());
            p.field_hex("Offset", section.sh_offset(endian).into());
            p.field_hex("Size", section.sh_size(endian).into());
            p.field("Link", section.sh_link(endian));
            p.field("Info", section.sh_info(endian));
            p.field_hex("AddressAlign", section.sh_addralign(endian).into());
            p.field_hex("EntrySize", section.sh_entsize(endian).into());

            if let Some(Some((compression, _, _))) = section.compression(endian, data).print_err(p)
            {
                p.group("CompressionHeader", |p| {
                    p.field_enum("Type", compression.ch_type(endian), FLAGS_ELFCOMPRESS);
                    p.field_hex("Size", compression.ch_size(endian).into());
                    p.field_hex("AddressAlign", compression.ch_addralign(endian).into());
                });
            }

            match section.sh_type(endian) {
                SHT_SYMTAB => {
                    if p.options.symbols {
                        print_section_symbols(p, endian, data, elf, sections, index, section);
                    }
                }
                SHT_DYNSYM => {
                    if p.options.elf_dynamic_symbols {
                        print_section_symbols(p, endian, data, elf, sections, index, section);
                    }
                }
                SHT_REL => print_section_rel(p, endian, data, elf, sections, section),
                SHT_RELA => print_section_rela(p, endian, data, elf, sections, section),
                SHT_RELR => print_section_relr(p, endian, data, elf, section),
                SHT_CREL => print_section_crel(p, endian, data, elf, sections, section),
                SHT_NOTE => print_section_notes(p, endian, data, elf, section),
                SHT_DYNAMIC => print_section_dynamic(p, endian, data, elf, sections, section),
                SHT_GROUP => print_section_group(p, endian, data, elf, sections, section),
                SHT_HASH => print_hash(p, endian, data, elf, sections, section),
                SHT_GNU_HASH => print_gnu_hash(p, endian, data, elf, sections, section),
                SHT_GNU_VERDEF => print_gnu_verdef(p, endian, data, elf, sections, section),
                SHT_GNU_VERNEED => print_gnu_verneed(p, endian, data, elf, sections, section),
                SHT_GNU_VERSYM => print_gnu_versym(p, endian, data, elf, sections, section),
                // TODO: other sections that contain attributes
                SHT_GNU_ATTRIBUTES => print_attributes(p, endian, data, elf, section),
                // TODO:
                //SHT_SHLIB =>
                //SHT_INIT_ARRAY =>
                //SHT_FINI_ARRAY =>
                //SHT_PREINIT_ARRAY =>
                _ => {}
            }
            match elf.e_machine(endian) {
                EM_ARM => {
                    if section.sh_type(endian) == SHT_ARM_ATTRIBUTES {
                        print_attributes(p, endian, data, elf, section);
                    }
                }
                EM_AARCH64 => {
                    if section.sh_type(endian) == SHT_AARCH64_ATTRIBUTES {
                        print_attributes(p, endian, data, elf, section);
                    }
                }
                _ => {}
            }
        });
    }
}

fn print_section_symbols<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    data: &[u8],
    elf: &Elf,
    sections: &SectionTable<Elf>,
    section_index: SectionIndex,
    section: &Elf::SectionHeader,
) {
    let constants = constants(endian, elf);
    if let Some(Some(symbols)) = section
        .symbols(endian, data, sections, section_index)
        .print_err(p)
    {
        let versions = if section.sh_type(endian) == SHT_DYNSYM {
            sections.versions(endian, data).print_err(p).flatten()
        } else {
            None
        };
        for (index, symbol) in symbols.enumerate() {
            p.group("Symbol", |p| {
                p.field("Index", index.0);
                if index == SymbolIndex(0) {
                    p.field_hex("Name", symbol.st_name(endian));
                } else {
                    p.field_string(
                        "Name",
                        symbol.st_name(endian),
                        symbol.name(endian, symbols.strings()),
                    );
                }
                if let Some(versions) = versions.as_ref() {
                    let version_index = versions.version_index(endian, index);
                    print_version(p, Some(versions), version_index);
                }
                p.field_hex("Value", symbol.st_value(endian).into());
                p.field_hex("Size", symbol.st_size(endian).into());
                p.field_consts("Type", symbol.st_type(), constants.stt);
                p.field_consts("Bind", symbol.st_bind(), constants.stb);
                p.field_flags("Other", symbol.st_other(), constants.sto);

                let shndx = symbol.st_shndx(endian);
                if shndx == SHN_UNDEF || shndx >= SHN_LORESERVE {
                    p.field_consts("SectionIndex", shndx, constants.shn);
                } else {
                    p.field("SectionIndex", shndx);
                }
                if let Some(shndx) = symbols.shndx(endian, index) {
                    p.field("ExtendedSectionIndex", shndx);
                }
            });
        }
    }
}

fn print_section_rel<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    data: &[u8],
    elf: &Elf,
    sections: &SectionTable<Elf>,
    section: &Elf::SectionHeader,
) {
    if !p.options.relocations {
        return;
    }
    if let Some(Some((relocations, link))) = section.rel(endian, data).print_err(p) {
        let symbols = if link.0 != 0 {
            sections
                .symbol_table_by_index(endian, data, link)
                .print_err(p)
        } else {
            None
        };
        let consts = constants(endian, elf).r;
        for relocation in relocations {
            p.group("Relocation", |p| {
                p.field_hex("Offset", relocation.r_offset(endian).into());
                p.field_consts("Type", relocation.r_type(endian), consts);
                let sym = relocation.symbol(endian);
                print_rel_symbol(p, endian, symbols, sym);
            });
        }
    }
}

fn print_section_rela<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    data: &[u8],
    elf: &Elf,
    sections: &SectionTable<Elf>,
    section: &Elf::SectionHeader,
) {
    if !p.options.relocations {
        return;
    }
    if let Some(Some((relocations, link))) = section.rela(endian, data).print_err(p) {
        let symbols = if link.0 != 0 {
            sections
                .symbol_table_by_index(endian, data, link)
                .print_err(p)
        } else {
            None
        };
        let consts = constants(endian, elf).r;
        for relocation in relocations {
            p.group("Relocation", |p| {
                p.field_hex("Offset", relocation.r_offset(endian).into());
                p.field_consts(
                    "Type",
                    relocation.r_type(endian, elf.is_mips64el(endian)),
                    consts,
                );
                let sym = relocation.symbol(endian, elf.is_mips64el(endian));
                print_rel_symbol(p, endian, symbols, sym);
                let addend = relocation.r_addend(endian).into();
                if addend != 0 {
                    p.field_hex("Addend", addend);
                }
            });
        }
    }
}

fn print_rel_symbol<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    symbols: Option<SymbolTable<'_, Elf>>,
    index: Option<SymbolIndex>,
) {
    let Some(index) = index else {
        p.field_hex("Symbol", 0);
        return;
    };
    let name = symbols.and_then(|symbols| {
        symbols
            .symbol(index)
            .and_then(|symbol| symbol.name(endian, symbols.strings()))
            .print_err(p)
    });
    p.field_string_option("Symbol", index.0, name);
}

fn print_section_relr<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    data: &[u8],
    _elf: &Elf,
    section: &Elf::SectionHeader,
) {
    if !p.options.relocations {
        return;
    }
    if let Some(Some(relocations)) = section.relr(endian, data).print_err(p) {
        for relocation in relocations {
            p.field_hex("Offset", relocation.into());
        }
    }
}

fn print_section_crel<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    data: &[u8],
    elf: &Elf,
    sections: &SectionTable<Elf>,
    section: &Elf::SectionHeader,
) {
    if !p.options.relocations {
        return;
    }

    if let Some(Some((relocations, link))) = section.crel(endian, data).print_err(p) {
        let symbols = if link.0 != 0 {
            sections
                .symbol_table_by_index(endian, data, link)
                .print_err(p)
        } else {
            None
        };
        let consts = constants(endian, elf).r;
        for relocation_result in relocations {
            let Some(relocation) = relocation_result.print_err(p) else {
                return;
            };

            p.group("Relocation", |p| {
                p.field_hex("Offset", relocation.r_offset);
                p.field_consts("Type", relocation.r_type, consts);
                print_rel_symbol(p, endian, symbols, relocation.symbol());
                let addend = relocation.r_addend;
                if addend != 0 {
                    p.field_hex("Addend", addend);
                }
            });
        }
    }
}

fn print_section_notes<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    data: &[u8],
    elf: &Elf,
    section: &Elf::SectionHeader,
) {
    if !p.options.elf_notes {
        return;
    }
    if let Some(Some(notes)) = section.notes(endian, data).print_err(p) {
        print_notes(p, endian, elf, notes);
    }
}

fn print_section_dynamic<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    data: &[u8],
    elf: &Elf,
    sections: &SectionTable<Elf>,
    section: &Elf::SectionHeader,
) {
    if !p.options.elf_dynamic {
        return;
    }
    if let Some(Some((dynamic, index))) = section.dynamic(endian, data).print_err(p) {
        let strings = sections.strings(endian, data, index).unwrap_or_default();
        print_dynamic(p, endian, elf, dynamic, strings);
    }
}

fn print_section_group<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    data: &[u8],
    _elf: &Elf,
    sections: &SectionTable<Elf>,
    section: &Elf::SectionHeader,
) {
    if let Some(Some((flag, members))) = section.group(endian, data).print_err(p) {
        p.field_enum("GroupFlag", flag, FLAGS_GRP);
        p.group("GroupSections", |p| {
            for member in members {
                let index = member.get(endian);
                p.print_indent();
                if let Some(section) = sections.section(SectionIndex(index as usize)).print_err(p) {
                    if let Some(name) = sections.section_name(endian, section).print_err(p) {
                        p.print_string(name);
                        writeln!(p.w, " ({})", index).unwrap();
                    } else {
                        writeln!(p.w, "{}", index).unwrap();
                    }
                } else {
                    writeln!(p.w, "{}", index).unwrap();
                }
            }
        });
    }
}

fn print_notes<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    elf: &Elf,
    mut notes: NoteIterator<Elf>,
) {
    while let Some(Some(note)) = notes.next().print_err(p) {
        p.group("Note", |p| {
            let name = note.name();
            p.field_string_option("Name", note.n_namesz(endian), Some(name));
            p.field_consts("Type", note.n_type(endian), note_type_names(name));
            if let Some(mut properties) = note.gnu_properties(endian) {
                while let Some(Some(property)) = properties.next().print_err(p) {
                    p.group("Property", |p| {
                        let pr_type = property.pr_type();
                        let proc = match elf.e_machine(endian) {
                            EM_386 | EM_X86_64 => FLAGS_GNU_PROPERTY_X86,
                            EM_AARCH64 => FLAGS_GNU_PROPERTY_AARCH64,
                            _ => &[],
                        };
                        p.field_enums("Type", pr_type, &[FLAGS_GNU_PROPERTY, proc]);
                        match pr_type {
                            GNU_PROPERTY_1_NEEDED => {
                                if let Some(val) = property.data_u32(endian).print_err(p) {
                                    p.field_hex("Value", val);
                                    p.flags(val, 0, FLAGS_GNU_PROPERTY_1_NEEDED);
                                }
                            }
                            _ => {}
                        }
                        match elf.e_machine(endian) {
                            EM_386 | EM_X86_64 => match pr_type {
                                GNU_PROPERTY_X86_ISA_1_USED | GNU_PROPERTY_X86_ISA_1_NEEDED => {
                                    if let Some(val) = property.data_u32(endian).print_err(p) {
                                        p.field_hex("Value", val);
                                        p.flags(val, 0, FLAGS_GNU_PROPERTY_X86_ISA_1);
                                    }
                                }
                                GNU_PROPERTY_X86_FEATURE_1_AND => {
                                    if let Some(val) = property.data_u32(endian).print_err(p) {
                                        p.field_hex("Value", val);
                                        p.flags(val, 0, FLAGS_GNU_PROPERTY_X86_FEATURE_1);
                                    }
                                }
                                _ => {}
                            },
                            EM_AARCH64 => match pr_type {
                                GNU_PROPERTY_AARCH64_FEATURE_1_AND => {
                                    if let Some(val) = property.data_u32(endian).print_err(p) {
                                        p.field_hex("Value", val);
                                        p.flags(val, 0, FLAGS_GNU_PROPERTY_AARCH64_FEATURE_1);
                                    }
                                }
                                _ => {}
                            },
                            _ => {}
                        }
                    });
                }
            } else {
                p.field_bytes("Desc", note.desc());
            }
        });
    }
}

fn print_dynamic<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    elf: &Elf,
    dynamic: &[Elf::Dyn],
    dynstr: StringTable,
) {
    let constants = constants(endian, elf);
    for d in dynamic {
        let tag = d.d_tag(endian).into();
        let val = d.d_val(endian).into();
        p.group("Dynamic", |p| {
            p.field_consts("Tag", tag, constants.dt);
            if d.is_string(endian) {
                p.field_string("Value", val, d.string(endian, dynstr));
            } else {
                p.field_hex("Value", val);
                if tag == DT_FLAGS {
                    p.flags(val, 0, FLAGS_DF);
                } else if tag == DT_FLAGS_1 {
                    p.flags(val, 0, FLAGS_DF_1);
                }
            }
        });
        if tag == DT_NULL {
            break;
        }
    }
}

fn print_hash<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    data: &[u8],
    _elf: &Elf,
    _sections: &SectionTable<Elf>,
    section: &Elf::SectionHeader,
) {
    if let Some(Some(hash)) = section.hash_header(endian, data).print_err(p) {
        p.group("Hash", |p| {
            p.field("BucketCount", hash.bucket_count.get(endian));
            p.field("ChainCount", hash.chain_count.get(endian));
        });
    }
    /* TODO: add this in a test somewhere
    if let Ok(Some((hash_table, link))) = section.hash(endian, data) {
        if let Ok(symbols) = _sections.symbol_table_by_index(endian, data, link) {
            if let Ok(versions) = _sections.versions(endian, data) {
                for (index, symbol) in symbols.symbols().enumerate() {
                    let name = symbols.symbol_name(endian, symbol).unwrap();
                    if name.is_empty() {
                        continue;
                    }
                    let hash = hash(name);
                    let version = versions.version(versions.version_index(endian, index));
                    let (hash_index, hash_symbol) = hash_table
                        .find(endian, name, hash, version, &symbols, &versions)
                        .unwrap();
                    let hash_name = symbols.symbol_name(endian, hash_symbol).unwrap();
                    assert_eq!(name, hash_name);
                    assert_eq!(index, hash_index);
                }
            }
        }
    }
    */
}

fn print_gnu_hash<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    data: &[u8],
    _elf: &Elf,
    _sections: &SectionTable<Elf>,
    section: &Elf::SectionHeader,
) {
    if let Some(Some(hash)) = section.gnu_hash_header(endian, data).print_err(p) {
        p.group("GnuHash", |p| {
            p.field("BucketCount", hash.bucket_count.get(endian));
            p.field("SymbolBase", hash.symbol_base.get(endian));
            p.field("BloomCount", hash.bloom_count.get(endian));
            p.field("BloomShift", hash.bloom_shift.get(endian));
        });
    }
    /* TODO: add this in a test somewhere
    if let Ok(Some((hash_table, link))) = section.gnu_hash(endian, data) {
        if let Ok(symbols) = _sections.symbol_table_by_index(endian, data, link) {
            if let Ok(versions) = _sections.versions(endian, data) {
                for (index, symbol) in symbols
                    .symbols()
                    .enumerate()
                    .skip(hash_table.symbol_base() as usize)
                {
                    let name = symbols.symbol_name(endian, symbol).unwrap();
                    let hash = gnu_hash(name);
                    let version = versions.version(versions.version_index(endian, index));
                    let (hash_index, hash_symbol) = hash_table
                        .find(endian, name, hash, version, &symbols, &versions)
                        .unwrap();
                    let hash_name = symbols.symbol_name(endian, hash_symbol).unwrap();
                    assert_eq!(name, hash_name);
                    assert_eq!(index, hash_index);
                }
            }
        }
    }
    */
}

fn print_gnu_verdef<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    data: &[u8],
    _elf: &Elf,
    sections: &SectionTable<Elf>,
    section: &Elf::SectionHeader,
) {
    if !p.options.elf_versions {
        return;
    }
    if let Some(Some((mut verdefs, link))) = section.gnu_verdef(endian, data).print_err(p) {
        let strings = sections.strings(endian, data, link).unwrap_or_default();
        while let Some(Some((verdef, mut verdauxs))) = verdefs.next().print_err(p) {
            p.group("VersionDefinition", |p| {
                p.field("Version", verdef.vd_version.get(endian));
                p.field_hex("Flags", verdef.vd_flags.get(endian));
                p.flags(verdef.vd_flags.get(endian), 0, FLAGS_VER_FLG);
                p.field("Index", verdef.vd_ndx.get(endian));
                p.field("AuxCount", verdef.vd_cnt.get(endian));
                p.field_hex("Hash", verdef.vd_hash.get(endian));
                p.field("AuxOffset", verdef.vd_aux.get(endian));
                p.field("NextOffset", verdef.vd_next.get(endian));
                while let Some(Some(verdaux)) = verdauxs.next().print_err(p) {
                    p.group("Aux", |p| {
                        p.field_string(
                            "Name",
                            verdaux.vda_name.get(endian),
                            verdaux.name(endian, strings),
                        );
                        p.field("NextOffset", verdaux.vda_next.get(endian));
                    });
                }
            });
        }
    }
}

fn print_gnu_verneed<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    data: &[u8],
    _elf: &Elf,
    sections: &SectionTable<Elf>,
    section: &Elf::SectionHeader,
) {
    if !p.options.elf_versions {
        return;
    }
    if let Some(Some((mut verneeds, link))) = section.gnu_verneed(endian, data).print_err(p) {
        let strings = sections.strings(endian, data, link).unwrap_or_default();
        while let Some(Some((verneed, mut vernauxs))) = verneeds.next().print_err(p) {
            p.group("VersionNeed", |p| {
                p.field("Version", verneed.vn_version.get(endian));
                p.field("AuxCount", verneed.vn_cnt.get(endian));
                p.field_string(
                    "Filename",
                    verneed.vn_file.get(endian),
                    verneed.file(endian, strings),
                );
                p.field("AuxOffset", verneed.vn_aux.get(endian));
                p.field("NextOffset", verneed.vn_next.get(endian));
                while let Some(Some(vernaux)) = vernauxs.next().print_err(p) {
                    p.group("Aux", |p| {
                        p.field_hex("Hash", vernaux.vna_hash.get(endian));
                        p.field_hex("Flags", vernaux.vna_flags.get(endian));
                        p.flags(vernaux.vna_flags.get(endian), 0, FLAGS_VER_FLG);
                        p.field("Index", vernaux.vna_other.get(endian));
                        p.field_string(
                            "Name",
                            vernaux.vna_name.get(endian),
                            vernaux.name(endian, strings),
                        );
                        p.field("NextOffset", vernaux.vna_next.get(endian));
                    });
                }
            });
        }
    }
}

fn print_gnu_versym<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    data: &[u8],
    _elf: &Elf,
    sections: &SectionTable<Elf>,
    section: &Elf::SectionHeader,
) {
    if !p.options.elf_versions {
        return;
    }
    if let Some(Some((syms, _link))) = section.gnu_versym(endian, data).print_err(p) {
        let versions = sections.versions(endian, data).print_err(p).flatten();
        for (index, sym) in syms.iter().enumerate() {
            let version_index = VersionIndex(sym.0.get(endian));
            p.group("VersionSymbol", |p| {
                p.field("Index", index);
                print_version(p, versions.as_ref(), version_index);
            });
        }
    }
}

fn print_attributes<Elf: FileHeader>(
    p: &mut Printer<'_>,
    endian: Elf::Endian,
    data: &[u8],
    _elf: &Elf,
    section: &Elf::SectionHeader,
) {
    if !p.options.elf_attributes {
        return;
    }
    if let Some(section) = section.attributes(endian, data).print_err(p) {
        p.group("Attributes", |p| {
            p.field("Version", section.version());
            if let Some(mut subsections) = section.subsections().print_err(p) {
                while let Some(Some(subsection)) = subsections.next().print_err(p) {
                    p.group("Subsection", |p| {
                        p.field_inline_string("Vendor", subsection.vendor());
                        let mut subsubsections = subsection.subsubsections();
                        while let Some(Some(subsubsection)) = subsubsections.next().print_err(p) {
                            p.group("Subsubsection", |p| {
                                p.field_enum("Tag", subsubsection.tag(), FLAGS_TAG);
                                let mut indices = subsubsection.indices();
                                while let Some(Some(index)) = indices.next().print_err(p) {
                                    p.field("Index", index);
                                }
                                // TODO: print attributes
                            });
                        }
                    });
                }
            }
        });
    }
}

fn print_version<Elf: FileHeader>(
    p: &mut Printer<'_>,
    versions: Option<&VersionTable<Elf>>,
    version_index: VersionIndex,
) {
    match versions.and_then(|versions| versions.version(version_index).print_err(p)) {
        Some(Some(version)) => {
            p.field_string_option("Version", version_index.0, Some(version.name()))
        }
        _ => p.field_enum("Version", version_index.0, FLAGS_VER_NDX),
    }
    p.flags(version_index.0, 0, FLAGS_VERSYM);
}

fn constants<Elf: FileHeader>(endian: Elf::Endian, elf: &Elf) -> &'static Constants {
    machine_constants(elf.e_machine(endian))
}

const FLAGS_ELFCOMPRESS: &[Flag<u32>] = &flags!(ELFCOMPRESS_ZLIB, ELFCOMPRESS_ZSTD);
const FLAGS_GNU_PROPERTY: &[Flag<u32>] = &flags!(
    GNU_PROPERTY_STACK_SIZE,
    GNU_PROPERTY_NO_COPY_ON_PROTECTED,
    GNU_PROPERTY_1_NEEDED,
);
const FLAGS_GNU_PROPERTY_1_NEEDED: &[Flag<u32>] =
    &flags!(GNU_PROPERTY_1_NEEDED_INDIRECT_EXTERN_ACCESS);
const FLAGS_GNU_PROPERTY_AARCH64: &[Flag<u32>] = &flags!(
    GNU_PROPERTY_AARCH64_FEATURE_1_AND,
    GNU_PROPERTY_AARCH64_FEATURE_PAUTH,
);
const FLAGS_GNU_PROPERTY_AARCH64_FEATURE_1: &[Flag<u32>] = &flags!(
    GNU_PROPERTY_AARCH64_FEATURE_1_BTI,
    GNU_PROPERTY_AARCH64_FEATURE_1_PAC,
);
const FLAGS_GNU_PROPERTY_X86: &[Flag<u32>] = &flags!(
    GNU_PROPERTY_X86_ISA_1_USED,
    GNU_PROPERTY_X86_ISA_1_NEEDED,
    GNU_PROPERTY_X86_FEATURE_1_AND,
);
const FLAGS_GNU_PROPERTY_X86_ISA_1: &[Flag<u32>] = &flags!(
    GNU_PROPERTY_X86_ISA_1_BASELINE,
    GNU_PROPERTY_X86_ISA_1_V2,
    GNU_PROPERTY_X86_ISA_1_V3,
    GNU_PROPERTY_X86_ISA_1_V4,
);
const FLAGS_GNU_PROPERTY_X86_FEATURE_1: &[Flag<u32>] = &flags!(
    GNU_PROPERTY_X86_FEATURE_1_IBT,
    GNU_PROPERTY_X86_FEATURE_1_SHSTK,
);
const FLAGS_GRP: &[Flag<u32>] = &flags!(GRP_COMDAT);
const FLAGS_DF: &[Flag<u32>] = &flags!(
    DF_ORIGIN,
    DF_SYMBOLIC,
    DF_TEXTREL,
    DF_BIND_NOW,
    DF_STATIC_TLS,
);
const FLAGS_DF_1: &[Flag<u32>] = &flags!(
    DF_1_NOW,
    DF_1_GLOBAL,
    DF_1_GROUP,
    DF_1_NODELETE,
    DF_1_LOADFLTR,
    DF_1_INITFIRST,
    DF_1_NOOPEN,
    DF_1_ORIGIN,
    DF_1_DIRECT,
    DF_1_TRANS,
    DF_1_INTERPOSE,
    DF_1_NODEFLIB,
    DF_1_NODUMP,
    DF_1_CONFALT,
    DF_1_ENDFILTEE,
    DF_1_DISPRELDNE,
    DF_1_DISPRELPND,
    DF_1_NODIRECT,
    DF_1_IGNMULDEF,
    DF_1_NOKSYMS,
    DF_1_NOHDR,
    DF_1_EDITED,
    DF_1_NORELOC,
    DF_1_SYMINTPOSE,
    DF_1_GLOBAUDIT,
    DF_1_SINGLETON,
    DF_1_STUB,
    DF_1_PIE,
);
const FLAGS_VER_FLG: &[Flag<u16>] = &flags!(VER_FLG_BASE, VER_FLG_WEAK);
const FLAGS_VER_NDX: &[Flag<u16>] = &flags!(VER_NDX_LOCAL, VER_NDX_GLOBAL);
const FLAGS_VERSYM: &[Flag<u16>] = &flags!(VERSYM_HIDDEN);
const FLAGS_TAG: &[Flag<u8>] = &flags!(Tag_File, Tag_Section, Tag_Symbol);
