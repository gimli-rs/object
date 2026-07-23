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
        p.field_flags("Flags", elf.e_flags(endian), names(endian, elf).ef);
        p.field_hex("HeaderSize", elf.e_ehsize(endian));
        p.field_hex("ProgramHeaderEntrySize", elf.e_phentsize(endian));
        p.field("ProgramHeaderCount", elf.e_phnum(endian));
        p.field_hex("SectionHeaderEntrySize", elf.e_shentsize(endian));
        p.field("SectionHeaderCount", elf.e_shnum(endian));
        let shstrndx = elf.e_shstrndx(endian);
        if let Some(index) = shstrndx.index() {
            p.field("SectionHeaderStringTableIndex", index);
        } else {
            p.field_consts(
                "SectionHeaderStringTableIndex",
                shstrndx,
                SymbolSection::NAMES,
            );
        }
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
    let names = names(endian, elf);
    for segment in segments {
        let p_type = segment.p_type(endian);
        if !p.options.segments
            && !(p.options.elf_notes && p_type == PT_NOTE)
            && !(p.options.elf_dynamic && p_type == PT_DYNAMIC)
        {
            continue;
        }
        p.group("ProgramHeader", |p| {
            p.field_consts("Type", segment.p_type(endian), names.pt);
            p.field_hex("Offset", segment.p_offset(endian).into());
            p.field_hex("VirtualAddress", segment.p_vaddr(endian).into());
            p.field_hex("PhysicalAddress", segment.p_paddr(endian).into());
            p.field_hex("FileSize", segment.p_filesz(endian).into());
            p.field_hex("MemorySize", segment.p_memsz(endian).into());
            p.field_flags("Flags", segment.p_flags(endian), names.pf);
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
            let tag = d.d_tag(endian);
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
    let names = names(endian, elf);
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

            p.field_consts("Type", section.sh_type(endian), names.sht);
            p.field_flags("Flags", section.sh_flags(endian), names.shf);
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
                    p.field_consts("Type", compression.ch_type(endian), CompressionType::NAMES);
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
    let names = names(endian, elf);
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
                p.field_consts("Type", symbol.st_type(), names.stt);
                p.field_consts("Bind", symbol.st_bind(), names.stb);
                p.field_flags("Other", symbol.st_other(), names.sto);

                let shndx = symbol.st_shndx(endian);
                if let Some(index) = shndx.index() {
                    p.field("SectionIndex", index);
                } else {
                    p.field_consts("SectionIndex", shndx, names.shn);
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
        let names = names(endian, elf).r;
        for relocation in relocations {
            p.group("Relocation", |p| {
                p.field_hex("Offset", relocation.r_offset(endian).into());
                p.field_consts("Type", relocation.r_type(endian), names);
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
        let names = names(endian, elf).r;
        for relocation in relocations {
            p.group("Relocation", |p| {
                p.field_hex("Offset", relocation.r_offset(endian).into());
                p.field_consts(
                    "Type",
                    relocation.r_type(endian, elf.is_mips64el(endian)),
                    names,
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
        let names = names(endian, elf).r;
        for relocation_result in relocations {
            let Some(relocation) = relocation_result.print_err(p) else {
                return;
            };

            p.group("Relocation", |p| {
                p.field_hex("Offset", relocation.r_offset);
                p.field_consts("Type", relocation.r_type, names);
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
        p.field_flags("GroupFlag", flag, GroupFlags::NAMES);
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
    let machine = elf.e_machine(endian);
    while let Some(Some(note)) = notes.next().print_err(p) {
        p.group("Note", |p| {
            let name = note.name();
            p.field_string_option("Name", note.n_namesz(endian), Some(name));
            p.field_consts("Type", note.n_type(endian), NoteType::names(name));
            if let Some(mut properties) = note.gnu_properties(endian) {
                while let Some(Some(property)) = properties.next().print_err(p) {
                    p.group("Property", |p| {
                        let pr_type = property.pr_type();
                        p.field_consts("Type", pr_type, GnuPropertyType::type_names(machine));
                        if let Some(names) = pr_type.u32_value_names(machine)
                            && let Some(val) = property.data_u32(endian).print_err(p)
                        {
                            p.field_flags("Value", val, names);
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
    let names = names(endian, elf);
    for d in dynamic {
        let tag = d.d_tag(endian);
        let val = d.d_val(endian).into();
        p.group("Dynamic", |p| {
            p.field_consts("Tag", tag, names.dt);
            if d.is_string(endian) {
                p.field_string("Value", val, d.string(endian, dynstr));
            } else {
                if tag == DT_FLAGS {
                    p.field_flags("Value", DynamicFlags(val), DynamicFlags::NAMES);
                } else if tag == DT_FLAGS_1 {
                    p.field_flags("Value", DynamicFlags1(val), DynamicFlags1::NAMES);
                } else {
                    p.field_hex("Value", val);
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
                p.field_flags("Flags", verdef.vd_flags.get(endian), VersionFlags::NAMES);
                p.field_consts("Index", verdef.vd_ndx.get(endian), VersionIndex::NAMES);
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
                        p.field_flags("Flags", vernaux.vna_flags.get(endian), VersionFlags::NAMES);
                        p.field_flags("Index", vernaux.vna_other(endian), VersymIndex::NAMES);
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
            let version_index = sym.0.get(endian);
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
                                p.field_consts("Tag", subsubsection.tag(), AttributeTag::NAMES);
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
    versym: VersymIndex,
) {
    match versions.and_then(|versions| versions.version(versym.index()).print_err(p)) {
        Some(Some(version)) => {
            p.field_string_option("Version", versym, Some(version.name()));
            p.flag_bits(versym & VERSYM_HIDDEN, VersymIndex::NAMES);
        }
        _ => p.field_flags("Version", versym, VersymIndex::NAMES),
    }
}

fn names<Elf: FileHeader>(endian: Elf::Endian, elf: &Elf) -> &'static Names {
    machine_names(elf.e_machine(endian))
}
