use std::error::Error;

use object::Endianness;
use object::elf;
use object::read::elf::{Dyn, FileHeader, ProgramHeader, Rel, Rela, SectionHeader, Sym};

struct Section {
    name: Option<object::write::StringId>,
    offset: u64,
}

struct Dynamic {
    tag: object::elf::DynamicTag,
    // Ignored if `string` is set.
    val: u64,
    string: Option<object::write::StringId>,
}

struct Symbol {
    in_sym: object::read::SymbolIndex,
    name: Option<object::write::StringId>,
    section: Option<object::write::elf::SectionIndex>,
}

struct DynamicSymbol {
    in_sym: object::read::SymbolIndex,
    name: Option<object::write::StringId>,
    section: Option<object::write::elf::SectionIndex>,
    hash: Option<u32>,
    gnu_hash: Option<u32>,
}

pub fn elfcopy32(in_data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    elfcopy::<object::elf::FileHeader32<Endianness>>(in_data)
}

pub fn elfcopy64(in_data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    elfcopy::<object::elf::FileHeader64<Endianness>>(in_data)
}

/// Create a copy of an ELF file using [`object::write::elf::Writer`] in two-phase mode.
pub fn elfcopy<Elf: FileHeader<Endian = Endianness>>(
    in_data: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let in_elf = Elf::parse(in_data)?;
    let endian = in_elf.endian()?;
    let is_mips64el = in_elf.is_mips64el(endian);
    let in_segments = in_elf.program_headers(endian, in_data)?;
    let in_sections = in_elf.sections(endian, in_data)?;
    let in_syms = in_sections.symbols(endian, in_data, elf::SHT_SYMTAB)?;
    let in_dynsyms = in_sections.symbols(endian, in_data, elf::SHT_DYNSYM)?;

    let mut out_data = Vec::new();
    let mut writer = object::write::elf::Writer::new(endian, in_elf.is_class_64(), &mut out_data);

    // Find metadata sections, and assign section indices.
    let mut in_dynamic = None;
    let mut in_hash = None;
    let mut in_gnu_hash = None;
    let mut in_versym = None;
    let mut in_verdef = None;
    let mut in_verneed = None;
    let mut in_attributes = None;
    let mut out_sections = Vec::with_capacity(in_sections.len());
    let mut out_sections_index = Vec::with_capacity(in_sections.len());
    for (i, in_section) in in_sections.enumerate() {
        let mut name = None;
        let index;
        match in_section.sh_type(endian) {
            elf::SHT_NULL => {
                index = writer.reserve_null_section_index();
            }
            elf::SHT_PROGBITS
            | elf::SHT_NOBITS
            | elf::SHT_NOTE
            | elf::SHT_REL
            | elf::SHT_RELA
            | elf::SHT_INIT_ARRAY
            | elf::SHT_FINI_ARRAY => {
                name = Some(writer.add_section_name(in_sections.section_name(endian, in_section)?));
                index = writer.reserve_section_index();
            }
            elf::SHT_STRTAB => {
                if i == in_syms.string_section() {
                    index = writer.reserve_strtab_section_index();
                } else if i == in_dynsyms.string_section() {
                    index = writer.reserve_dynstr_section_index();
                } else if i == in_elf.section_strings_index(endian, in_data)? {
                    index = writer.reserve_shstrtab_section_index();
                } else {
                    panic!("Unsupported string section {}", i);
                }
            }
            elf::SHT_SYMTAB => {
                if i == in_syms.section() {
                    index = writer.reserve_symtab_section_index();
                } else {
                    panic!("Unsupported symtab section {}", i);
                }
            }
            elf::SHT_SYMTAB_SHNDX => {
                if i == in_syms.shndx_section() {
                    index = writer.reserve_symtab_shndx_section_index();
                } else {
                    panic!("Unsupported symtab shndx section {}", i);
                }
            }
            elf::SHT_DYNSYM => {
                if i == in_dynsyms.section() {
                    index = writer.reserve_dynsym_section_index();
                } else {
                    panic!("Unsupported dynsym section {}", i);
                }
            }
            elf::SHT_DYNAMIC => {
                assert!(in_dynamic.is_none());
                in_dynamic = in_section.dynamic(endian, in_data)?;
                debug_assert!(in_dynamic.is_some());
                index = writer.reserve_dynamic_section_index();
            }
            elf::SHT_HASH => {
                assert!(in_hash.is_none());
                in_hash = in_section.hash_header(endian, in_data)?;
                debug_assert!(in_hash.is_some());
                index = writer.reserve_hash_section_index();
            }
            elf::SHT_GNU_HASH => {
                assert!(in_gnu_hash.is_none());
                in_gnu_hash = in_section.gnu_hash_header(endian, in_data)?;
                debug_assert!(in_gnu_hash.is_some());
                index = writer.reserve_gnu_hash_section_index();
            }
            elf::SHT_GNU_VERSYM => {
                in_versym = in_section.gnu_versym(endian, in_data)?;
                debug_assert!(in_versym.is_some());
                index = writer.reserve_gnu_versym_section_index();
            }
            elf::SHT_GNU_VERDEF => {
                in_verdef = in_section.gnu_verdef(endian, in_data)?;
                debug_assert!(in_verdef.is_some());
                index = writer.reserve_gnu_verdef_section_index();
            }
            elf::SHT_GNU_VERNEED => {
                in_verneed = in_section.gnu_verneed(endian, in_data)?;
                debug_assert!(in_verneed.is_some());
                index = writer.reserve_gnu_verneed_section_index();
            }
            elf::SHT_GNU_ATTRIBUTES => {
                in_attributes = in_section.gnu_attributes(endian, in_data)?;
                debug_assert!(in_attributes.is_some());
                index = writer.reserve_gnu_attributes_section_index();
            }
            other => {
                panic!("Unsupported section type {:x}", other);
            }
        }
        out_sections.push(Section { name, offset: 0 });
        out_sections_index.push(index);
    }

    // Assign dynamic strings.
    let mut out_dynamic = Vec::new();
    if let Some((in_dynamic, link)) = in_dynamic {
        out_dynamic.reserve(in_dynamic.len());
        let in_dynamic_strings = in_sections.strings(endian, in_data, link)?;
        for d in in_dynamic {
            let tag = d.d_tag(endian);
            let val = d.d_val(endian).into();
            let string = if d.is_string(endian) {
                let s = in_dynamic_strings
                    .get(val.try_into()?)
                    .map_err(|_| "Invalid dynamic string")?;
                Some(writer.add_dynamic_string(s))
            } else {
                None
            };
            out_dynamic.push(Dynamic { tag, val, string });
            if tag == elf::DT_NULL {
                break;
            }
        }
    }

    // Assign dynamic symbol indices.
    let mut out_dynsyms = Vec::with_capacity(in_dynsyms.len());
    for (i, in_dynsym) in in_dynsyms.enumerate().skip(1) {
        let section = match in_dynsyms.symbol_section(endian, in_dynsym, i)? {
            Some(in_section) => {
                // Skip symbols for sections we aren't copying.
                if out_sections_index[in_section.0].0 == 0 {
                    continue;
                }
                Some(out_sections_index[in_section.0])
            }
            None => None,
        };
        let mut name = None;
        let mut hash = None;
        let mut gnu_hash = None;
        if in_dynsym.st_name(endian) != 0 {
            let in_name = in_dynsyms.symbol_name(endian, in_dynsym)?;
            name = Some(writer.add_dynamic_string(in_name));
            if !in_name.is_empty() {
                hash = Some(elf::hash(in_name));
                if !in_dynsym.is_undefined(endian) {
                    gnu_hash = Some(elf::gnu_hash(in_name));
                }
            }
        };
        out_dynsyms.push(DynamicSymbol {
            in_sym: i,
            name,
            section,
            hash,
            gnu_hash,
        });
    }
    // We must sort for GNU hash before allocating symbol indices.
    if let Some(in_gnu_hash) = in_gnu_hash.as_ref() {
        // TODO: recalculate bucket_count
        out_dynsyms.sort_by_key(|sym| match sym.gnu_hash {
            None => (0, 0),
            Some(hash) => (1, hash % in_gnu_hash.bucket_count.get(endian)),
        });
    }
    let mut out_dynsyms_index = vec![Default::default(); in_dynsyms.len()];
    for out_dynsym in out_dynsyms.iter_mut() {
        out_dynsyms_index[out_dynsym.in_sym.0] = writer.reserve_dynamic_symbol_index();
    }

    // Hash parameters.
    let hash_index_base = out_dynsyms
        .first()
        .map(|sym| out_dynsyms_index[sym.in_sym.0].0)
        .unwrap_or(0);
    let hash_chain_count = writer.dynamic_symbol_count();

    // GNU hash parameters.
    let gnu_hash_index_base = out_dynsyms
        .iter()
        .position(|sym| sym.gnu_hash.is_some())
        .unwrap_or(0);
    let gnu_hash_symbol_base = out_dynsyms
        .iter()
        .find(|sym| sym.gnu_hash.is_some())
        .map(|sym| out_dynsyms_index[sym.in_sym.0].0)
        .unwrap_or_else(|| writer.dynamic_symbol_count());
    let gnu_hash_symbol_count = writer.dynamic_symbol_count() - gnu_hash_symbol_base;

    // Assign symbol indices.
    let mut num_local = 0;
    let mut out_syms = Vec::with_capacity(in_syms.len());
    let mut out_syms_index = Vec::with_capacity(in_syms.len());
    out_syms_index.push(Default::default());
    for (i, in_sym) in in_syms.enumerate().skip(1) {
        let section = match in_syms.symbol_section(endian, in_sym, i)? {
            Some(in_section) => {
                // Skip symbols for sections we aren't copying.
                if out_sections_index[in_section.0].0 == 0 {
                    out_syms_index.push(Default::default());
                    continue;
                }
                Some(out_sections_index[in_section.0])
            }
            None => None,
        };
        out_syms_index.push(writer.reserve_symbol_index(section));
        let name = if in_sym.st_name(endian) != 0 {
            Some(writer.add_string(in_syms.symbol_name(endian, in_sym)?))
        } else {
            None
        };
        out_syms.push(Symbol {
            in_sym: i,
            name,
            section,
        });
        if in_sym.st_bind() == elf::STB_LOCAL {
            num_local = writer.symbol_count();
        }
    }

    // Symbol version parameters.
    let mut verdef_count = 0;
    let mut verdef_shared_base = false;
    let mut version_base = None;
    let mut verdaux_count = 0;
    if let Some((mut verdefs, link)) = in_verdef.clone() {
        let strings = in_sections.strings(endian, in_data, link)?;
        while let Some((verdef, mut verdauxs)) = verdefs.next()? {
            assert!(verdef.vd_cnt.get(endian) > 0);
            verdef_count += 1;
            let mut names = Vec::new();
            while let Some(verdaux) = verdauxs.next()? {
                let name = verdaux.name(endian, strings)?;
                names.push(writer.add_dynamic_string(name));
            }
            if verdef_count == 1
                && let [name] = names[..]
            {
                version_base = Some(name);
                verdaux_count += names.len();
            } else if verdef_count == 2
                && let [name] = names[..]
                && Some(name) == version_base
            {
                verdef_shared_base = true;
            } else {
                verdaux_count += names.len();
            };
        }
    }

    let mut verneed_count = 0;
    let mut vernaux_count = 0;
    if let Some((mut verneeds, link)) = in_verneed.clone() {
        let strings = in_sections.strings(endian, in_data, link)?;
        while let Some((verneed, mut vernauxs)) = verneeds.next()? {
            writer.add_dynamic_string(verneed.file(endian, strings)?);
            verneed_count += 1;
            while let Some(vernaux) = vernauxs.next()? {
                writer.add_dynamic_string(vernaux.name(endian, strings)?);
                vernaux_count += 1;
            }
        }
    }

    let mut gnu_attributes = Vec::new();
    if let Some(attributes) = in_attributes {
        let mut writer = writer.attributes_writer();
        let mut subsections = attributes.subsections()?;
        while let Some(subsection) = subsections.next()? {
            writer.start_subsection(subsection.vendor());
            let mut subsubsections = subsection.subsubsections();
            while let Some(subsubsection) = subsubsections.next()? {
                writer.start_subsubsection(subsubsection.tag());
                match subsubsection.tag() {
                    elf::Tag_File => {}
                    elf::Tag_Section => {
                        let mut indices = subsubsection.indices();
                        while let Some(index) = indices.next()? {
                            writer.write_subsubsection_index(out_sections_index[index as usize].0);
                        }
                        writer.write_subsubsection_index(0);
                    }
                    elf::Tag_Symbol => {
                        let mut indices = subsubsection.indices();
                        while let Some(index) = indices.next()? {
                            writer.write_subsubsection_index(out_syms_index[index as usize].0);
                        }
                        writer.write_subsubsection_index(0);
                    }
                    _ => unimplemented!(),
                }
                writer.write_subsubsection_attributes(subsubsection.attributes_data());
                writer.end_subsubsection();
            }
            writer.end_subsection();
        }
        gnu_attributes = writer.data();
        assert_ne!(gnu_attributes.len(), 0);
    }

    // Start reserving file ranges.
    writer.reserve_file_header();

    let mut hash_addr = 0;
    let mut gnu_hash_addr = 0;
    let mut versym_addr = 0;
    let mut verdef_addr = 0;
    let mut verneed_addr = 0;
    let mut dynamic_addr = 0;
    let mut dynsym_addr = 0;
    let mut dynstr_addr = 0;

    let mut alloc_sections = Vec::new();
    if in_segments.is_empty() {
        // Reserve sections at any offset.
        for (i, in_section) in in_sections.enumerate() {
            match in_section.sh_type(endian) {
                elf::SHT_PROGBITS | elf::SHT_NOTE | elf::SHT_INIT_ARRAY | elf::SHT_FINI_ARRAY => {
                    out_sections[i.0].offset = writer.reserve(
                        in_section.sh_size(endian).into(),
                        in_section.sh_addralign(endian).into(),
                    );
                }
                elf::SHT_GNU_ATTRIBUTES => {
                    writer.reserve_gnu_attributes(gnu_attributes.len() as u64);
                }
                _ => {}
            }
        }
    } else {
        // We don't support moving program headers.
        assert_eq!(in_elf.e_phoff(endian).into(), writer.reserved_len());
        writer.reserve_program_headers(in_segments.len());

        // Reserve alloc sections at original offsets.
        alloc_sections = in_sections
            .enumerate()
            .filter(|(_, s)| s.sh_flags(endian).contains(elf::SHF_ALLOC))
            .collect();
        // The data for alloc sections may need to be written in a different order
        // from their section headers.
        alloc_sections.sort_by_key(|(_, x)| x.sh_offset(endian).into());
        for (i, in_section) in alloc_sections.iter() {
            writer.reserve_until(in_section.sh_offset(endian).into());
            match in_section.sh_type(endian) {
                elf::SHT_PROGBITS | elf::SHT_NOTE | elf::SHT_INIT_ARRAY | elf::SHT_FINI_ARRAY => {
                    out_sections[i.0].offset = writer.reserve(in_section.sh_size(endian).into(), 1);
                }
                elf::SHT_NOBITS => {
                    out_sections[i.0].offset = writer.reserved_len();
                }
                elf::SHT_REL => {
                    let (rels, _link) = in_section.rel(endian, in_data)?.unwrap();
                    out_sections[i.0].offset = writer.reserve_relocations(rels.len(), false);
                }
                elf::SHT_RELA => {
                    let (rels, _link) = in_section.rela(endian, in_data)?.unwrap();
                    out_sections[i.0].offset = writer.reserve_relocations(rels.len(), true);
                }
                elf::SHT_DYNAMIC => {
                    dynamic_addr = in_section.sh_addr(endian).into();
                    writer.reserve_dynamic(out_dynamic.len());
                }
                elf::SHT_DYNSYM if *i == in_dynsyms.section() => {
                    dynsym_addr = in_section.sh_addr(endian).into();
                    writer.reserve_dynsym();
                }
                elf::SHT_STRTAB if *i == in_dynsyms.string_section() => {
                    dynstr_addr = in_section.sh_addr(endian).into();
                    writer.reserve_dynstr()?;
                }
                elf::SHT_HASH => {
                    hash_addr = in_section.sh_addr(endian).into();
                    let hash = in_hash.as_ref().unwrap();
                    writer.reserve_hash(hash.bucket_count.get(endian), hash_chain_count);
                }
                elf::SHT_GNU_HASH => {
                    gnu_hash_addr = in_section.sh_addr(endian).into();
                    let hash = in_gnu_hash.as_ref().unwrap();
                    writer.reserve_gnu_hash(
                        hash.bloom_count.get(endian),
                        hash.bucket_count.get(endian),
                        gnu_hash_symbol_count,
                    );
                }
                elf::SHT_GNU_VERSYM => {
                    versym_addr = in_section.sh_addr(endian).into();
                    writer.reserve_gnu_versym();
                }
                elf::SHT_GNU_VERDEF => {
                    verdef_addr = in_section.sh_addr(endian).into();
                    writer.reserve_gnu_verdef(verdef_count, verdaux_count);
                }
                elf::SHT_GNU_VERNEED => {
                    verneed_addr = in_section.sh_addr(endian).into();
                    writer.reserve_gnu_verneed(verneed_count, vernaux_count);
                }
                other => {
                    panic!("Unsupported alloc section index {}, type {}", *i, other);
                }
            }
        }

        // Reserve non-alloc sections at any offset.
        for (i, in_section) in in_sections.enumerate() {
            if in_section.sh_flags(endian).contains(elf::SHF_ALLOC) {
                continue;
            }
            match in_section.sh_type(endian) {
                elf::SHT_PROGBITS | elf::SHT_NOTE => {
                    out_sections[i.0].offset = writer.reserve(
                        in_section.sh_size(endian).into(),
                        in_section.sh_addralign(endian).into(),
                    );
                }
                elf::SHT_GNU_ATTRIBUTES => {
                    writer.reserve_gnu_attributes(gnu_attributes.len() as u64);
                }
                _ => {}
            }
        }
    }

    writer.reserve_symtab();
    writer.reserve_symtab_shndx();
    writer.reserve_strtab()?;

    for (i, in_section) in in_sections.enumerate() {
        if !in_segments.is_empty() && in_section.sh_flags(endian).contains(elf::SHF_ALLOC) {
            continue;
        }
        match in_section.sh_type(endian) {
            elf::SHT_REL => {
                let (rels, _link) = in_section.rel(endian, in_data)?.unwrap();
                out_sections[i.0].offset = writer.reserve_relocations(rels.len(), false);
            }
            elf::SHT_RELA => {
                let (rels, _link) = in_section.rela(endian, in_data)?.unwrap();
                out_sections[i.0].offset = writer.reserve_relocations(rels.len(), true);
            }
            _ => {}
        }
    }

    writer.reserve_shstrtab()?;
    writer.reserve_section_headers();

    writer.write_file_header(&object::write::elf::FileHeader {
        os_abi: in_elf.e_ident().os_abi,
        abi_version: in_elf.e_ident().abi_version,
        e_type: in_elf.e_type(endian),
        e_machine: in_elf.e_machine(endian),
        e_entry: in_elf.e_entry(endian).into(),
        e_flags: in_elf.e_flags(endian),
    })?;

    if in_segments.is_empty() {
        for (i, in_section) in in_sections.iter().enumerate() {
            match in_section.sh_type(endian) {
                elf::SHT_PROGBITS | elf::SHT_NOTE | elf::SHT_INIT_ARRAY | elf::SHT_FINI_ARRAY => {
                    writer.write_align(in_section.sh_addralign(endian).into());
                    debug_assert_eq!(out_sections[i].offset, writer.offset());
                    writer.write(in_section.data(endian, in_data)?);
                }
                elf::SHT_GNU_ATTRIBUTES => {
                    writer.write_gnu_attributes(&gnu_attributes);
                }
                _ => {}
            }
        }
    } else {
        writer.write_align_program_headers();
        for in_segment in in_segments {
            writer.write_program_header(&object::write::elf::ProgramHeader {
                p_type: in_segment.p_type(endian),
                p_flags: in_segment.p_flags(endian),
                p_offset: in_segment.p_offset(endian).into(),
                p_vaddr: in_segment.p_vaddr(endian).into(),
                p_paddr: in_segment.p_paddr(endian).into(),
                p_filesz: in_segment.p_filesz(endian).into(),
                p_memsz: in_segment.p_memsz(endian).into(),
                p_align: in_segment.p_align(endian).into(),
            });
        }

        for (i, in_section) in alloc_sections.iter() {
            writer.pad_until(in_section.sh_offset(endian).into());
            match in_section.sh_type(endian) {
                elf::SHT_PROGBITS | elf::SHT_NOTE | elf::SHT_INIT_ARRAY | elf::SHT_FINI_ARRAY => {
                    debug_assert_eq!(out_sections[i.0].offset, writer.offset());
                    writer.write(in_section.data(endian, in_data)?);
                }
                elf::SHT_NOBITS => {}
                elf::SHT_REL => {
                    let (rels, _link) = in_section.rel(endian, in_data)?.unwrap();
                    writer.write_align_relocation();
                    for rel in rels {
                        let out_sym = if let Some(in_sym) = rel.symbol(endian) {
                            out_dynsyms_index[in_sym.0].0
                        } else {
                            0
                        };
                        writer.write_relocation(
                            false,
                            &object::write::elf::Rel {
                                r_offset: rel.r_offset(endian).into(),
                                r_sym: out_sym,
                                r_type: rel.r_type(endian),
                                r_addend: 0,
                            },
                        );
                    }
                }
                elf::SHT_RELA => {
                    let (rels, _link) = in_section.rela(endian, in_data)?.unwrap();
                    writer.write_align_relocation();
                    for rel in rels {
                        let out_sym = if let Some(in_sym) = rel.symbol(endian, is_mips64el) {
                            out_dynsyms_index[in_sym.0].0
                        } else {
                            0
                        };
                        writer.write_relocation(
                            true,
                            &object::write::elf::Rel {
                                r_offset: rel.r_offset(endian).into(),
                                r_sym: out_sym,
                                r_type: rel.r_type(endian, is_mips64el),
                                r_addend: rel.r_addend(endian).into(),
                            },
                        );
                    }
                }
                elf::SHT_DYNAMIC => {
                    for d in &out_dynamic {
                        if let Some(string) = d.string {
                            writer.write_dynamic_string(d.tag, string)?;
                        } else {
                            // TODO: fix values
                            let val = d.val;
                            writer.write_dynamic(d.tag, val)?;
                        }
                    }
                }
                elf::SHT_DYNSYM if *i == in_dynsyms.section() => {
                    writer.write_null_dynamic_symbol();
                    for sym in &out_dynsyms {
                        let in_dynsym = in_dynsyms.symbol(sym.in_sym)?;
                        writer.write_dynamic_symbol(&object::write::elf::Sym {
                            section: sym.section.map(|s| s.0),
                            st_name: writer.dynamic_string_offset(sym.name),
                            st_info: in_dynsym.st_info(),
                            st_other: in_dynsym.st_other(),
                            st_shndx: in_dynsym.st_shndx(endian),
                            st_value: in_dynsym.st_value(endian).into(),
                            st_size: in_dynsym.st_size(endian).into(),
                        });
                    }
                }
                elf::SHT_STRTAB if *i == in_dynsyms.string_section() => {
                    writer.write_dynstr();
                }
                elf::SHT_HASH => {
                    let hash = in_hash.as_ref().unwrap();
                    writer.write_hash(hash.bucket_count.get(endian), hash_chain_count, |index| {
                        out_dynsyms
                            .get(index.checked_sub(hash_index_base)? as usize)?
                            .hash
                    });
                }
                elf::SHT_GNU_HASH => {
                    let gnu_hash = in_gnu_hash.as_ref().unwrap();
                    writer.write_gnu_hash(
                        gnu_hash_symbol_base,
                        gnu_hash.bloom_shift.get(endian),
                        gnu_hash.bloom_count.get(endian),
                        gnu_hash.bucket_count.get(endian),
                        gnu_hash_symbol_count,
                        |index| {
                            out_dynsyms[gnu_hash_index_base + index as usize]
                                .gnu_hash
                                .unwrap()
                        },
                    );
                }
                elf::SHT_GNU_VERSYM => {
                    let (in_versym, _) = in_versym.as_ref().unwrap();
                    writer.write_null_gnu_versym();
                    for out_dynsym in &out_dynsyms {
                        writer.write_gnu_versym(
                            in_versym.get(out_dynsym.in_sym.0).unwrap().0.get(endian),
                        );
                    }
                }
                elf::SHT_GNU_VERDEF => {
                    let (mut verdefs, link) = in_verdef.clone().unwrap();
                    let strings = in_sections.strings(endian, in_data, link)?;
                    writer.write_align_gnu_verdef();
                    while let Some((verdef, mut verdauxs)) = verdefs.next()? {
                        let verdaux = verdauxs.next()?.unwrap();
                        let name = verdaux.name(endian, strings)?;
                        let name_id = writer.get_dynamic_string(name);
                        let verdef = object::write::elf::Verdef {
                            version: verdef.vd_version.get(endian),
                            flags: verdef.vd_flags.get(endian),
                            index: verdef.vd_ndx.get(endian),
                            aux_count: verdef.vd_cnt.get(endian),
                            name: writer.dynamic_string_offset(Some(name_id)),
                            hash: elf::hash(name),
                        };
                        if verdef_shared_base {
                            writer.write_gnu_verdef_shared(&verdef);
                            verdef_shared_base = false;
                            continue;
                        }
                        writer.write_gnu_verdef(&verdef);
                        while let Some(verdaux) = verdauxs.next()? {
                            writer.write_gnu_verdaux(
                                writer.get_dynamic_string(verdaux.name(endian, strings)?),
                            );
                        }
                    }
                }
                elf::SHT_GNU_VERNEED => {
                    let (mut verneeds, link) = in_verneed.clone().unwrap();
                    let strings = in_sections.strings(endian, in_data, link)?;
                    writer.write_align_gnu_verneed();
                    while let Some((verneed, mut vernauxs)) = verneeds.next()? {
                        let file_id = writer.get_dynamic_string(verneed.file(endian, strings)?);
                        writer.write_gnu_verneed(&object::write::elf::Verneed {
                            version: verneed.vn_version.get(endian),
                            aux_count: verneed.vn_cnt.get(endian),
                            file: writer.dynamic_string_offset(Some(file_id)),
                        });
                        while let Some(vernaux) = vernauxs.next()? {
                            let name = vernaux.name(endian, strings)?;
                            let name_id = writer.get_dynamic_string(name);
                            writer.write_gnu_vernaux(&object::write::elf::Vernaux {
                                flags: vernaux.vna_flags.get(endian),
                                index: vernaux.vna_other.get(endian),
                                name: writer.dynamic_string_offset(Some(name_id)),
                                hash: elf::hash(name),
                            });
                        }
                    }
                }
                other => {
                    panic!("Unsupported alloc section type {:x}", other);
                }
            }
        }

        for (i, in_section) in in_sections.enumerate() {
            if in_section.sh_flags(endian).contains(elf::SHF_ALLOC) {
                continue;
            }
            match in_section.sh_type(endian) {
                elf::SHT_PROGBITS | elf::SHT_NOTE => {
                    writer.write_align(in_section.sh_addralign(endian).into());
                    debug_assert_eq!(out_sections[i.0].offset, writer.offset());
                    writer.write(in_section.data(endian, in_data)?);
                }
                elf::SHT_GNU_ATTRIBUTES => {
                    writer.write_gnu_attributes(&gnu_attributes);
                }
                _ => {}
            }
        }
    }

    writer.write_null_symbol();
    for sym in &out_syms {
        let in_sym = in_syms.symbol(sym.in_sym)?;
        writer.write_symbol(&object::write::elf::Sym {
            section: sym.section.map(|s| s.0),
            st_name: writer.string_offset(sym.name),
            st_info: in_sym.st_info(),
            st_other: in_sym.st_other(),
            st_shndx: in_sym.st_shndx(endian),
            st_value: in_sym.st_value(endian).into(),
            st_size: in_sym.st_size(endian).into(),
        });
    }
    writer.write_symtab_shndx();
    writer.write_strtab();

    for in_section in in_sections.iter() {
        if !in_segments.is_empty() && in_section.sh_flags(endian).contains(elf::SHF_ALLOC) {
            continue;
        }
        let out_syms = if in_section.link(endian) == in_syms.section() {
            &out_syms_index
        } else {
            &out_dynsyms_index
        };
        match in_section.sh_type(endian) {
            elf::SHT_REL => {
                let (rels, _link) = in_section.rel(endian, in_data)?.unwrap();
                writer.write_align_relocation();
                for rel in rels {
                    let out_sym = if let Some(in_sym) = rel.symbol(endian) {
                        out_syms[in_sym.0].0
                    } else {
                        0
                    };
                    writer.write_relocation(
                        false,
                        &object::write::elf::Rel {
                            r_offset: rel.r_offset(endian).into(),
                            r_sym: out_sym,
                            r_type: rel.r_type(endian),
                            r_addend: 0,
                        },
                    );
                }
            }
            elf::SHT_RELA => {
                let (rels, _link) = in_section.rela(endian, in_data)?.unwrap();
                writer.write_align_relocation();
                for rel in rels {
                    let out_sym = if let Some(in_sym) = rel.symbol(endian, is_mips64el) {
                        out_syms[in_sym.0].0
                    } else {
                        0
                    };
                    writer.write_relocation(
                        true,
                        &object::write::elf::Rel {
                            r_offset: rel.r_offset(endian).into(),
                            r_sym: out_sym,
                            r_type: rel.r_type(endian, is_mips64el),
                            r_addend: rel.r_addend(endian).into(),
                        },
                    );
                }
            }
            _ => {}
        }
    }

    writer.write_shstrtab();

    writer.write_null_section_header();
    for (i, in_section) in in_sections.enumerate() {
        match in_section.sh_type(endian) {
            elf::SHT_NULL => {}
            elf::SHT_PROGBITS
            | elf::SHT_NOBITS
            | elf::SHT_NOTE
            | elf::SHT_REL
            | elf::SHT_RELA
            | elf::SHT_INIT_ARRAY
            | elf::SHT_FINI_ARRAY => {
                let out_section = &out_sections[i.0];
                let sh_link = out_sections_index[in_section.link(endian).0].0;
                let mut sh_info = in_section.sh_info(endian);
                if in_section.has_info_link(endian) {
                    sh_info = out_sections_index[sh_info as usize].0;
                }
                writer.write_section_header(&object::write::elf::SectionHeader {
                    sh_name: writer.section_name_offset(out_section.name),
                    sh_type: in_section.sh_type(endian),
                    sh_flags: in_section.sh_flags(endian),
                    sh_addr: in_section.sh_addr(endian).into(),
                    sh_offset: out_section.offset,
                    sh_size: in_section.sh_size(endian).into(),
                    sh_link,
                    sh_info,
                    sh_addralign: in_section.sh_addralign(endian).into(),
                    sh_entsize: in_section.sh_entsize(endian).into(),
                });
            }
            elf::SHT_STRTAB => {
                if i == in_syms.string_section() {
                    writer.write_strtab_section_header();
                } else if i == in_dynsyms.string_section() {
                    writer.write_dynstr_section_header(dynstr_addr);
                } else if i == in_elf.section_strings_index(endian, in_data)? {
                    writer.write_shstrtab_section_header();
                } else {
                    panic!("Unsupported string section {}", i);
                }
            }
            elf::SHT_SYMTAB => {
                if i == in_syms.section() {
                    writer.write_symtab_section_header(num_local);
                } else {
                    panic!("Unsupported symtab section {}", i);
                }
            }
            elf::SHT_SYMTAB_SHNDX => {
                if i == in_syms.shndx_section() {
                    writer.write_symtab_shndx_section_header();
                } else {
                    panic!("Unsupported symtab shndx section {}", i);
                }
            }
            elf::SHT_DYNSYM => {
                if i == in_dynsyms.section() {
                    writer.write_dynsym_section_header(dynsym_addr, 1);
                } else {
                    panic!("Unsupported dynsym section {}", i);
                }
            }
            elf::SHT_DYNAMIC => {
                writer.write_dynamic_section_header(dynamic_addr);
            }
            elf::SHT_HASH => {
                writer.write_hash_section_header(hash_addr);
            }
            elf::SHT_GNU_HASH => {
                writer.write_gnu_hash_section_header(gnu_hash_addr);
            }
            elf::SHT_GNU_VERSYM => {
                writer.write_gnu_versym_section_header(versym_addr);
            }
            elf::SHT_GNU_VERDEF => {
                writer.write_gnu_verdef_section_header(verdef_addr);
            }
            elf::SHT_GNU_VERNEED => {
                writer.write_gnu_verneed_section_header(verneed_addr);
            }
            elf::SHT_GNU_ATTRIBUTES => {
                writer.write_gnu_attributes_section_header();
            }
            other => {
                panic!("Unsupported section type {:x}", other);
            }
        }
    }
    debug_assert_eq!(writer.reserved_len(), writer.len());

    Ok(out_data)
}
