use std::error::Error;

use object::Endianness;
use object::elf;
use object::read::elf::{ElfFile64, FileHeader as _, Sym as _};
use object::write::elf::{
    FileHeader, ProgramHeader, SectionHeader, Sym, Verdef, Vernaux, Verneed, Writer,
};

/// Create a stub ELF shared library from a real one, using
/// [`object::write::elf::Writer`] in single-phase mode.
///
/// The output preserves the SONAME, `DT_NEEDED` list, dynamic symbol
/// table, and version information from the input, but replaces every
/// defined symbol's code/data with a single placeholder byte.
pub fn elfstub(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let elf = ElfFile64::<Endianness>::parse(data)?;
    let endian = elf.endian();
    let header = elf.elf_header();
    if header.e_type(endian) != elf::ET_DYN {
        return Err("input is not an ET_DYN shared object".into());
    }

    let sections = elf.elf_section_table();
    let dynsyms = elf.elf_dynamic_symbol_table();
    let in_dynstr = dynsyms.strings();
    let in_syms = dynsyms.symbols();

    // Build the output.
    let mut buffer = Vec::new();
    let mut writer = Writer::new_single_phase(endian, true, &mut buffer);

    // Placeholder file header, filled in at the end via write_headers_to after table
    // locations are known.
    let ident = header.e_ident();
    writer.write_file_header(&FileHeader {
        os_abi: ident.os_abi,
        abi_version: ident.abi_version,
        e_type: header.e_type(endian),
        e_machine: header.e_machine(endian),
        e_entry: 0,
        e_flags: header.e_flags(endian),
    })?;

    // Placeholder program headers (PT_PHDR for program headers, PT_LOAD for allocated
    // sections, PT_DYNAMIC for .dynamic).
    let (phdr_offset, phdr_size) = writer.write_program_headers_placeholder(3);

    // .stub section, one byte per symbol (only really need one per defined symbol).
    // This will be the first section header written (after the null section header).
    let stub_section_index = object::write::elf::SectionIndex(1);
    let stub_offset = writer.offset();
    let stub_size = in_syms.len() as u64;
    writer.pad_until(stub_offset + stub_size);

    // .dynsym
    let dynsym_offset = writer.write_null_dynamic_symbol();
    let mut hashes = vec![None];
    for (i, sym) in in_syms.iter().enumerate().skip(1) {
        let name = if sym.st_name(endian) != 0 {
            Some(sym.name(endian, in_dynstr)?)
        } else {
            None
        };
        let id = name.map(|name| writer.add_dynamic_string(name));
        hashes.push(name.map(elf::hash));

        let mut section = None;
        let mut st_value = sym.st_value(endian);
        let mut st_size = sym.st_size(endian);
        let st_shndx = sym.st_shndx(endian);
        if sym.st_shndx(endian).index().is_some() {
            section = Some(stub_section_index);
            st_value = stub_offset + i as u64;
            st_size = 1;
        }

        writer.write_dynamic_symbol(&Sym {
            name: id,
            section,
            st_info: sym.st_info(),
            st_other: sym.st_other(),
            st_shndx,
            st_value,
            st_size,
        });
    }
    let num_local_dynsym = 1u32
        + in_syms
            .iter()
            .skip(1)
            .take_while(|s| s.st_bind() == elf::STB_LOCAL)
            .count() as u32;

    // .hash
    let chain_count = in_syms.len() as u32;
    let bucket_count = chain_count.div_ceil(4).max(1);
    let hash_offset = writer.write_hash(bucket_count, chain_count, |i| hashes[i as usize]);

    // .gnu.version
    let mut versym_offset = 0;
    if let Some((versyms, _link)) = sections.gnu_versym(endian, data)? {
        if versyms.len() != in_syms.len() {
            return Err("versym length mismatch".into());
        }
        versym_offset = writer.write_null_gnu_versym();
        for versym in versyms.iter().skip(1) {
            writer.write_gnu_versym(versym.0.get(endian));
        }
    }

    // .gnu.version_d
    let mut verdef_offset = 0;
    let mut verdef_count = 0;
    if let Some((mut verdefs, link)) = sections.gnu_verdef(endian, data)? {
        let strings = sections.strings(endian, data, link)?;
        verdef_offset = writer.write_align_gnu_verdef();
        verdef_count = verdefs.clone().count() as u16;
        writer.set_gnu_verdef_count(verdef_count);
        while let Some((verdef, mut verdauxs)) = verdefs.next()? {
            let aux_count = verdauxs.clone().count() as u16;
            let Some(verdaux) = verdauxs.next()? else {
                return Err("missing verdef name".into());
            };
            let name = writer.add_dynamic_string(verdaux.name(endian, strings)?);
            writer.write_gnu_verdef(&Verdef {
                version: verdef.vd_version.get(endian),
                flags: verdef.vd_flags.get(endian),
                index: verdef.vd_ndx.get(endian),
                aux_count,
                name,
            });
            while let Some(verdaux) = verdauxs.next()? {
                let name = writer.add_dynamic_string(verdaux.name(endian, strings)?);
                writer.write_gnu_verdaux(name);
            }
        }
    }

    // .gnu.version_r
    let mut verneed_offset = 0;
    let mut verneed_count = 0;
    if let Some((mut verneeds, link)) = sections.gnu_verneed(endian, data)? {
        let strings = sections.strings(endian, data, link)?;
        verneed_offset = writer.write_align_gnu_verneed();
        verneed_count = verneeds.clone().count() as u16;
        writer.set_gnu_verneed_count(verneed_count);
        while let Some((verneed, mut vernauxs)) = verneeds.next()? {
            let aux_count = vernauxs.clone().count() as u16;
            let file = writer.add_dynamic_string(verneed.file(endian, strings)?);
            writer.write_gnu_verneed(&Verneed {
                version: verneed.vn_version.get(endian),
                aux_count,
                file,
            });
            while let Some(vernaux) = vernauxs.next()? {
                let name = writer.add_dynamic_string(vernaux.name(endian, strings)?);
                writer.write_gnu_vernaux(&Vernaux {
                    flags: vernaux.vna_flags.get(endian),
                    index: vernaux.vna_other.get(endian),
                    name,
                });
            }
        }
    }

    // .dynamic references .dynstr, so we need to add .dynamic strings and write .dynstr first.
    let dyn_table = elf.elf_dynamic_table()?;
    let dyn_strs = dyn_table.strings();
    let mut soname = None;
    let mut needed = Vec::new();
    let mut rpath = None;
    let mut runpath = None;
    let mut dt_flags = 0;
    let mut dt_flags_1 = 0;
    for d in dyn_table.iter() {
        match d.tag {
            elf::DT_SONAME => soname = Some(writer.add_dynamic_string(d.string(dyn_strs)?)),
            elf::DT_NEEDED => needed.push(writer.add_dynamic_string(d.string(dyn_strs)?)),
            elf::DT_RPATH => rpath = Some(writer.add_dynamic_string(d.string(dyn_strs)?)),
            elf::DT_RUNPATH => runpath = Some(writer.add_dynamic_string(d.string(dyn_strs)?)),
            elf::DT_FLAGS => dt_flags = d.val,
            elf::DT_FLAGS_1 => dt_flags_1 = d.val,
            _ => {}
        }
    }

    // .dynstr
    let (dynstr_offset, dynstr_size) = writer.write_dynstr()?;

    // .dynamic
    let dynamic_offset = writer.write_align_dynamic();
    if let Some(id) = soname {
        writer.write_dynamic_string(elf::DT_SONAME, id)?;
    }
    for id in needed {
        writer.write_dynamic_string(elf::DT_NEEDED, id)?;
    }
    if let Some(id) = rpath {
        writer.write_dynamic_string(elf::DT_RPATH, id)?;
    }
    if let Some(id) = runpath {
        writer.write_dynamic_string(elf::DT_RUNPATH, id)?;
    }
    writer.write_dynamic(elf::DT_HASH, hash_offset)?;
    writer.write_dynamic(elf::DT_STRTAB, dynstr_offset)?;
    writer.write_dynamic(elf::DT_SYMTAB, dynsym_offset)?;
    writer.write_dynamic(elf::DT_STRSZ, dynstr_size.into())?;
    writer.write_dynamic(
        elf::DT_SYMENT,
        core::mem::size_of::<elf::Sym64<Endianness>>() as u64,
    )?;
    if versym_offset != 0 {
        writer.write_dynamic(elf::DT_VERSYM, versym_offset)?;
    }
    if verdef_offset != 0 {
        writer.write_dynamic(elf::DT_VERDEF, verdef_offset)?;
        writer.write_dynamic(elf::DT_VERDEFNUM, verdef_count.into())?;
    }
    if verneed_offset != 0 {
        writer.write_dynamic(elf::DT_VERNEED, verneed_offset)?;
        writer.write_dynamic(elf::DT_VERNEEDNUM, verneed_count.into())?;
    }
    if dt_flags != 0 {
        writer.write_dynamic(elf::DT_FLAGS, dt_flags)?;
    }
    if dt_flags_1 != 0 {
        writer.write_dynamic(elf::DT_FLAGS_1, dt_flags_1)?;
    }
    writer.write_dynamic(elf::DT_NULL, 0)?;
    let load_size = writer.offset();
    let dynamic_size = load_size - dynamic_offset;

    // .shstrtab
    // Add the section name for our stub section. All other section names
    // are added implicitly when their data is written.
    let stub_name_id = writer.add_section_name(b".stub");
    writer.write_shstrtab()?;

    // Section header table.
    // PT_LOAD maps p_vaddr == p_offset so all section addresses are equal to offsets.
    writer.write_null_section_header();
    let index = writer.write_section_header(&SectionHeader {
        name: Some(stub_name_id),
        sh_type: elf::SHT_PROGBITS,
        sh_flags: elf::SHF_ALLOC,
        sh_addr: stub_offset,
        sh_offset: stub_offset,
        sh_size: stub_size,
        sh_link: 0,
        sh_info: 0,
        sh_addralign: 1,
        sh_entsize: 0,
    });
    debug_assert_eq!(index, stub_section_index);
    writer.write_dynstr_section_header(dynstr_offset);
    writer.write_dynsym_section_header(dynsym_offset, num_local_dynsym);
    writer.write_hash_section_header(hash_offset);
    writer.write_gnu_versym_section_header(versym_offset);
    writer.write_gnu_verdef_section_header(verdef_offset);
    writer.write_gnu_verneed_section_header(verneed_offset);
    writer.write_dynamic_section_header(dynamic_offset);
    writer.write_shstrtab_section_header();

    // Write the corrected file header and program headers.
    let program_headers = [
        ProgramHeader {
            p_type: elf::PT_PHDR,
            p_flags: elf::PF_R,
            p_offset: phdr_offset,
            p_vaddr: phdr_offset,
            p_paddr: phdr_offset,
            p_filesz: phdr_size,
            p_memsz: phdr_size,
            p_align: 0x1000,
        },
        ProgramHeader {
            p_type: elf::PT_LOAD,
            p_flags: elf::PF_R,
            p_offset: 0,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: load_size,
            p_memsz: load_size,
            p_align: 0x1000,
        },
        ProgramHeader {
            p_type: elf::PT_DYNAMIC,
            p_flags: elf::PF_R,
            p_offset: dynamic_offset,
            p_vaddr: dynamic_offset,
            p_paddr: dynamic_offset,
            p_filesz: dynamic_size,
            p_memsz: dynamic_size,
            p_align: 8,
        },
    ];

    let mut header_buf = Vec::new();
    writer.write_headers_to(&mut header_buf, &program_headers)?;
    buffer[..header_buf.len()].copy_from_slice(&header_buf);

    Ok(buffer)
}
