use std::error::Error;
use std::{env, fs, process};

use object::read::elf::{FileHeader, Rel, Rela, SectionHeader};
use object::Endianness;
use object::{elf, pe, ReadRef, SectionIndex};

fn main() {
    let mut args = env::args();
    if args.len() != 3 {
        eprintln!("Usage: {} <infile> <outfile>", args.next().unwrap());
        process::exit(1);
    }

    args.next();
    let in_file_path = args.next().unwrap();
    let out_file_path = args.next().unwrap();

    let in_file = match fs::File::open(&in_file_path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Failed to open file '{}': {}", in_file_path, err,);
            process::exit(1);
        }
    };
    let in_data = match unsafe { memmap2::Mmap::map(&in_file) } {
        Ok(mmap) => mmap,
        Err(err) => {
            eprintln!("Failed to map file '{}': {}", in_file_path, err,);
            process::exit(1);
        }
    };
    let in_data = &*in_data;

    let kind = match object::FileKind::parse(in_data) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Failed to parse file: {}", err);
            process::exit(1);
        }
    };
    let out_data = match kind {
        object::FileKind::Elf32 => copy_file::<elf::FileHeader32<Endianness>>(in_data).unwrap(),
        object::FileKind::Elf64 => copy_file::<elf::FileHeader64<Endianness>>(in_data).unwrap(),
        _ => {
            eprintln!("Not an ELF file");
            process::exit(1);
        }
    };
    if let Err(err) = fs::write(&out_file_path, out_data) {
        eprintln!("Failed to write file '{}': {}", out_file_path, err);
        process::exit(1);
    }
}

fn copy_file<Elf: FileHeader<Endian = Endianness>>(
    in_data: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let in_elf = Elf::parse(in_data)?;
    let endian = in_elf.endian()?;
    let is_mips64el = in_elf.is_mips64el(endian);
    let in_sections = in_elf.sections(endian, in_data)?;

    let text = in_sections.iter().find(|s| is_text(*s, endian)).unwrap();
    let alignment = text.sh_addralign(endian).into();

    // Calculate text and data layout.
    // For now, we use the ELF layout without any change, and require
    // sections to be in order of address, and all text sections must
    // appear before data sections.
    let mut text_start = !0;
    let mut text_end = 0;
    let mut have_data = false;
    let mut data_start = !0;
    let mut data_end = 0;
    for in_section in in_sections.iter() {
        if !is_alloc(in_section, endian) {
            continue;
        }
        assert!(in_section.sh_addralign(endian).into() <= alignment);
        let start = in_section.sh_addr(endian).into() as u32;
        let end = start + in_section.sh_size(endian).into() as u32;
        if is_text(in_section, endian) {
            assert!(text_end <= start);
            if text_start > start {
                text_start = start;
            }
            if text_end < end {
                text_end = end;
            }
        } else if is_data(in_section, endian) {
            assert!(data_end <= start);
            have_data = true;
            if data_start > start {
                data_start = start;
            }
            if data_end < end {
                data_end = end;
            }
        } else {
            unreachable!();
        }
    }
    assert!(text_start <= text_end);
    if have_data {
        assert!(text_end <= data_start);
        assert!(data_start <= data_end);
    }

    let machine = match in_elf.e_machine(endian) {
        elf::EM_ARM => pe::IMAGE_FILE_MACHINE_THUMB,
        elf::EM_AARCH64 => pe::IMAGE_FILE_MACHINE_ARM64,
        elf::EM_RISCV => {
            if in_elf.is_class_64() {
                pe::IMAGE_FILE_MACHINE_RISCV64
            } else {
                pe::IMAGE_FILE_MACHINE_RISCV32
            }
        }
        _ => unimplemented!(),
    };

    let mut out_data = Vec::new();
    let mut writer = object::write::pe::Writer::new(
        in_elf.is_type_64(),
        alignment as u32,
        alignment as u32,
        &mut out_data,
    );

    // Add relocations
    for in_section in in_sections.iter() {
        if let Some((rels, _)) = in_section.rel(endian, in_data)? {
            let info_index = SectionIndex(in_section.sh_info(endian) as usize);
            let info = in_sections.section(info_index)?;
            if !is_alloc(info, endian) {
                continue;
            }
            for rel in rels {
                let r_offset = rel.r_offset(endian).into() as u32;
                let r_type = rel.r_type(endian);
                match machine {
                    pe::IMAGE_FILE_MACHINE_THUMB => {
                        match r_type {
                            elf::R_ARM_PC24
                            | elf::R_ARM_REL32
                            | elf::R_ARM_THM_PC22
                            | elf::R_ARM_CALL
                            | elf::R_ARM_JUMP24
                            | elf::R_ARM_THM_JUMP24 => {
                                // Relative relocations can be ignored if relative offsets
                                // between sections are preserved.
                            }
                            elf::R_ARM_ABS32 => {
                                writer.add_reloc(r_offset, pe::IMAGE_REL_BASED_HIGHLOW);
                            }
                            _ => {
                                unimplemented!("relocation offset {:x}, type {}", r_offset, r_type);
                            }
                        }
                    }
                    _ => unimplemented!(),
                }
            }
        } else if let Some((relas, _)) = in_section.rela(endian, in_data)? {
            let info_index = SectionIndex(in_section.sh_info(endian) as usize);
            let info = in_sections.section(info_index).unwrap();
            if !is_alloc(info, endian) {
                continue;
            }
            let info_addr = info.sh_addr(endian).into();
            let info_data = info.data(endian, in_data)?;
            let mut got_address = None;
            let mut got_addresses = Vec::new();
            for rela in relas {
                let r_offset = rela.r_offset(endian).into() as u32;
                let r_type = rela.r_type(endian, is_mips64el);
                match machine {
                    pe::IMAGE_FILE_MACHINE_ARM64 => {
                        match r_type {
                            elf::R_AARCH64_PREL64
                            | elf::R_AARCH64_PREL32
                            | elf::R_AARCH64_PREL16
                            | elf::R_AARCH64_LD_PREL_LO19
                            | elf::R_AARCH64_ADR_PREL_LO21
                            | elf::R_AARCH64_ADR_PREL_PG_HI21
                            | elf::R_AARCH64_CONDBR19
                            | elf::R_AARCH64_JUMP26
                            | elf::R_AARCH64_CALL26 => {
                                // Relative relocations can be ignored if relative offsets
                                // between sections are preserved.
                            }
                            elf::R_AARCH64_ADD_ABS_LO12_NC
                            | elf::R_AARCH64_LDST8_ABS_LO12_NC
                            | elf::R_AARCH64_LDST16_ABS_LO12_NC
                            | elf::R_AARCH64_LDST32_ABS_LO12_NC
                            | elf::R_AARCH64_LDST64_ABS_LO12_NC
                            | elf::R_AARCH64_LDST128_ABS_LO12_NC => {
                                // ABS_LO12 relocations can be ignored if sections are aligned
                                // to pages.
                                assert!(alignment >= 0x1000);
                            }
                            elf::R_AARCH64_ABS64 => {
                                writer.add_reloc(r_offset, pe::IMAGE_REL_BASED_DIR64);
                            }
                            elf::R_AARCH64_ABS32 => {
                                writer.add_reloc(r_offset, pe::IMAGE_REL_BASED_HIGHLOW);
                            }
                            _ => {
                                unimplemented!("relocation offset {:x}, type {}", r_offset, r_type);
                            }
                        }
                    }
                    pe::IMAGE_FILE_MACHINE_RISCV64 => {
                        match r_type {
                            elf::R_RISCV_BRANCH
                            | elf::R_RISCV_JAL
                            | elf::R_RISCV_CALL
                            | elf::R_RISCV_CALL_PLT
                            | elf::R_RISCV_RVC_BRANCH
                            | elf::R_RISCV_RVC_JUMP
                            | elf::R_RISCV_PCREL_HI20 => {
                                // Relative relocations can be ignored if relative offsets
                                // between sections are preserved.
                            }
                            elf::R_RISCV_ADD32 | elf::R_RISCV_SUB32 => {
                                // While these are individually absolute, they appear as pairs
                                // which generate a relative value, so they can be ignored.
                            }
                            elf::R_RISCV_GOT_HI20 => {
                                // This is a relative relocation which can be ignored,
                                // but it points to an absolute value for which we won't
                                // have a relocation, so we need to generate one.
                                // (Alternatively, we could modify the code to avoid the
                                // indirection, but that's more complicated.)
                                // This relocation is paired with a R_RISCV_PCREL_LO12_I.
                                let info_offset = u64::from(r_offset).wrapping_sub(info_addr);
                                let instruction = info_data
                                    .read_at::<object::U32Bytes<Elf::Endian>>(info_offset)
                                    .unwrap()
                                    .get(endian);
                                // auipc
                                assert_eq!(instruction & 0x7f, 0x17);
                                got_address =
                                    Some(r_offset.wrapping_add(instruction & 0xffff_f000));
                            }
                            elf::R_RISCV_PCREL_LO12_I => {
                                // May be paired with R_RISCV_GOT_HI20, which requires handling.
                                if let Some(mut got_address) = got_address.take() {
                                    let info_offset = u64::from(r_offset).wrapping_sub(info_addr);
                                    let instruction = info_data
                                        .read_at::<object::U32Bytes<Elf::Endian>>(info_offset)
                                        .unwrap()
                                        .get(endian);
                                    // ld
                                    assert_eq!(instruction & 0x707f, 0x3003);
                                    got_address = got_address.wrapping_add(
                                        ((instruction & 0xfff0_0000) as i32 >> 20) as u32,
                                    );
                                    got_addresses.push(got_address);
                                }
                            }
                            elf::R_RISCV_64 => {
                                writer.add_reloc(r_offset, pe::IMAGE_REL_BASED_DIR64);
                            }
                            elf::R_RISCV_32 => {
                                writer.add_reloc(r_offset, pe::IMAGE_REL_BASED_HIGHLOW);
                            }
                            _ => {
                                unimplemented!("relocation offset {:x}, type {}", r_offset, r_type);
                            }
                        }
                    }
                    _ => unimplemented!(),
                }
            }

            got_addresses.sort_unstable();
            got_addresses.dedup();
            for got_address in got_addresses {
                writer.add_reloc(got_address, pe::IMAGE_REL_BASED_DIR64);
            }
        }
    }

    let mut section_num = 1;
    if have_data {
        section_num += 1;
    }
    if writer.has_relocs() {
        section_num += 1;
    }

    // Reserve file ranges and virtual addresses.
    writer.reserve_dos_header();
    writer.reserve_nt_headers(16);
    writer.reserve_section_headers(section_num);
    writer.reserve_virtual_until(text_start);
    let text_range = writer.reserve_text_section(text_end - text_start);
    assert_eq!(text_range.virtual_address, text_start);
    let mut data_range = Default::default();
    if have_data {
        writer.reserve_virtual_until(data_start);
        // TODO: handle bss
        data_range = writer.reserve_data_section(data_end - data_start, data_end - data_start);
        assert_eq!(data_range.virtual_address, data_start);
    }
    if writer.has_relocs() {
        writer.reserve_reloc_section();
    }

    // Start writing.
    writer.write_empty_dos_header()?;
    writer.write_nt_headers(object::write::pe::NtHeaders {
        machine,
        time_date_stamp: 0,
        characteristics: if in_elf.is_class_64() {
            pe::IMAGE_FILE_EXECUTABLE_IMAGE
                | pe::IMAGE_FILE_LINE_NUMS_STRIPPED
                | pe::IMAGE_FILE_LOCAL_SYMS_STRIPPED
                | pe::IMAGE_FILE_LARGE_ADDRESS_AWARE
        } else {
            pe::IMAGE_FILE_EXECUTABLE_IMAGE
                | pe::IMAGE_FILE_LINE_NUMS_STRIPPED
                | pe::IMAGE_FILE_LOCAL_SYMS_STRIPPED
                | pe::IMAGE_FILE_32BIT_MACHINE
        },
        major_linker_version: 0,
        minor_linker_version: 0,
        address_of_entry_point: in_elf.e_entry(endian).into() as u32,
        image_base: 0,
        major_operating_system_version: 0,
        minor_operating_system_version: 0,
        major_image_version: 0,
        minor_image_version: 0,
        major_subsystem_version: 0,
        minor_subsystem_version: 0,
        subsystem: pe::IMAGE_SUBSYSTEM_EFI_APPLICATION,
        dll_characteristics: 0,
        size_of_stack_reserve: 0,
        size_of_stack_commit: 0,
        size_of_heap_reserve: 0,
        size_of_heap_commit: 0,
    });
    writer.write_section_headers();

    writer.pad_until(text_range.file_offset);
    for in_section in in_sections.iter() {
        if !is_text(in_section, endian) {
            continue;
        }
        let offset = (in_section.sh_addr(endian).into() as u32)
            .checked_sub(text_range.virtual_address)
            .unwrap();
        writer.pad_until(text_range.file_offset + offset);
        writer.write(in_section.data(endian, in_data)?);
    }
    writer.pad_until(text_range.file_offset + text_range.file_size);
    if have_data {
        for in_section in in_sections.iter() {
            if !is_data(in_section, endian) {
                continue;
            }
            let offset = (in_section.sh_addr(endian).into() as u32)
                .checked_sub(data_range.virtual_address)
                .unwrap();
            writer.pad_until(data_range.file_offset + offset);
            writer.write(in_section.data(endian, in_data)?);
        }
        writer.pad_until(data_range.file_offset + data_range.file_size);
    }
    writer.write_reloc_section();

    debug_assert_eq!(writer.reserved_len() as usize, writer.len());

    Ok(out_data)
}

// Include both code and read only data in the text section.
fn is_text<S: SectionHeader>(s: &S, endian: S::Endian) -> bool {
    let flags = s.sh_flags(endian).into() as u32;
    flags & elf::SHF_ALLOC != 0 && (flags & elf::SHF_EXECINSTR != 0 || flags & elf::SHF_WRITE == 0)
}

// Anything that is alloc but not text.
fn is_data<S: SectionHeader>(s: &S, endian: S::Endian) -> bool {
    let flags = s.sh_flags(endian).into() as u32;
    flags & elf::SHF_ALLOC != 0 && flags & elf::SHF_EXECINSTR == 0 && flags & elf::SHF_WRITE != 0
}

fn is_alloc<S: SectionHeader>(s: &S, endian: S::Endian) -> bool {
    let flags = s.sh_flags(endian).into() as u32;
    flags & elf::SHF_ALLOC != 0
}
