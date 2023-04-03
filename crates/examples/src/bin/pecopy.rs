use std::error::Error;
use std::{env, fs, process};

use object::pe;
use object::read::coff::CoffHeader;
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader};
use object::LittleEndian as LE;

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
        object::FileKind::Pe32 => copy_file::<pe::ImageNtHeaders32>(in_data).unwrap(),
        object::FileKind::Pe64 => copy_file::<pe::ImageNtHeaders64>(in_data).unwrap(),
        _ => {
            eprintln!("Not a PE file");
            process::exit(1);
        }
    };
    if let Err(err) = fs::write(&out_file_path, out_data) {
        eprintln!("Failed to write file '{}': {}", out_file_path, err);
        process::exit(1);
    }
}

fn copy_file<Pe: ImageNtHeaders>(in_data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let in_dos_header = pe::ImageDosHeader::parse(in_data)?;
    let mut offset = in_dos_header.nt_headers_offset().into();
    let in_rich_header = object::read::pe::RichHeaderInfo::parse(in_data, offset);
    let (in_nt_headers, in_data_directories) = Pe::parse(in_data, &mut offset)?;
    let in_file_header = in_nt_headers.file_header();
    let in_optional_header = in_nt_headers.optional_header();
    let in_sections = in_file_header.sections(in_data, offset)?;

    let mut out_data = Vec::new();
    let mut writer = object::write::pe::Writer::new(
        in_nt_headers.is_type_64(),
        in_optional_header.section_alignment(),
        in_optional_header.file_alignment(),
        &mut out_data,
    );

    // Reserve file ranges and virtual addresses.
    writer.reserve_dos_header_and_stub();
    if let Some(in_rich_header) = in_rich_header.as_ref() {
        writer.reserve(in_rich_header.length as u32 + 8, 4);
    }
    writer.reserve_nt_headers(in_data_directories.len());

    // Copy data directories that don't have special handling.
    let cert_dir = in_data_directories
        .get(pe::IMAGE_DIRECTORY_ENTRY_SECURITY)
        .map(pe::ImageDataDirectory::address_range);
    let reloc_dir = in_data_directories
        .get(pe::IMAGE_DIRECTORY_ENTRY_BASERELOC)
        .map(pe::ImageDataDirectory::address_range);
    for (i, dir) in in_data_directories.iter().enumerate() {
        if dir.virtual_address.get(LE) == 0
            || i == pe::IMAGE_DIRECTORY_ENTRY_SECURITY
            || i == pe::IMAGE_DIRECTORY_ENTRY_BASERELOC
        {
            continue;
        }
        writer.set_data_directory(i, dir.virtual_address.get(LE), dir.size.get(LE));
    }

    // Determine which sections to copy.
    // We ignore any existing ".reloc" section since we recreate it ourselves.
    let mut in_sections_index = Vec::new();
    for (index, in_section) in in_sections.iter().enumerate() {
        if reloc_dir == Some(in_section.pe_address_range()) {
            continue;
        }
        in_sections_index.push(index + 1);
    }

    let mut out_sections_len = in_sections_index.len();
    if reloc_dir.is_some() {
        out_sections_len += 1;
    }
    writer.reserve_section_headers(out_sections_len as u16);

    let mut in_sections_data = Vec::new();
    for index in &in_sections_index {
        let in_section = in_sections.section(*index)?;
        let range = writer.reserve_section(
            in_section.name,
            in_section.characteristics.get(LE),
            in_section.virtual_size.get(LE),
            in_section.size_of_raw_data.get(LE),
        );
        debug_assert_eq!(range.virtual_address, in_section.virtual_address.get(LE));
        debug_assert_eq!(range.file_offset, in_section.pointer_to_raw_data.get(LE));
        debug_assert_eq!(range.file_size, in_section.size_of_raw_data.get(LE));
        in_sections_data.push((range.file_offset, in_section.pe_data(in_data)?));
    }

    if reloc_dir.is_some() {
        let mut blocks = in_data_directories
            .relocation_blocks(in_data, &in_sections)?
            .unwrap();
        while let Some(block) = blocks.next()? {
            for reloc in block {
                writer.add_reloc(reloc.virtual_address, reloc.typ);
            }
        }
        writer.reserve_reloc_section();
    }

    if let Some((_, size)) = cert_dir {
        // TODO: reserve individual certificates
        writer.reserve_certificate_table(size);
    }

    // Start writing.
    writer.write_dos_header_and_stub()?;
    if let Some(in_rich_header) = in_rich_header.as_ref() {
        // TODO: recalculate xor key
        writer.write_align(4);
        writer.write(&in_data[in_rich_header.offset..][..in_rich_header.length + 8]);
    }
    writer.write_nt_headers(object::write::pe::NtHeaders {
        machine: in_file_header.machine.get(LE),
        time_date_stamp: in_file_header.time_date_stamp.get(LE),
        characteristics: in_file_header.characteristics.get(LE),
        major_linker_version: in_optional_header.major_linker_version(),
        minor_linker_version: in_optional_header.minor_linker_version(),
        address_of_entry_point: in_optional_header.address_of_entry_point(),
        image_base: in_optional_header.image_base(),
        major_operating_system_version: in_optional_header.major_operating_system_version(),
        minor_operating_system_version: in_optional_header.minor_operating_system_version(),
        major_image_version: in_optional_header.major_image_version(),
        minor_image_version: in_optional_header.minor_image_version(),
        major_subsystem_version: in_optional_header.major_subsystem_version(),
        minor_subsystem_version: in_optional_header.minor_subsystem_version(),
        subsystem: in_optional_header.subsystem(),
        dll_characteristics: in_optional_header.dll_characteristics(),
        size_of_stack_reserve: in_optional_header.size_of_stack_reserve(),
        size_of_stack_commit: in_optional_header.size_of_stack_commit(),
        size_of_heap_reserve: in_optional_header.size_of_heap_reserve(),
        size_of_heap_commit: in_optional_header.size_of_heap_commit(),
    });
    writer.write_section_headers();
    for (offset, data) in in_sections_data {
        writer.write_section(offset, data);
    }
    writer.write_reloc_section();
    if let Some((address, size)) = cert_dir {
        // TODO: write individual certificates
        writer.write_certificate_table(&in_data[address as usize..][..size as usize]);
    }

    debug_assert_eq!(writer.reserved_len() as usize, writer.len());

    Ok(out_data)
}
