use super::*;
use object::pe::*;
use object::read::pe::*;
use object::LittleEndian as LE;
use object::{Bytes, U32Bytes, U64Bytes};

pub(super) fn print_coff(p: &mut Printer<'_>, data: &[u8]) {
    let mut offset = 0;
    if let Some(header) = ImageFileHeader::parse(data, &mut offset).print_err(p) {
        writeln!(p.w(), "Format: COFF").unwrap();
        print_file(p, header);
        let sections = header.sections(data, offset).print_err(p);
        let symbols = header.symbols(data).print_err(p);
        if let Some(ref sections) = sections {
            print_sections(p, data, header.machine.get(LE), symbols.as_ref(), &sections);
        }
        if let Some(ref symbols) = symbols {
            print_symbols(p, sections.as_ref(), &symbols);
        }
    }
}

pub(super) fn print_pe32(p: &mut Printer<'_>, data: &[u8]) {
    writeln!(p.w(), "Format: PE 32-bit").unwrap();
    print_pe::<ImageNtHeaders32>(p, data);
}

pub(super) fn print_pe64(p: &mut Printer<'_>, data: &[u8]) {
    writeln!(p.w(), "Format: PE 64-bit").unwrap();
    print_pe::<ImageNtHeaders64>(p, data);
}

fn print_pe<Pe: ImageNtHeaders>(p: &mut Printer<'_>, data: &[u8]) {
    if let Some(dos_header) = ImageDosHeader::parse(data).print_err(p) {
        p.group("ImageDosHeader", |p| {
            p.field_hex("Magic", dos_header.e_magic.get(LE));
            p.field_hex("CountBytesLastPage", dos_header.e_cblp.get(LE));
            p.field_hex("CountPages", dos_header.e_cp.get(LE));
            p.field_hex("CountRelocations", dos_header.e_crlc.get(LE));
            p.field_hex("CountHeaderParagraphs", dos_header.e_cparhdr.get(LE));
            p.field_hex("MinAllocParagraphs", dos_header.e_minalloc.get(LE));
            p.field_hex("MaxAllocParagraphs", dos_header.e_maxalloc.get(LE));
            p.field_hex("StackSegment", dos_header.e_ss.get(LE));
            p.field_hex("StackPointer", dos_header.e_sp.get(LE));
            p.field_hex("Checksum", dos_header.e_csum.get(LE));
            p.field_hex("InstructionPointer", dos_header.e_ip.get(LE));
            p.field_hex("CodeSegment", dos_header.e_cs.get(LE));
            p.field_hex("AddressOfRelocations", dos_header.e_lfarlc.get(LE));
            p.field_hex("OverlayNumber", dos_header.e_ovno.get(LE));
            p.field_hex("OemId", dos_header.e_oemid.get(LE));
            p.field_hex("OemInfo", dos_header.e_oeminfo.get(LE));
            p.field_hex("AddressOfNewHeader", dos_header.e_lfanew.get(LE));
        });
        let mut offset = dos_header.nt_headers_offset().into();
        if let Some(rich_header) = RichHeaderInfo::parse(data, offset) {
            p.group("RichHeader", |p| {
                p.field_hex("Offset", rich_header.offset);
                p.field_hex("Length", rich_header.length);
                p.field_hex("XorKey", rich_header.xor_key);
                for entry in rich_header.unmasked_entries() {
                    p.group("RichHeaderEntry", |p| {
                        p.field("ComponentId", format!("0x{:08X}", entry.comp_id));
                        p.field("Count", entry.count);
                    });
                }
            });
        }
        if let Some((nt_headers, data_directories)) = Pe::parse(data, &mut offset).print_err(p) {
            p.group("ImageNtHeaders", |p| {
                p.field_hex("Signature", nt_headers.signature());
            });
            let header = nt_headers.file_header();
            let machine = header.machine.get(LE);
            let sections = header.sections(data, offset).print_err(p);
            let symbols = header.symbols(data).print_err(p);
            print_file(p, header);
            print_optional(p, nt_headers.optional_header());
            for (index, dir) in data_directories.iter().enumerate() {
                p.group("ImageDataDirectory", |p| {
                    p.field_enum("Index", index, FLAGS_IMAGE_DIRECTORY_ENTRY);
                    p.field_hex("VirtualAddress", dir.virtual_address.get(LE));
                    p.field_hex("Size", dir.size.get(LE));
                });
            }
            if let Some(ref sections) = sections {
                print_sections(p, data, machine, symbols.as_ref(), sections);
            }
            if let Some(ref symbols) = symbols {
                print_symbols(p, sections.as_ref(), &symbols);
            }
            if let Some(ref sections) = sections {
                print_export_dir(p, data, &sections, &data_directories);
                print_import_dir::<Pe>(p, data, &sections, &data_directories);
                print_reloc_dir(p, data, machine, &sections, &data_directories);
                print_resource_dir(p, data, &sections, &data_directories);
            }
        }
    }
}

fn print_file(p: &mut Printer<'_>, header: &ImageFileHeader) {
    p.group("ImageFileHeader", |p| {
        p.field_enum("Machine", header.machine.get(LE), FLAGS_IMAGE_FILE_MACHINE);
        p.field("NumberOfSections", header.number_of_sections.get(LE));
        p.field("TimeDateStamp", header.time_date_stamp.get(LE));
        p.field_hex(
            "PointerToSymbolTable",
            header.pointer_to_symbol_table.get(LE),
        );
        p.field("NumberOfSymbols", header.number_of_symbols.get(LE));
        p.field_hex(
            "SizeOfOptionalHeader",
            header.size_of_optional_header.get(LE),
        );
        p.field_hex("Characteristics", header.characteristics.get(LE));
        p.flags(header.characteristics.get(LE), 0, FLAGS_IMAGE_FILE);
    });
}

fn print_optional(p: &mut Printer<'_>, header: &impl ImageOptionalHeader) {
    p.group("ImageOptionalHeader", |p| {
        p.field_hex("Magic", header.magic());
        p.field("MajorLinkerVersion", header.major_linker_version());
        p.field("MinorLinkerVersion", header.minor_linker_version());
        p.field_hex("SizeOfCode", header.size_of_code());
        p.field_hex("SizeOfInitializedData", header.size_of_initialized_data());
        p.field_hex(
            "SizeOfUninitializedData",
            header.size_of_uninitialized_data(),
        );
        p.field_hex("AddressOfEntryPoint", header.address_of_entry_point());
        p.field_hex("BaseOfCode", header.base_of_code());
        p.field_hex("ImageBase", header.image_base());
        p.field_hex("SectionAlignment", header.section_alignment());
        p.field_hex("FileAlignment", header.file_alignment());
        p.field(
            "MajorOperatingSystemVersion",
            header.major_operating_system_version(),
        );
        p.field(
            "MinorOperatingSystemVersion",
            header.minor_operating_system_version(),
        );
        p.field("MajorImageVersion", header.major_image_version());
        p.field("MinorImageVersion", header.minor_image_version());
        p.field("MajorSubsystemVersion", header.major_subsystem_version());
        p.field("MinorSubsystemVersion", header.minor_subsystem_version());
        p.field("Win32VersionValue", header.win32_version_value());
        p.field_hex("SizeOfImage", header.size_of_image());
        p.field_hex("SizeOfHeaders", header.size_of_headers());
        p.field_hex("CheckSum", header.check_sum());
        p.field_enum("Subsystem", header.subsystem(), FLAGS_IMAGE_SUBSYSTEM);
        p.field_hex("DllCharacteristics", header.dll_characteristics());
        p.flags(
            header.dll_characteristics(),
            0,
            FLAGS_IMAGE_DLLCHARACTERISTICS,
        );
        p.field_hex("SizeOfStackReserve", header.size_of_stack_reserve());
        p.field_hex("SizeOfStackCommit", header.size_of_stack_commit());
        p.field_hex("SizeOfHeapReserve", header.size_of_heap_reserve());
        p.field_hex("SizeOfHeapCommit", header.size_of_heap_commit());
        p.field_hex("LoaderFlags", header.loader_flags());
        p.field_hex("NumberOfRvaAndSizes", header.number_of_rva_and_sizes());
    });
}

fn print_export_dir(
    p: &mut Printer<'_>,
    data: &[u8],
    sections: &SectionTable,
    data_directories: &DataDirectories,
) -> Option<()> {
    let export_dir = data_directories
        .export_directory(data, sections)
        .print_err(p)??;
    p.group("ImageExportDirectory", |p| {
        p.field_hex("Characteristics", export_dir.characteristics.get(LE));
        p.field_hex("TimeDateStamp", export_dir.time_date_stamp.get(LE));
        p.field("MajorVersion", export_dir.major_version.get(LE));
        p.field("MinorVersion", export_dir.minor_version.get(LE));
        p.field_hex("Name", export_dir.name.get(LE));
        p.field("Base", export_dir.base.get(LE));
        p.field("NumberOfFunctions", export_dir.number_of_functions.get(LE));
        p.field("NumberOfNames", export_dir.number_of_names.get(LE));
        p.field_hex(
            "AddressOfFunctions",
            export_dir.address_of_functions.get(LE),
        );
        p.field_hex("AddressOfNames", export_dir.address_of_names.get(LE));
        p.field_hex(
            "AddressOfNameOrdinals",
            export_dir.address_of_name_ordinals.get(LE),
        );
        if let Some(Some(export_table)) = data_directories.export_table(data, sections).print_err(p)
        {
            // TODO: the order of the name pointers might be interesting?
            let mut names = vec![None; export_table.addresses().len()];
            for (name_pointer, ordinal) in export_table.name_iter() {
                if let Some(name) = names.get_mut(ordinal as usize) {
                    *name = Some(name_pointer);
                }
            }

            let ordinal_base = export_table.ordinal_base();
            for (ordinal, address) in export_table.addresses().iter().enumerate() {
                p.group("Export", |p| {
                    p.field("Ordinal", ordinal_base.wrapping_add(ordinal as u32));
                    if let Some(name_pointer) = names[ordinal] {
                        p.field_string(
                            "Name",
                            name_pointer,
                            export_table.name_from_pointer(name_pointer),
                        );
                    }
                    p.field_hex("Address", address.get(LE));
                    if let Some(target) = export_table
                        .target_from_address(address.get(LE))
                        .print_err(p)
                    {
                        match target {
                            ExportTarget::Address(_) => {}
                            ExportTarget::ForwardByOrdinal(library, ordinal) => {
                                p.field_inline_string("ForwardLibrary", library);
                                p.field("ForwardOrdinal", ordinal);
                            }
                            ExportTarget::ForwardByName(library, name) => {
                                p.field_inline_string("ForwardLibrary", library);
                                p.field_inline_string("ForwardName", name);
                            }
                        }
                    } else if let Some(Some(forward)) =
                        export_table.forward_string(address.get(LE)).print_err(p)
                    {
                        p.field_inline_string("Forward", forward);
                    }
                });
            }
        }
    });
    Some(())
}

fn print_import_dir<Pe: ImageNtHeaders>(
    p: &mut Printer<'_>,
    data: &[u8],
    sections: &SectionTable,
    data_directories: &DataDirectories,
) -> Option<()> {
    let import_table = data_directories
        .import_table(data, sections)
        .print_err(p)??;
    let mut import_descs = import_table.descriptors().print_err(p)?;
    p.group("ImageImportDirectory", |p| {
        while let Some(Some(import_desc)) = import_descs.next().print_err(p) {
            p.group("ImageImportDescriptor", |p| {
                p.field_hex("LookupTable", import_desc.original_first_thunk.get(LE));
                p.field_hex("TimeDataStamp", import_desc.time_date_stamp.get(LE));
                p.field_hex("ForwarderChain", import_desc.forwarder_chain.get(LE));
                let name = import_desc.name.get(LE);
                p.field_string("Name", name, import_table.name(name));
                p.field_hex("AddressTable", import_desc.first_thunk.get(LE));

                let mut address_thunks = import_table
                    .thunks(import_desc.first_thunk.get(LE))
                    .print_err(p);

                let mut lookup_thunks;
                let mut thunks;
                if import_desc.original_first_thunk.get(LE) != 0 {
                    lookup_thunks = import_table
                        .thunks(import_desc.original_first_thunk.get(LE))
                        .print_err(p);
                    thunks = lookup_thunks.clone();
                } else {
                    lookup_thunks = None;
                    thunks = address_thunks.clone();
                }

                if let Some(thunks) = thunks.as_mut() {
                    while let Some(Some(thunk)) = thunks.next::<Pe>().print_err(p) {
                        p.group("Thunk", |p| {
                            if let Some(Some(thunk)) = lookup_thunks
                                .as_mut()
                                .and_then(|thunks| thunks.next::<Pe>().print_err(p))
                            {
                                p.field_hex("Lookup", thunk.raw());
                            }
                            if let Some(Some(thunk)) = address_thunks
                                .as_mut()
                                .and_then(|thunks| thunks.next::<Pe>().print_err(p))
                            {
                                p.field_hex("Address", thunk.raw());
                            }
                            if thunk.is_ordinal() {
                                p.field("Ordinal", thunk.ordinal());
                            } else if let Some((hint, name)) =
                                import_table.hint_name(thunk.address()).print_err(p)
                            {
                                p.field("Hint", hint);
                                p.field_inline_string("Name", name);
                            }
                        });
                    }
                }
            });
        }
    });
    Some(())
}

fn print_resource_dir(
    p: &mut Printer<'_>,
    data: &[u8],
    sections: &SectionTable,
    data_directories: &DataDirectories,
) -> Option<()> {
    let directory = data_directories
        .resource_directory(data, sections)
        .print_err(p)??;
    let root = directory.root().print_err(p)?;
    print_resource_table(p, directory, root, 0);
    Some(())
}

fn print_resource_table(
    p: &mut Printer<'_>,
    directory: ResourceDirectory<'_>,
    table: ResourceDirectoryTable<'_>,
    level: usize,
) {
    p.group("ImageResourceDirectory", |p| {
        p.field("Characteristics", table.header.characteristics.get(LE));
        p.field("TimeDateStamp", table.header.time_date_stamp.get(LE));
        p.field("MajorVersion", table.header.major_version.get(LE));
        p.field("MinorVersion", table.header.minor_version.get(LE));
        p.field(
            "NumberOfNamedEntries",
            table.header.number_of_named_entries.get(LE),
        );
        p.field(
            "NumberOfIdEntries",
            table.header.number_of_id_entries.get(LE),
        );
        for entry in table.entries {
            p.group("ImageResourceDirectoryEntry", |p| {
                match entry.name_or_id() {
                    ResourceNameOrId::Name(name) => {
                        let offset = entry.name_or_id.get(LE);
                        if let Some(name) = name.to_string_lossy(directory).print_err(p) {
                            p.field_name("NameOrId");
                            writeln!(p.w, "\"{}\" (0x{:X})", name, offset).unwrap();
                        } else {
                            p.field_hex("NameOrId", offset);
                        }
                    }
                    ResourceNameOrId::Id(id) => {
                        if level == 0 {
                            p.field_enum("NameOrId", id, FLAGS_RT);
                        } else {
                            p.field("NameOrId", id);
                        }
                    }
                }
                p.field_hex(
                    "OffsetToDataOrDirectory",
                    entry.offset_to_data_or_directory.get(LE),
                );

                match entry.data(directory).print_err(p) {
                    Some(ResourceDirectoryEntryData::Table(table)) => {
                        print_resource_table(p, directory, table, level + 1)
                    }
                    Some(ResourceDirectoryEntryData::Data(data_entry)) => {
                        p.group("ImageResourceDataEntry", |p| {
                            p.field_hex("VirtualAddress", data_entry.offset_to_data.get(LE));
                            p.field("Size", data_entry.size.get(LE));
                            p.field("CodePage", data_entry.code_page.get(LE));
                            p.field_hex("Reserved", data_entry.reserved.get(LE));
                        });
                    }
                    None => {}
                }
            });
        }
    })
}

fn print_sections(
    p: &mut Printer<'_>,
    data: &[u8],
    machine: u16,
    symbols: Option<&SymbolTable>,
    sections: &SectionTable,
) {
    for (index, section) in sections.iter().enumerate() {
        p.group("ImageSectionHeader", |p| {
            p.field("Index", index + 1);
            if let Some(name) =
                symbols.and_then(|symbols| section.name(symbols.strings()).print_err(p))
            {
                p.field_inline_string("Name", name);
            } else {
                p.field_inline_string("Name", section.raw_name());
            }
            p.field_hex("VirtualSize", section.virtual_size.get(LE));
            p.field_hex("VirtualAddress", section.virtual_address.get(LE));
            p.field_hex("SizeOfRawData", section.size_of_raw_data.get(LE));
            p.field_hex("PointerToRawData", section.pointer_to_raw_data.get(LE));
            p.field_hex(
                "PointerToRelocations",
                section.pointer_to_relocations.get(LE),
            );
            p.field_hex(
                "PointerToLinenumbers",
                section.pointer_to_linenumbers.get(LE),
            );
            p.field("NumberOfRelocations", section.number_of_relocations.get(LE));
            p.field("NumberOfLinenumbers", section.number_of_linenumbers.get(LE));
            p.field_hex("Characteristics", section.characteristics.get(LE));
            p.flags(section.characteristics.get(LE), 0, FLAGS_IMAGE_SCN);
            // 0 means no alignment flag.
            if section.characteristics.get(LE) & IMAGE_SCN_ALIGN_MASK != 0 {
                p.flags(
                    section.characteristics.get(LE),
                    IMAGE_SCN_ALIGN_MASK,
                    FLAGS_IMAGE_SCN_ALIGN,
                );
            }
            if let Some(relocations) = section.coff_relocations(data).print_err(p) {
                for relocation in relocations {
                    p.group("ImageRelocation", |p| {
                        p.field_hex("VirtualAddress", relocation.virtual_address.get(LE));
                        let index = relocation.symbol_table_index.get(LE);
                        let name = symbols.and_then(|symbols| {
                            symbols
                                .symbol(index as usize)
                                .and_then(|symbol| symbol.name(symbols.strings()))
                                .print_err(p)
                        });
                        p.field_string_option("Symbol", index, name);
                        let proc = match machine {
                            IMAGE_FILE_MACHINE_I386 => FLAGS_IMAGE_REL_I386,
                            IMAGE_FILE_MACHINE_MIPS16
                            | IMAGE_FILE_MACHINE_MIPSFPU
                            | IMAGE_FILE_MACHINE_MIPSFPU16 => FLAGS_IMAGE_REL_MIPS,
                            IMAGE_FILE_MACHINE_ALPHA | IMAGE_FILE_MACHINE_ALPHA64 => {
                                FLAGS_IMAGE_REL_ALPHA
                            }
                            IMAGE_FILE_MACHINE_POWERPC | IMAGE_FILE_MACHINE_POWERPCFP => {
                                FLAGS_IMAGE_REL_PPC
                            }
                            IMAGE_FILE_MACHINE_SH3
                            | IMAGE_FILE_MACHINE_SH3DSP
                            | IMAGE_FILE_MACHINE_SH3E
                            | IMAGE_FILE_MACHINE_SH4
                            | IMAGE_FILE_MACHINE_SH5 => FLAGS_IMAGE_REL_SH,
                            IMAGE_FILE_MACHINE_ARM => FLAGS_IMAGE_REL_ARM,
                            IMAGE_FILE_MACHINE_AM33 => FLAGS_IMAGE_REL_AM,
                            IMAGE_FILE_MACHINE_ARM64 => FLAGS_IMAGE_REL_ARM64,
                            IMAGE_FILE_MACHINE_AMD64 => FLAGS_IMAGE_REL_AMD64,
                            IMAGE_FILE_MACHINE_IA64 => FLAGS_IMAGE_REL_IA64,
                            IMAGE_FILE_MACHINE_CEF => FLAGS_IMAGE_REL_CEF,
                            IMAGE_FILE_MACHINE_CEE => FLAGS_IMAGE_REL_CEE,
                            IMAGE_FILE_MACHINE_M32R => FLAGS_IMAGE_REL_M32R,
                            IMAGE_FILE_MACHINE_EBC => FLAGS_IMAGE_REL_EBC,
                            _ => &[],
                        };
                        let typ = relocation.typ.get(LE);
                        p.field_enum("Type", typ, proc);
                        match machine {
                            IMAGE_FILE_MACHINE_POWERPC | IMAGE_FILE_MACHINE_POWERPCFP => {
                                p.flags(typ, 0, FLAGS_IMAGE_REL_PPC_BITS)
                            }
                            IMAGE_FILE_MACHINE_SH3
                            | IMAGE_FILE_MACHINE_SH3DSP
                            | IMAGE_FILE_MACHINE_SH3E
                            | IMAGE_FILE_MACHINE_SH4
                            | IMAGE_FILE_MACHINE_SH5 => p.flags(typ, 0, FLAGS_IMAGE_REL_SH_BITS),
                            _ => {}
                        }
                    });
                }
            }
        });
    }
}

fn print_symbols(p: &mut Printer<'_>, sections: Option<&SectionTable>, symbols: &SymbolTable) {
    for (index, symbol) in symbols.iter() {
        p.group("ImageSymbol", |p| {
            p.field("Index", index);
            if let Some(name) = symbol.name(symbols.strings()).print_err(p) {
                p.field_inline_string("Name", name);
            } else {
                p.field("Name", format!("{:X?}", symbol.name));
            }
            p.field_hex("Value", symbol.value.get(LE));
            let section = symbol.section_number.get(LE);
            if section == 0 || section >= IMAGE_SYM_SECTION_MAX {
                p.field_enum("Section", section, FLAGS_IMAGE_SYM);
            } else {
                let section_name = sections.and_then(|sections| {
                    sections
                        .section(section.into())
                        .and_then(|section| section.name(symbols.strings()))
                        .print_err(p)
                });
                p.field_string_option("Section", section, section_name);
            }
            p.field_hex("Type", symbol.typ.get(LE));
            p.field_enum("BaseType", symbol.base_type(), FLAGS_IMAGE_SYM_TYPE);
            p.field_enum("DerivedType", symbol.derived_type(), FLAGS_IMAGE_SYM_DTYPE);
            p.field_enum("StorageClass", symbol.storage_class, FLAGS_IMAGE_SYM_CLASS);
            p.field_hex("NumberOfAuxSymbols", symbol.number_of_aux_symbols);
            if symbol.has_aux_file_name() {
                if let Some(name) = symbols
                    .aux_file_name(index, symbol.number_of_aux_symbols)
                    .print_err(p)
                {
                    p.group("ImageAuxSymbolFile", |p| {
                        p.field_inline_string("Name", name);
                    });
                }
            } else if symbol.has_aux_function() {
                if let Some(aux) = symbols.aux_function(index).print_err(p) {
                    p.group("ImageAuxSymbolFunction", |p| {
                        p.field("TagIndex", aux.tag_index.get(LE));
                        p.field("TotalSize", aux.total_size.get(LE));
                        p.field_hex("PointerToLinenumber", aux.pointer_to_linenumber.get(LE));
                        p.field(
                            "PointerToNextFunction",
                            aux.pointer_to_next_function.get(LE),
                        );
                        p.field("Unused", format!("{:X?}", aux.unused));
                    });
                }
            } else if symbol.has_aux_section() {
                if let Some(aux) = symbols.aux_section(index).print_err(p) {
                    p.group("ImageAuxSymbolSection", |p| {
                        p.field_hex("Length", aux.length.get(LE));
                        p.field("NumberOfRelocations", aux.number_of_relocations.get(LE));
                        p.field("NumberOfLinenumbers", aux.number_of_linenumbers.get(LE));
                        p.field_hex("CheckSum", aux.check_sum.get(LE));
                        p.field("Number", aux.number.get(LE));
                        p.field_enum("Selection", aux.selection, FLAGS_IMAGE_COMDAT_SELECT);
                        p.field_hex("Reserved", aux.reserved);
                        p.field("HighNumber", aux.high_number.get(LE));
                    });
                }
            }
            // TODO: ImageAuxSymbolFunctionBeginEnd
            // TODO: ImageAuxSymbolWeak
        });
    }
}

fn print_reloc_dir(
    p: &mut Printer<'_>,
    data: &[u8],
    machine: u16,
    sections: &SectionTable,
    data_directories: &DataDirectories,
) -> Option<()> {
    let proc = match machine {
        IMAGE_FILE_MACHINE_IA64 => FLAGS_IMAGE_REL_IA64_BASED,
        IMAGE_FILE_MACHINE_MIPS16 | IMAGE_FILE_MACHINE_MIPSFPU | IMAGE_FILE_MACHINE_MIPSFPU16 => {
            FLAGS_IMAGE_REL_MIPS_BASED
        }
        IMAGE_FILE_MACHINE_ARM => FLAGS_IMAGE_REL_ARM_BASED,
        IMAGE_FILE_MACHINE_RISCV32 | IMAGE_FILE_MACHINE_RISCV64 | IMAGE_FILE_MACHINE_RISCV128 => {
            FLAGS_IMAGE_REL_RISCV_BASED
        }
        _ => &[],
    };
    let mut blocks = data_directories
        .relocation_blocks(data, sections)
        .print_err(p)??;
    while let Some(block) = blocks.next().print_err(p)? {
        let block_address = block.virtual_address();
        let block_data = sections.pe_data_at(data, block_address).map(Bytes);
        for reloc in block {
            p.group("ImageBaseRelocation", |p| {
                p.field_hex("VirtualAddress", reloc.virtual_address);
                p.field_enums("Type", reloc.typ, &[proc, FLAGS_IMAGE_REL_BASED]);
                let offset = (reloc.virtual_address - block_address) as usize;
                if let Some(addend) = match reloc.typ {
                    IMAGE_REL_BASED_HIGHLOW => block_data
                        .and_then(|data| data.read_at::<U32Bytes<LE>>(offset).ok())
                        .map(|addend| u64::from(addend.get(LE))),
                    IMAGE_REL_BASED_DIR64 => block_data
                        .and_then(|data| data.read_at::<U64Bytes<LE>>(offset).ok())
                        .map(|addend| addend.get(LE)),
                    _ => None,
                } {
                    p.field_hex("Addend", addend);
                }
            });
        }
    }
    Some(())
}

static FLAGS_IMAGE_FILE: &[Flag<u16>] = &flags!(
    IMAGE_FILE_RELOCS_STRIPPED,
    IMAGE_FILE_EXECUTABLE_IMAGE,
    IMAGE_FILE_LINE_NUMS_STRIPPED,
    IMAGE_FILE_LOCAL_SYMS_STRIPPED,
    IMAGE_FILE_AGGRESIVE_WS_TRIM,
    IMAGE_FILE_LARGE_ADDRESS_AWARE,
    IMAGE_FILE_BYTES_REVERSED_LO,
    IMAGE_FILE_32BIT_MACHINE,
    IMAGE_FILE_DEBUG_STRIPPED,
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,
    IMAGE_FILE_NET_RUN_FROM_SWAP,
    IMAGE_FILE_SYSTEM,
    IMAGE_FILE_DLL,
    IMAGE_FILE_UP_SYSTEM_ONLY,
    IMAGE_FILE_BYTES_REVERSED_HI,
);
static FLAGS_IMAGE_FILE_MACHINE: &[Flag<u16>] = &flags!(
    IMAGE_FILE_MACHINE_UNKNOWN,
    IMAGE_FILE_MACHINE_TARGET_HOST,
    IMAGE_FILE_MACHINE_I386,
    IMAGE_FILE_MACHINE_R3000,
    IMAGE_FILE_MACHINE_R4000,
    IMAGE_FILE_MACHINE_R10000,
    IMAGE_FILE_MACHINE_WCEMIPSV2,
    IMAGE_FILE_MACHINE_ALPHA,
    IMAGE_FILE_MACHINE_SH3,
    IMAGE_FILE_MACHINE_SH3DSP,
    IMAGE_FILE_MACHINE_SH3E,
    IMAGE_FILE_MACHINE_SH4,
    IMAGE_FILE_MACHINE_SH5,
    IMAGE_FILE_MACHINE_ARM,
    IMAGE_FILE_MACHINE_THUMB,
    IMAGE_FILE_MACHINE_ARMNT,
    IMAGE_FILE_MACHINE_AM33,
    IMAGE_FILE_MACHINE_POWERPC,
    IMAGE_FILE_MACHINE_POWERPCFP,
    IMAGE_FILE_MACHINE_IA64,
    IMAGE_FILE_MACHINE_MIPS16,
    IMAGE_FILE_MACHINE_ALPHA64,
    IMAGE_FILE_MACHINE_MIPSFPU,
    IMAGE_FILE_MACHINE_MIPSFPU16,
    IMAGE_FILE_MACHINE_AXP64,
    IMAGE_FILE_MACHINE_TRICORE,
    IMAGE_FILE_MACHINE_CEF,
    IMAGE_FILE_MACHINE_EBC,
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_M32R,
    IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_CEE,
    IMAGE_FILE_MACHINE_RISCV32,
    IMAGE_FILE_MACHINE_RISCV64,
    IMAGE_FILE_MACHINE_RISCV128,
);
static FLAGS_IMAGE_SCN: &[Flag<u32>] = &flags!(
    IMAGE_SCN_TYPE_NO_PAD,
    IMAGE_SCN_CNT_CODE,
    IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA,
    IMAGE_SCN_LNK_OTHER,
    IMAGE_SCN_LNK_INFO,
    IMAGE_SCN_LNK_REMOVE,
    IMAGE_SCN_LNK_COMDAT,
    IMAGE_SCN_NO_DEFER_SPEC_EXC,
    IMAGE_SCN_GPREL,
    IMAGE_SCN_MEM_FARDATA,
    IMAGE_SCN_MEM_PURGEABLE,
    IMAGE_SCN_MEM_16BIT,
    IMAGE_SCN_MEM_LOCKED,
    IMAGE_SCN_MEM_PRELOAD,
    IMAGE_SCN_LNK_NRELOC_OVFL,
    IMAGE_SCN_MEM_DISCARDABLE,
    IMAGE_SCN_MEM_NOT_CACHED,
    IMAGE_SCN_MEM_NOT_PAGED,
    IMAGE_SCN_MEM_SHARED,
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE,
);
static FLAGS_IMAGE_SCN_ALIGN: &[Flag<u32>] = &flags!(
    IMAGE_SCN_ALIGN_1BYTES,
    IMAGE_SCN_ALIGN_2BYTES,
    IMAGE_SCN_ALIGN_4BYTES,
    IMAGE_SCN_ALIGN_8BYTES,
    IMAGE_SCN_ALIGN_16BYTES,
    IMAGE_SCN_ALIGN_32BYTES,
    IMAGE_SCN_ALIGN_64BYTES,
    IMAGE_SCN_ALIGN_128BYTES,
    IMAGE_SCN_ALIGN_256BYTES,
    IMAGE_SCN_ALIGN_512BYTES,
    IMAGE_SCN_ALIGN_1024BYTES,
    IMAGE_SCN_ALIGN_2048BYTES,
    IMAGE_SCN_ALIGN_4096BYTES,
    IMAGE_SCN_ALIGN_8192BYTES,
);
static FLAGS_IMAGE_REL_I386: &[Flag<u16>] = &flags!(
    IMAGE_REL_I386_ABSOLUTE,
    IMAGE_REL_I386_DIR16,
    IMAGE_REL_I386_REL16,
    IMAGE_REL_I386_DIR32,
    IMAGE_REL_I386_DIR32NB,
    IMAGE_REL_I386_SEG12,
    IMAGE_REL_I386_SECTION,
    IMAGE_REL_I386_SECREL,
    IMAGE_REL_I386_TOKEN,
    IMAGE_REL_I386_SECREL7,
    IMAGE_REL_I386_REL32,
);
static FLAGS_IMAGE_REL_MIPS: &[Flag<u16>] = &flags!(
    IMAGE_REL_MIPS_ABSOLUTE,
    IMAGE_REL_MIPS_REFHALF,
    IMAGE_REL_MIPS_REFWORD,
    IMAGE_REL_MIPS_JMPADDR,
    IMAGE_REL_MIPS_REFHI,
    IMAGE_REL_MIPS_REFLO,
    IMAGE_REL_MIPS_GPREL,
    IMAGE_REL_MIPS_LITERAL,
    IMAGE_REL_MIPS_SECTION,
    IMAGE_REL_MIPS_SECREL,
    IMAGE_REL_MIPS_SECRELLO,
    IMAGE_REL_MIPS_SECRELHI,
    IMAGE_REL_MIPS_TOKEN,
    IMAGE_REL_MIPS_JMPADDR16,
    IMAGE_REL_MIPS_REFWORDNB,
    IMAGE_REL_MIPS_PAIR,
);
static FLAGS_IMAGE_REL_ALPHA: &[Flag<u16>] = &flags!(
    IMAGE_REL_ALPHA_ABSOLUTE,
    IMAGE_REL_ALPHA_REFLONG,
    IMAGE_REL_ALPHA_REFQUAD,
    IMAGE_REL_ALPHA_GPREL32,
    IMAGE_REL_ALPHA_LITERAL,
    IMAGE_REL_ALPHA_LITUSE,
    IMAGE_REL_ALPHA_GPDISP,
    IMAGE_REL_ALPHA_BRADDR,
    IMAGE_REL_ALPHA_HINT,
    IMAGE_REL_ALPHA_INLINE_REFLONG,
    IMAGE_REL_ALPHA_REFHI,
    IMAGE_REL_ALPHA_REFLO,
    IMAGE_REL_ALPHA_PAIR,
    IMAGE_REL_ALPHA_MATCH,
    IMAGE_REL_ALPHA_SECTION,
    IMAGE_REL_ALPHA_SECREL,
    IMAGE_REL_ALPHA_REFLONGNB,
    IMAGE_REL_ALPHA_SECRELLO,
    IMAGE_REL_ALPHA_SECRELHI,
    IMAGE_REL_ALPHA_REFQ3,
    IMAGE_REL_ALPHA_REFQ2,
    IMAGE_REL_ALPHA_REFQ1,
    IMAGE_REL_ALPHA_GPRELLO,
    IMAGE_REL_ALPHA_GPRELHI,
);
static FLAGS_IMAGE_REL_PPC: &[Flag<u16>] = &flags!(
    IMAGE_REL_PPC_ABSOLUTE,
    IMAGE_REL_PPC_ADDR64,
    IMAGE_REL_PPC_ADDR32,
    IMAGE_REL_PPC_ADDR24,
    IMAGE_REL_PPC_ADDR16,
    IMAGE_REL_PPC_ADDR14,
    IMAGE_REL_PPC_REL24,
    IMAGE_REL_PPC_REL14,
    IMAGE_REL_PPC_TOCREL16,
    IMAGE_REL_PPC_TOCREL14,
    IMAGE_REL_PPC_ADDR32NB,
    IMAGE_REL_PPC_SECREL,
    IMAGE_REL_PPC_SECTION,
    IMAGE_REL_PPC_IFGLUE,
    IMAGE_REL_PPC_IMGLUE,
    IMAGE_REL_PPC_SECREL16,
    IMAGE_REL_PPC_REFHI,
    IMAGE_REL_PPC_REFLO,
    IMAGE_REL_PPC_PAIR,
    IMAGE_REL_PPC_SECRELLO,
    IMAGE_REL_PPC_SECRELHI,
    IMAGE_REL_PPC_GPREL,
    IMAGE_REL_PPC_TOKEN,
);
static FLAGS_IMAGE_REL_PPC_BITS: &[Flag<u16>] = &flags!(
    IMAGE_REL_PPC_NEG,
    IMAGE_REL_PPC_BRTAKEN,
    IMAGE_REL_PPC_BRNTAKEN,
    IMAGE_REL_PPC_TOCDEFN,
);
static FLAGS_IMAGE_REL_SH: &[Flag<u16>] = &flags!(
    IMAGE_REL_SH3_ABSOLUTE,
    IMAGE_REL_SH3_DIRECT16,
    IMAGE_REL_SH3_DIRECT32,
    IMAGE_REL_SH3_DIRECT8,
    IMAGE_REL_SH3_DIRECT8_WORD,
    IMAGE_REL_SH3_DIRECT8_LONG,
    IMAGE_REL_SH3_DIRECT4,
    IMAGE_REL_SH3_DIRECT4_WORD,
    IMAGE_REL_SH3_DIRECT4_LONG,
    IMAGE_REL_SH3_PCREL8_WORD,
    IMAGE_REL_SH3_PCREL8_LONG,
    IMAGE_REL_SH3_PCREL12_WORD,
    IMAGE_REL_SH3_STARTOF_SECTION,
    IMAGE_REL_SH3_SIZEOF_SECTION,
    IMAGE_REL_SH3_SECTION,
    IMAGE_REL_SH3_SECREL,
    IMAGE_REL_SH3_DIRECT32_NB,
    IMAGE_REL_SH3_GPREL4_LONG,
    IMAGE_REL_SH3_TOKEN,
    IMAGE_REL_SHM_PCRELPT,
    IMAGE_REL_SHM_REFLO,
    IMAGE_REL_SHM_REFHALF,
    IMAGE_REL_SHM_RELLO,
    IMAGE_REL_SHM_RELHALF,
    IMAGE_REL_SHM_PAIR,
);
static FLAGS_IMAGE_REL_SH_BITS: &[Flag<u16>] = &flags!(IMAGE_REL_SH_NOMODE,);
static FLAGS_IMAGE_REL_ARM: &[Flag<u16>] = &flags!(
    IMAGE_REL_ARM_ABSOLUTE,
    IMAGE_REL_ARM_ADDR32,
    IMAGE_REL_ARM_ADDR32NB,
    IMAGE_REL_ARM_BRANCH24,
    IMAGE_REL_ARM_BRANCH11,
    IMAGE_REL_ARM_TOKEN,
    IMAGE_REL_ARM_GPREL12,
    IMAGE_REL_ARM_GPREL7,
    IMAGE_REL_ARM_BLX24,
    IMAGE_REL_ARM_BLX11,
    IMAGE_REL_ARM_SECTION,
    IMAGE_REL_ARM_SECREL,
    IMAGE_REL_ARM_MOV32A,
    IMAGE_REL_ARM_MOV32T,
    IMAGE_REL_ARM_BRANCH20T,
    IMAGE_REL_ARM_BRANCH24T,
    IMAGE_REL_ARM_BLX23T,
);
static FLAGS_IMAGE_REL_AM: &[Flag<u16>] = &flags!(
    IMAGE_REL_AM_ABSOLUTE,
    IMAGE_REL_AM_ADDR32,
    IMAGE_REL_AM_ADDR32NB,
    IMAGE_REL_AM_CALL32,
    IMAGE_REL_AM_FUNCINFO,
    IMAGE_REL_AM_REL32_1,
    IMAGE_REL_AM_REL32_2,
    IMAGE_REL_AM_SECREL,
    IMAGE_REL_AM_SECTION,
    IMAGE_REL_AM_TOKEN,
);
static FLAGS_IMAGE_REL_ARM64: &[Flag<u16>] = &flags!(
    IMAGE_REL_ARM64_ABSOLUTE,
    IMAGE_REL_ARM64_ADDR32,
    IMAGE_REL_ARM64_ADDR32NB,
    IMAGE_REL_ARM64_BRANCH26,
    IMAGE_REL_ARM64_PAGEBASE_REL21,
    IMAGE_REL_ARM64_REL21,
    IMAGE_REL_ARM64_PAGEOFFSET_12A,
    IMAGE_REL_ARM64_PAGEOFFSET_12L,
    IMAGE_REL_ARM64_SECREL,
    IMAGE_REL_ARM64_SECREL_LOW12A,
    IMAGE_REL_ARM64_SECREL_HIGH12A,
    IMAGE_REL_ARM64_SECREL_LOW12L,
    IMAGE_REL_ARM64_TOKEN,
    IMAGE_REL_ARM64_SECTION,
    IMAGE_REL_ARM64_ADDR64,
    IMAGE_REL_ARM64_BRANCH19,
);
static FLAGS_IMAGE_REL_AMD64: &[Flag<u16>] = &flags!(
    IMAGE_REL_AMD64_ABSOLUTE,
    IMAGE_REL_AMD64_ADDR64,
    IMAGE_REL_AMD64_ADDR32,
    IMAGE_REL_AMD64_ADDR32NB,
    IMAGE_REL_AMD64_REL32,
    IMAGE_REL_AMD64_REL32_1,
    IMAGE_REL_AMD64_REL32_2,
    IMAGE_REL_AMD64_REL32_3,
    IMAGE_REL_AMD64_REL32_4,
    IMAGE_REL_AMD64_REL32_5,
    IMAGE_REL_AMD64_SECTION,
    IMAGE_REL_AMD64_SECREL,
    IMAGE_REL_AMD64_SECREL7,
    IMAGE_REL_AMD64_TOKEN,
    IMAGE_REL_AMD64_SREL32,
    IMAGE_REL_AMD64_PAIR,
    IMAGE_REL_AMD64_SSPAN32,
    IMAGE_REL_AMD64_EHANDLER,
    IMAGE_REL_AMD64_IMPORT_BR,
    IMAGE_REL_AMD64_IMPORT_CALL,
    IMAGE_REL_AMD64_CFG_BR,
    IMAGE_REL_AMD64_CFG_BR_REX,
    IMAGE_REL_AMD64_CFG_CALL,
    IMAGE_REL_AMD64_INDIR_BR,
    IMAGE_REL_AMD64_INDIR_BR_REX,
    IMAGE_REL_AMD64_INDIR_CALL,
    IMAGE_REL_AMD64_INDIR_BR_SWITCHTABLE_FIRST,
    IMAGE_REL_AMD64_INDIR_BR_SWITCHTABLE_LAST,
);
static FLAGS_IMAGE_REL_IA64: &[Flag<u16>] = &flags!(
    IMAGE_REL_IA64_ABSOLUTE,
    IMAGE_REL_IA64_IMM14,
    IMAGE_REL_IA64_IMM22,
    IMAGE_REL_IA64_IMM64,
    IMAGE_REL_IA64_DIR32,
    IMAGE_REL_IA64_DIR64,
    IMAGE_REL_IA64_PCREL21B,
    IMAGE_REL_IA64_PCREL21M,
    IMAGE_REL_IA64_PCREL21F,
    IMAGE_REL_IA64_GPREL22,
    IMAGE_REL_IA64_LTOFF22,
    IMAGE_REL_IA64_SECTION,
    IMAGE_REL_IA64_SECREL22,
    IMAGE_REL_IA64_SECREL64I,
    IMAGE_REL_IA64_SECREL32,
    IMAGE_REL_IA64_DIR32NB,
    IMAGE_REL_IA64_SREL14,
    IMAGE_REL_IA64_SREL22,
    IMAGE_REL_IA64_SREL32,
    IMAGE_REL_IA64_UREL32,
    IMAGE_REL_IA64_PCREL60X,
    IMAGE_REL_IA64_PCREL60B,
    IMAGE_REL_IA64_PCREL60F,
    IMAGE_REL_IA64_PCREL60I,
    IMAGE_REL_IA64_PCREL60M,
    IMAGE_REL_IA64_IMMGPREL64,
    IMAGE_REL_IA64_TOKEN,
    IMAGE_REL_IA64_GPREL32,
    IMAGE_REL_IA64_ADDEND,
);
static FLAGS_IMAGE_REL_CEF: &[Flag<u16>] = &flags!(
    IMAGE_REL_CEF_ABSOLUTE,
    IMAGE_REL_CEF_ADDR32,
    IMAGE_REL_CEF_ADDR64,
    IMAGE_REL_CEF_ADDR32NB,
    IMAGE_REL_CEF_SECTION,
    IMAGE_REL_CEF_SECREL,
    IMAGE_REL_CEF_TOKEN,
);
static FLAGS_IMAGE_REL_CEE: &[Flag<u16>] = &flags!(
    IMAGE_REL_CEE_ABSOLUTE,
    IMAGE_REL_CEE_ADDR32,
    IMAGE_REL_CEE_ADDR64,
    IMAGE_REL_CEE_ADDR32NB,
    IMAGE_REL_CEE_SECTION,
    IMAGE_REL_CEE_SECREL,
    IMAGE_REL_CEE_TOKEN,
);
static FLAGS_IMAGE_REL_M32R: &[Flag<u16>] = &flags!(
    IMAGE_REL_M32R_ABSOLUTE,
    IMAGE_REL_M32R_ADDR32,
    IMAGE_REL_M32R_ADDR32NB,
    IMAGE_REL_M32R_ADDR24,
    IMAGE_REL_M32R_GPREL16,
    IMAGE_REL_M32R_PCREL24,
    IMAGE_REL_M32R_PCREL16,
    IMAGE_REL_M32R_PCREL8,
    IMAGE_REL_M32R_REFHALF,
    IMAGE_REL_M32R_REFHI,
    IMAGE_REL_M32R_REFLO,
    IMAGE_REL_M32R_PAIR,
    IMAGE_REL_M32R_SECTION,
    IMAGE_REL_M32R_SECREL32,
    IMAGE_REL_M32R_TOKEN,
);
static FLAGS_IMAGE_REL_EBC: &[Flag<u16>] = &flags!(
    IMAGE_REL_EBC_ABSOLUTE,
    IMAGE_REL_EBC_ADDR32NB,
    IMAGE_REL_EBC_REL32,
    IMAGE_REL_EBC_SECTION,
    IMAGE_REL_EBC_SECREL,
);
static FLAGS_IMAGE_SYM: &[Flag<u16>] =
    &flags!(IMAGE_SYM_UNDEFINED, IMAGE_SYM_ABSOLUTE, IMAGE_SYM_DEBUG,);
static FLAGS_IMAGE_SYM_TYPE: &[Flag<u16>] = &flags!(
    IMAGE_SYM_TYPE_NULL,
    IMAGE_SYM_TYPE_VOID,
    IMAGE_SYM_TYPE_CHAR,
    IMAGE_SYM_TYPE_SHORT,
    IMAGE_SYM_TYPE_INT,
    IMAGE_SYM_TYPE_LONG,
    IMAGE_SYM_TYPE_FLOAT,
    IMAGE_SYM_TYPE_DOUBLE,
    IMAGE_SYM_TYPE_STRUCT,
    IMAGE_SYM_TYPE_UNION,
    IMAGE_SYM_TYPE_ENUM,
    IMAGE_SYM_TYPE_MOE,
    IMAGE_SYM_TYPE_BYTE,
    IMAGE_SYM_TYPE_WORD,
    IMAGE_SYM_TYPE_UINT,
    IMAGE_SYM_TYPE_DWORD,
    IMAGE_SYM_TYPE_PCODE,
);
static FLAGS_IMAGE_SYM_DTYPE: &[Flag<u16>] = &flags!(
    IMAGE_SYM_DTYPE_NULL,
    IMAGE_SYM_DTYPE_POINTER,
    IMAGE_SYM_DTYPE_FUNCTION,
    IMAGE_SYM_DTYPE_ARRAY,
);
static FLAGS_IMAGE_SYM_CLASS: &[Flag<u8>] = &flags!(
    IMAGE_SYM_CLASS_END_OF_FUNCTION,
    IMAGE_SYM_CLASS_NULL,
    IMAGE_SYM_CLASS_AUTOMATIC,
    IMAGE_SYM_CLASS_EXTERNAL,
    IMAGE_SYM_CLASS_STATIC,
    IMAGE_SYM_CLASS_REGISTER,
    IMAGE_SYM_CLASS_EXTERNAL_DEF,
    IMAGE_SYM_CLASS_LABEL,
    IMAGE_SYM_CLASS_UNDEFINED_LABEL,
    IMAGE_SYM_CLASS_MEMBER_OF_STRUCT,
    IMAGE_SYM_CLASS_ARGUMENT,
    IMAGE_SYM_CLASS_STRUCT_TAG,
    IMAGE_SYM_CLASS_MEMBER_OF_UNION,
    IMAGE_SYM_CLASS_UNION_TAG,
    IMAGE_SYM_CLASS_TYPE_DEFINITION,
    IMAGE_SYM_CLASS_UNDEFINED_STATIC,
    IMAGE_SYM_CLASS_ENUM_TAG,
    IMAGE_SYM_CLASS_MEMBER_OF_ENUM,
    IMAGE_SYM_CLASS_REGISTER_PARAM,
    IMAGE_SYM_CLASS_BIT_FIELD,
    IMAGE_SYM_CLASS_FAR_EXTERNAL,
    IMAGE_SYM_CLASS_BLOCK,
    IMAGE_SYM_CLASS_FUNCTION,
    IMAGE_SYM_CLASS_END_OF_STRUCT,
    IMAGE_SYM_CLASS_FILE,
    IMAGE_SYM_CLASS_SECTION,
    IMAGE_SYM_CLASS_WEAK_EXTERNAL,
    IMAGE_SYM_CLASS_CLR_TOKEN,
);
static FLAGS_IMAGE_COMDAT_SELECT: &[Flag<u8>] = &flags!(
    IMAGE_COMDAT_SELECT_NODUPLICATES,
    IMAGE_COMDAT_SELECT_ANY,
    IMAGE_COMDAT_SELECT_SAME_SIZE,
    IMAGE_COMDAT_SELECT_EXACT_MATCH,
    IMAGE_COMDAT_SELECT_ASSOCIATIVE,
    IMAGE_COMDAT_SELECT_LARGEST,
    IMAGE_COMDAT_SELECT_NEWEST,
);
static FLAGS_IMAGE_SUBSYSTEM: &[Flag<u16>] = &flags!(
    IMAGE_SUBSYSTEM_UNKNOWN,
    IMAGE_SUBSYSTEM_NATIVE,
    IMAGE_SUBSYSTEM_WINDOWS_GUI,
    IMAGE_SUBSYSTEM_WINDOWS_CUI,
    IMAGE_SUBSYSTEM_OS2_CUI,
    IMAGE_SUBSYSTEM_POSIX_CUI,
    IMAGE_SUBSYSTEM_NATIVE_WINDOWS,
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI,
    IMAGE_SUBSYSTEM_EFI_APPLICATION,
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER,
    IMAGE_SUBSYSTEM_EFI_ROM,
    IMAGE_SUBSYSTEM_XBOX,
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION,
    IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG,
);
static FLAGS_IMAGE_DLLCHARACTERISTICS: &[Flag<u16>] = &flags!(
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
    IMAGE_DLLCHARACTERISTICS_NO_SEH,
    IMAGE_DLLCHARACTERISTICS_NO_BIND,
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER,
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,
    IMAGE_DLLCHARACTERISTICS_GUARD_CF,
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,
);
static FLAGS_IMAGE_DIRECTORY_ENTRY: &[Flag<usize>] = &flags!(
    IMAGE_DIRECTORY_ENTRY_EXPORT,
    IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_RESOURCE,
    IMAGE_DIRECTORY_ENTRY_EXCEPTION,
    IMAGE_DIRECTORY_ENTRY_SECURITY,
    IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_DIRECTORY_ENTRY_DEBUG,
    IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,
    IMAGE_DIRECTORY_ENTRY_GLOBALPTR,
    IMAGE_DIRECTORY_ENTRY_TLS,
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
    IMAGE_DIRECTORY_ENTRY_IAT,
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
);
static FLAGS_IMAGE_REL_BASED: &[Flag<u16>] = &flags!(
    IMAGE_REL_BASED_ABSOLUTE,
    IMAGE_REL_BASED_HIGH,
    IMAGE_REL_BASED_LOW,
    IMAGE_REL_BASED_HIGHLOW,
    IMAGE_REL_BASED_HIGHADJ,
    IMAGE_REL_BASED_MACHINE_SPECIFIC_5,
    IMAGE_REL_BASED_RESERVED,
    IMAGE_REL_BASED_MACHINE_SPECIFIC_7,
    IMAGE_REL_BASED_MACHINE_SPECIFIC_8,
    IMAGE_REL_BASED_MACHINE_SPECIFIC_9,
    IMAGE_REL_BASED_DIR64,
);
static FLAGS_IMAGE_REL_IA64_BASED: &[Flag<u16>] = &flags!(IMAGE_REL_BASED_IA64_IMM64,);
static FLAGS_IMAGE_REL_MIPS_BASED: &[Flag<u16>] =
    &flags!(IMAGE_REL_BASED_MIPS_JMPADDR, IMAGE_REL_BASED_MIPS_JMPADDR16,);
static FLAGS_IMAGE_REL_ARM_BASED: &[Flag<u16>] =
    &flags!(IMAGE_REL_BASED_ARM_MOV32, IMAGE_REL_BASED_THUMB_MOV32,);
static FLAGS_IMAGE_REL_RISCV_BASED: &[Flag<u16>] = &flags!(
    IMAGE_REL_BASED_RISCV_HIGH20,
    IMAGE_REL_BASED_RISCV_LOW12I,
    IMAGE_REL_BASED_RISCV_LOW12S,
);
static FLAGS_RT: &[Flag<u16>] = &flags!(
    RT_CURSOR,
    RT_BITMAP,
    RT_ICON,
    RT_MENU,
    RT_DIALOG,
    RT_STRING,
    RT_FONTDIR,
    RT_FONT,
    RT_ACCELERATOR,
    RT_RCDATA,
    RT_MESSAGETABLE,
    RT_GROUP_CURSOR,
    RT_GROUP_ICON,
    RT_VERSION,
    RT_DLGINCLUDE,
    RT_PLUGPLAY,
    RT_VXD,
    RT_ANICURSOR,
    RT_ANIICON,
    RT_HTML,
    RT_MANIFEST,
);
