use super::*;
use object::macho::*;
use object::read::macho::*;
use object::BigEndian;

pub(super) fn print_dyld_cache(p: &mut Printer<'_>, data: &[u8]) {
    if let Some(header) = DyldCacheHeader::<Endianness>::parse(data).print_err(p) {
        if let Some((_, endian)) = header.parse_magic().print_err(p) {
            print_dyld_cache_header(p, endian, header);
            let mappings = header.mappings(endian, data).print_err(p);
            if let Some(mappings) = &mappings {
                print_dyld_cache_mappings(p, mappings);
            }
            if let Some(images) = header.images(endian, data).print_err(p) {
                print_dyld_cache_images(p, endian, data, mappings, images);
            }
        }
    }
}

pub(super) fn print_dyld_cache_header(
    p: &mut Printer<'_>,
    endian: Endianness,
    header: &DyldCacheHeader<Endianness>,
) {
    if !p.options.file {
        return;
    }
    p.group("DyldCacheHeader", |p| {
        p.field_bytes("Magic", &header.magic);
        p.field_hex("MappingOffset", header.mapping_offset.get(endian));
        p.field("MappingCount", header.mapping_count.get(endian));
        p.field_hex("ImagesOffset", header.images_offset.get(endian));
        p.field("ImagesCount", header.images_count.get(endian));
        p.field_hex("DyldBaseAddress", header.dyld_base_address.get(endian));
    });
}

pub(super) fn print_dyld_cache_mappings(p: &mut Printer<'_>, mappings: &DyldCacheMappingSlice) {
    if !p.options.file {
        return;
    }
    for mapping in mappings.iter() {
        p.group("DyldCacheMapping", |p| {
            p.field_hex("Address", mapping.address());
            p.field_hex("Size", mapping.size());
            p.field_hex("FileOffset", mapping.file_offset());
            p.field_hex("MaxProt", mapping.max_prot());
            p.flags(mapping.max_prot(), 0, FLAGS_VM);
            p.field_hex("InitProt", mapping.init_prot());
            p.flags(mapping.init_prot(), 0, FLAGS_VM);
        });
    }
}

pub(super) fn print_dyld_cache_images(
    p: &mut Printer<'_>,
    endian: Endianness,
    data: &[u8],
    mappings: Option<DyldCacheMappingSlice>,
    images: &[DyldCacheImageInfo<Endianness>],
) {
    for image in images {
        if p.options.file {
            p.group("DyldCacheImageInfo", |p| {
                p.field_hex("Address", image.address.get(endian));
                p.field_hex("ModTime", image.mod_time.get(endian));
                p.field_hex("Inode", image.inode.get(endian));
                p.field_string(
                    "Path",
                    image.path_file_offset.get(endian),
                    image.path(endian, data),
                );
                p.field_hex("Pad", image.pad.get(endian));
            });
        }
        if let Some(offset) = mappings
            .as_ref()
            .and_then(|mappings| image.file_offset(endian, mappings).print_err(p))
        {
            if p.options.file {
                p.blank();
            }
            print_object_at(p, data, offset);
            p.blank();
        }
    }
}

pub(super) fn print_macho_fat32(p: &mut Printer<'_>, data: &[u8]) {
    if let Some(fat) = MachOFatFile32::parse(data).print_err(p) {
        writeln!(p.w(), "Format: Mach-O Fat 32-bit").unwrap();
        print_fat_header(p, fat.header());
        for arch in fat.arches() {
            print_fat_arch(p, arch);
        }
        for arch in fat.arches() {
            if let Some(data) = arch.data(data).print_err(p) {
                p.blank();
                print_object(p, data);
            }
        }
    }
}

pub(super) fn print_macho_fat64(p: &mut Printer<'_>, data: &[u8]) {
    if let Some(fat) = MachOFatFile64::parse(data).print_err(p) {
        writeln!(p.w(), "Format: Mach-O Fat 64-bit").unwrap();
        print_fat_header(p, fat.header());
        for arch in fat.arches() {
            print_fat_arch(p, arch);
        }
        for arch in fat.arches() {
            if let Some(data) = arch.data(data).print_err(p) {
                p.blank();
                print_object(p, data);
            }
        }
    }
}

pub(super) fn print_fat_header(p: &mut Printer<'_>, header: &macho::FatHeader) {
    if !p.options.file {
        return;
    }
    p.group("FatHeader", |p| {
        p.field_hex("Magic", header.magic.get(BigEndian));
        p.field("NumberOfFatArch", header.nfat_arch.get(BigEndian));
    });
}

pub(super) fn print_fat_arch<Arch: FatArch>(p: &mut Printer<'_>, arch: &Arch) {
    if !p.options.file {
        return;
    }
    p.group("FatArch", |p| {
        print_cputype(p, arch.cputype(), arch.cpusubtype());
        p.field_hex("Offset", arch.offset().into());
        p.field_hex("Size", arch.size().into());
        p.field("Align", arch.align());
    });
}

pub(super) fn print_macho32(p: &mut Printer<'_>, data: &[u8], offset: u64) {
    if let Some(header) = MachHeader32::parse(data, offset).print_err(p) {
        writeln!(p.w(), "Format: Mach-O 32-bit").unwrap();
        print_macho(p, header, data, offset);
    }
}

pub(super) fn print_macho64(p: &mut Printer<'_>, data: &[u8], offset: u64) {
    if let Some(header) = MachHeader64::parse(data, offset).print_err(p) {
        writeln!(p.w(), "Format: Mach-O 64-bit").unwrap();
        print_macho(p, header, data, offset);
    }
}

#[derive(Default)]
struct MachState<'a> {
    cputype: u32,
    symbols: Vec<Option<&'a [u8]>>,
    sections: Vec<Vec<u8>>,
    section_index: usize,
}

fn print_macho<Mach: MachHeader<Endian = Endianness>>(
    p: &mut Printer<'_>,
    header: &Mach,
    data: &[u8],
    offset: u64,
) {
    if let Some(endian) = header.endian().print_err(p) {
        let mut state = MachState {
            cputype: header.cputype(endian),
            sections: vec![vec![]],
            ..MachState::default()
        };
        if let Ok(mut commands) = header.load_commands(endian, data, 0) {
            while let Ok(Some(command)) = commands.next() {
                if let Ok(Some((segment, section_data))) = Mach::Segment::from_command(command) {
                    if let Ok(segment_sections) = segment.sections(endian, section_data) {
                        state
                            .sections
                            .extend(segment_sections.iter().map(|section| {
                                let mut name = Vec::new();
                                name.extend(section.segment_name());
                                name.push(b',');
                                name.extend(section.name());
                                name
                            }));
                    }
                } else if let Ok(Some(command)) = command.symtab() {
                    if let Ok(symtab) = command.symbols::<Mach, _>(endian, data) {
                        state.symbols.extend(
                            symtab
                                .iter()
                                .map(|symbol| symbol.name(endian, symtab.strings()).ok()),
                        );
                    }
                }
            }
        }

        print_mach_header(p, endian, header);
        print_load_commands(p, endian, data, offset, header, &mut state);
    }
}

fn print_mach_header<Mach: MachHeader>(p: &mut Printer<'_>, endian: Mach::Endian, header: &Mach) {
    if !p.options.file {
        return;
    }
    p.group("MachHeader", |p| {
        p.field_hex("Magic", header.magic());
        print_cputype(p, header.cputype(endian), header.cpusubtype(endian));
        p.field_enum("FileType", header.filetype(endian), FLAGS_MH_FILETYPE);
        p.field("NumberOfCmds", header.ncmds(endian));
        p.field_hex("SizeOfCmds", header.sizeofcmds(endian));
        p.field_enum("Flags", header.flags(endian), FLAGS_MH);
    });
}

fn print_load_commands<Mach: MachHeader>(
    p: &mut Printer<'_>,
    endian: Mach::Endian,
    data: &[u8],
    offset: u64,
    header: &Mach,
    state: &mut MachState,
) {
    if let Some(mut commands) = header.load_commands(endian, data, offset).print_err(p) {
        while let Some(Some(command)) = commands.next().print_err(p) {
            print_load_command(p, endian, data, header, command, state);
        }
    }
}

fn print_load_command<Mach: MachHeader>(
    p: &mut Printer<'_>,
    endian: Mach::Endian,
    data: &[u8],
    _header: &Mach,
    command: LoadCommandData<Mach::Endian>,
    state: &mut MachState,
) {
    if let Some(variant) = command.variant().print_err(p) {
        match variant {
            LoadCommandVariant::Segment32(segment, section_data) => {
                print_segment(p, endian, data, segment, section_data, state);
            }
            LoadCommandVariant::Segment64(segment, section_data) => {
                print_segment(p, endian, data, segment, section_data, state);
            }
            LoadCommandVariant::Symtab(symtab) => {
                print_symtab::<Mach>(p, endian, data, symtab, state);
            }
            _ => {}
        }
        if !p.options.macho_load_commands {
            return;
        }
        match variant {
            LoadCommandVariant::Segment32(..)
            | LoadCommandVariant::Segment64(..)
            | LoadCommandVariant::Symtab(..) => {}
            LoadCommandVariant::Thread(x, _thread_data) => {
                p.group("ThreadCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    // TODO: thread_data
                });
            }
            LoadCommandVariant::Dysymtab(x) => {
                p.group("DysymtabCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    // TODO: dump the tables these are all pointing to
                    p.field("IndexOfLocalSymbols", x.ilocalsym.get(endian));
                    p.field("NumberOfLocalSymbols", x.nlocalsym.get(endian));
                    p.field("IndexOfExternallyDefinedSymbols", x.iextdefsym.get(endian));
                    p.field("NumberOfExternallyDefinedSymbols", x.nextdefsym.get(endian));
                    p.field("IndexOfUndefinedSymbols", x.iundefsym.get(endian));
                    p.field("NumberOfUndefinedSymbols", x.nundefsym.get(endian));
                    p.field_hex("TocOffset", x.tocoff.get(endian));
                    p.field("NumberOfTocEntries", x.ntoc.get(endian));
                    p.field_hex("ModuleTableOffset", x.modtaboff.get(endian));
                    p.field("NumberOfModuleTableEntries", x.nmodtab.get(endian));
                    p.field_hex("ExternalRefSymbolOffset", x.extrefsymoff.get(endian));
                    p.field("NumberOfExternalRefSymbols", x.nextrefsyms.get(endian));
                    p.field_hex("IndirectSymbolOffset", x.indirectsymoff.get(endian));
                    p.field("NumberOfIndirectSymbols", x.nindirectsyms.get(endian));
                    p.field_hex("ExternalRelocationOffset", x.extreloff.get(endian));
                    p.field("NumberOfExternalRelocations", x.nextrel.get(endian));
                    p.field_hex("LocalRelocationOffset", x.locreloff.get(endian));
                    p.field("NumberOfLocalRelocations", x.nlocrel.get(endian));
                });
            }
            LoadCommandVariant::Dylib(x) | LoadCommandVariant::IdDylib(x) => {
                p.group("DylibCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.group("Dylib", |p| {
                        p.field_string(
                            "Name",
                            x.dylib.name.offset.get(endian),
                            command.string(endian, x.dylib.name),
                        );
                        p.field("Timestamp", x.dylib.timestamp.get(endian));
                        p.field_hex("CurrentVersion", x.dylib.current_version.get(endian));
                        p.field_hex(
                            "CompatibilityVersion",
                            x.dylib.compatibility_version.get(endian),
                        );
                    });
                });
            }
            LoadCommandVariant::LoadDylinker(x)
            | LoadCommandVariant::IdDylinker(x)
            | LoadCommandVariant::DyldEnvironment(x) => {
                p.group("DylinkerCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_string(
                        "Name",
                        x.name.offset.get(endian),
                        command.string(endian, x.name),
                    );
                });
            }
            LoadCommandVariant::PreboundDylib(x) => {
                p.group("PreboundDylibCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_string(
                        "Name",
                        x.name.offset.get(endian),
                        command.string(endian, x.name),
                    );
                    p.field("NumberOfModules", x.nmodules.get(endian));
                    // TODO: display bit vector
                    p.field_hex("LinkedModules", x.linked_modules.offset.get(endian));
                });
            }
            LoadCommandVariant::Routines32(x) => {
                p.group("RoutinesCommand32", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_hex("InitAddress", x.init_address.get(endian));
                    p.field_hex("InitModule", x.init_module.get(endian));
                    p.field_hex("Reserved1", x.reserved1.get(endian));
                    p.field_hex("Reserved2", x.reserved2.get(endian));
                    p.field_hex("Reserved3", x.reserved3.get(endian));
                    p.field_hex("Reserved4", x.reserved4.get(endian));
                    p.field_hex("Reserved5", x.reserved5.get(endian));
                    p.field_hex("Reserved6", x.reserved6.get(endian));
                });
            }
            LoadCommandVariant::Routines64(x) => {
                p.group("RoutinesCommand64", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_hex("InitAddress", x.init_address.get(endian));
                    p.field_hex("InitModule", x.init_module.get(endian));
                    p.field_hex("Reserved1", x.reserved1.get(endian));
                    p.field_hex("Reserved2", x.reserved2.get(endian));
                    p.field_hex("Reserved3", x.reserved3.get(endian));
                    p.field_hex("Reserved4", x.reserved4.get(endian));
                    p.field_hex("Reserved5", x.reserved5.get(endian));
                    p.field_hex("Reserved6", x.reserved6.get(endian));
                });
            }
            LoadCommandVariant::SubFramework(x) => {
                p.group("SubFrameworkCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_string(
                        "Umbrella",
                        x.umbrella.offset.get(endian),
                        command.string(endian, x.umbrella),
                    );
                });
            }
            LoadCommandVariant::SubUmbrella(x) => {
                p.group("SubUmbrellaCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_string(
                        "SubUmbrella",
                        x.sub_umbrella.offset.get(endian),
                        command.string(endian, x.sub_umbrella),
                    );
                });
            }
            LoadCommandVariant::SubClient(x) => {
                p.group("SubClientCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_string(
                        "Client",
                        x.client.offset.get(endian),
                        command.string(endian, x.client),
                    );
                });
            }
            LoadCommandVariant::SubLibrary(x) => {
                p.group("SubLibraryCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_string(
                        "SubLibrary",
                        x.sub_library.offset.get(endian),
                        command.string(endian, x.sub_library),
                    );
                });
            }
            LoadCommandVariant::TwolevelHints(x) => {
                p.group("TwolevelHintsCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_hex("Offset", x.offset.get(endian));
                    p.field_hex("NumberOfHints", x.nhints.get(endian));
                    // TODO: display hints
                });
            }
            LoadCommandVariant::PrebindCksum(x) => {
                p.group("PrebindCksumCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_hex("Cksum", x.cksum.get(endian));
                });
            }
            LoadCommandVariant::Uuid(x) => {
                p.group("UuidCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field("Uuid", format!("{:X?}", x.uuid));
                });
            }
            LoadCommandVariant::Rpath(x) => {
                p.group("RpathCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_string(
                        "Path",
                        x.path.offset.get(endian),
                        command.string(endian, x.path),
                    );
                });
            }
            LoadCommandVariant::LinkeditData(x) => {
                p.group("LinkeditDataCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_hex("DataOffset", x.dataoff.get(endian));
                    p.field_hex("DataSize", x.datasize.get(endian));
                });
            }
            LoadCommandVariant::EncryptionInfo32(x) => {
                p.group("EncryptionInfoCommand32", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_hex("CryptOffset", x.cryptoff.get(endian));
                    p.field_hex("CryptSize", x.cryptsize.get(endian));
                    p.field_hex("CryptId", x.cryptid.get(endian));
                });
            }
            LoadCommandVariant::EncryptionInfo64(x) => {
                p.group("EncryptionInfoCommand64", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_hex("CryptOffset", x.cryptoff.get(endian));
                    p.field_hex("CryptSize", x.cryptsize.get(endian));
                    p.field_hex("CryptId", x.cryptid.get(endian));
                    p.field_hex("Pad", x.pad.get(endian));
                });
            }
            LoadCommandVariant::DyldInfo(x) => {
                p.group("DyldInfoCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    // TODO: dump the tables these are all pointing to
                    p.field_hex("RebaseOffset", x.rebase_off.get(endian));
                    p.field_hex("RebaseSize", x.rebase_size.get(endian));
                    p.field_hex("BindOffset", x.bind_off.get(endian));
                    p.field_hex("BindSize", x.bind_size.get(endian));
                    p.field_hex("WeakBindOffset", x.weak_bind_off.get(endian));
                    p.field_hex("WeakBindSize", x.weak_bind_size.get(endian));
                    p.field_hex("LazyBindOffset", x.lazy_bind_off.get(endian));
                    p.field_hex("LazyBindSize", x.lazy_bind_size.get(endian));
                    p.field_hex("ExportOffset", x.export_off.get(endian));
                    p.field_hex("ExportSize", x.export_size.get(endian));
                });
            }
            LoadCommandVariant::VersionMin(x) => {
                p.group("VersionMinCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_hex("Version", x.version.get(endian));
                    p.field_hex("Sdk", x.sdk.get(endian));
                });
            }
            LoadCommandVariant::EntryPoint(x) => {
                p.group("EntryPointCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_hex("EntryOffset", x.entryoff.get(endian));
                    p.field_hex("StackSize", x.stacksize.get(endian));
                });
            }
            LoadCommandVariant::SourceVersion(x) => {
                p.group("SourceVersionCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_hex("Version", x.version.get(endian));
                });
            }
            LoadCommandVariant::LinkerOption(x) => {
                p.group("LinkerOptionCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_hex("Count", x.count.get(endian));
                    // TODO: dump strings
                });
            }
            LoadCommandVariant::Note(x) => {
                p.group("NoteCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    // TODO: string?
                    p.field("DataOwner", format!("{:X?}", x.data_owner));
                    p.field_hex("Offset", x.offset.get(endian));
                    p.field_hex("Size", x.size.get(endian));
                });
            }
            LoadCommandVariant::BuildVersion(x) => {
                p.group("BuildVersionCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_enum("Platform", x.platform.get(endian), FLAGS_PLATFORM);
                    p.field_hex("MinOs", x.minos.get(endian));
                    p.field_hex("Sdk", x.sdk.get(endian));
                    p.field_hex("NumberOfTools", x.ntools.get(endian));
                    // TODO: dump tools
                });
            }
            LoadCommandVariant::FilesetEntry(x) => {
                p.group("FilesetEntryCommand", |p| {
                    p.field_enum("Cmd", x.cmd.get(endian), FLAGS_LC);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_hex("VmAddress", x.vmaddr.get(endian));
                    p.field_hex("FileOffset", x.fileoff.get(endian));
                    p.field_string(
                        "EntryId",
                        x.entry_id.offset.get(endian),
                        command.string(endian, x.entry_id),
                    );
                    p.field_hex("Reserved", x.reserved.get(endian));
                });
            }
            _ => {
                p.group("LoadCommand", |p| {
                    p.field_enum("Cmd", command.cmd(), FLAGS_LC);
                    p.field_hex("CmdSize", command.cmdsize());
                });
            }
        }
    } else {
        p.group("LoadCommand", |p| {
            p.field_enum("Cmd", command.cmd(), FLAGS_LC);
            p.field_hex("CmdSize", command.cmdsize());
        });
    }
}

fn print_segment<S: Segment>(
    p: &mut Printer<'_>,
    endian: S::Endian,
    data: &[u8],
    segment: &S,
    section_data: &[u8],
    state: &mut MachState,
) {
    if !p.options.macho_load_commands
        && !p.options.segments
        && !p.options.sections
        && !p.options.relocations
    {
        return;
    }
    p.group("SegmentCommand", |p| {
        p.field_enum("Cmd", segment.cmd(endian), FLAGS_LC);
        p.field_hex("CmdSize", segment.cmdsize(endian));
        p.field_inline_string("SegmentName", segment.name());
        if p.options.macho_load_commands || p.options.segments {
            p.field_hex("VmAddress", segment.vmaddr(endian).into());
            p.field_hex("VmSize", segment.vmsize(endian).into());
            p.field_hex("FileOffset", segment.fileoff(endian).into());
            p.field_hex("FileSize", segment.filesize(endian).into());
            p.field_hex("MaxProt", segment.maxprot(endian));
            p.flags(segment.maxprot(endian), 0, FLAGS_VM);
            p.field_hex("InitProt", segment.initprot(endian));
            p.flags(segment.initprot(endian), 0, FLAGS_VM);
            p.field("NumberOfSections", segment.nsects(endian));
            p.field_hex("Flags", segment.flags(endian));
            p.flags(segment.flags(endian), 0, FLAGS_SG);
        }
        if let Some(sections) = segment.sections(endian, section_data).print_err(p) {
            for section in sections {
                state.section_index += 1;
                print_section(p, endian, data, section, state);
            }
        }
    });
}

fn print_section<S: Section>(
    p: &mut Printer<'_>,
    endian: S::Endian,
    data: &[u8],
    section: &S,
    state: &mut MachState,
) {
    if !p.options.sections && !(p.options.relocations && section.nreloc(endian) != 0) {
        return;
    }
    p.group("Section", |p| {
        p.field("Index", state.section_index);
        p.field_inline_string("SectionName", section.name());
        p.field_inline_string("SegmentName", section.segment_name());
        if p.options.sections {
            p.field_hex("Address", section.addr(endian).into());
            p.field_hex("Size", section.size(endian).into());
            p.field_hex("Offset", section.offset(endian));
            p.field_hex("Align", section.align(endian));
            p.field_hex("RelocationOffset", section.reloff(endian));
            p.field_hex("NumberOfRelocations", section.nreloc(endian));
            let flags = section.flags(endian);
            if flags & SECTION_TYPE == flags {
                p.field_enum("Flags", flags, FLAGS_S_TYPE);
            } else {
                p.field_hex("Flags", section.flags(endian));
                p.flags(flags, SECTION_TYPE, FLAGS_S_TYPE);
                p.flags(flags, 0, FLAGS_S_ATTR);
            }
        }
        print_section_relocations(p, endian, data, section, state);
    });
}

fn print_section_relocations<S: Section>(
    p: &mut Printer<'_>,
    endian: S::Endian,
    data: &[u8],
    section: &S,
    state: &MachState,
) {
    if !p.options.relocations {
        return;
    }
    if let Some(relocations) = section.relocations(endian, data).print_err(p) {
        let proc = match state.cputype {
            CPU_TYPE_X86 => FLAGS_GENERIC_RELOC,
            CPU_TYPE_X86_64 => FLAGS_X86_64_RELOC,
            CPU_TYPE_ARM => FLAGS_ARM_RELOC,
            CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32 => FLAGS_ARM64_RELOC,
            CPU_TYPE_POWERPC | CPU_TYPE_POWERPC64 => FLAGS_PPC_RELOC,
            _ => &[],
        };
        for relocation in relocations {
            if relocation.r_scattered(endian, state.cputype) {
                let info = relocation.scattered_info(endian);
                p.group("ScatteredRelocationInfo", |p| {
                    p.field_hex("Address", info.r_address);
                    p.field("PcRel", if info.r_pcrel { "yes" } else { "no" });
                    p.field("Length", info.r_length);
                    p.field_enum("Type", info.r_type, proc);
                    p.field_hex("Value", info.r_value);
                });
            } else {
                let info = relocation.info(endian);
                p.group("RelocationInfo", |p| {
                    p.field_hex("Address", info.r_address);
                    p.field("Extern", if info.r_extern { "yes" } else { "no" });
                    if info.r_extern {
                        let name = state
                            .symbols
                            .get(info.r_symbolnum as usize)
                            .copied()
                            .flatten();
                        p.field_string_option("Symbol", info.r_symbolnum, name);
                    } else {
                        let name = state
                            .sections
                            .get(info.r_symbolnum as usize)
                            .map(|name| &name[..]);
                        p.field_string_option("Section", info.r_symbolnum, name);
                    }
                    p.field("PcRel", if info.r_pcrel { "yes" } else { "no" });
                    p.field("Length", info.r_length);
                    p.field_enum("Type", info.r_type, proc);
                });
            }
        }
    }
}

fn print_symtab<Mach: MachHeader>(
    p: &mut Printer<'_>,
    endian: Mach::Endian,
    data: &[u8],
    symtab: &SymtabCommand<Mach::Endian>,
    state: &MachState,
) {
    if !p.options.macho_load_commands && !p.options.symbols {
        return;
    }
    p.group("SymtabCommand", |p| {
        p.field_enum("Cmd", symtab.cmd.get(endian), FLAGS_LC);
        p.field_hex("CmdSize", symtab.cmdsize.get(endian));
        p.field_hex("SymbolOffset", symtab.symoff.get(endian));
        p.field_hex("NumberOfSymbols", symtab.nsyms.get(endian));
        p.field_hex("StringOffset", symtab.stroff.get(endian));
        p.field_hex("StringSize", symtab.strsize.get(endian));
        print_symtab_symbols::<Mach>(p, endian, data, symtab, state);
    });
}

fn print_symtab_symbols<Mach: MachHeader>(
    p: &mut Printer<'_>,
    endian: Mach::Endian,
    data: &[u8],
    symtab: &SymtabCommand<Mach::Endian>,
    state: &MachState,
) {
    if !p.options.symbols {
        return;
    }
    if let Some(symbols) = symtab.symbols::<Mach, _>(endian, data).print_err(p) {
        for (index, nlist) in symbols.iter().enumerate() {
            p.group("Nlist", |p| {
                p.field("Index", index);
                p.field_string(
                    "String",
                    nlist.n_strx(endian),
                    nlist.name(endian, symbols.strings()),
                );
                let n_type = nlist.n_type();
                if nlist.is_stab() {
                    p.field_enum("Type", n_type, FLAGS_N_STAB);
                } else if n_type & N_TYPE == n_type {
                    // Avoid an extra line if no flags.
                    p.field_enum("Type", n_type, FLAGS_N_TYPE);
                } else {
                    p.field_hex("Type", n_type);
                    p.flags(n_type, N_TYPE, FLAGS_N_TYPE);
                    p.flags(n_type, 0, FLAGS_N_EXT);
                }
                let n_sect = nlist.n_sect();
                let name = state.sections.get(n_sect as usize).map(|name| &name[..]);
                p.field_string_option("Section", n_sect, name);
                let n_desc = nlist.n_desc(endian);
                p.field_hex("Desc", n_desc);
                if nlist.is_undefined() {
                    p.flags(n_desc, REFERENCE_TYPE, FLAGS_REFERENCE);
                }
                if !nlist.is_stab() {
                    p.flags(n_desc, 0, FLAGS_N_DESC);
                }
                p.field_hex("Value", nlist.n_value(endian).into());
            });
        }
    }
}

fn print_cputype(p: &mut Printer<'_>, cputype: u32, cpusubtype: u32) {
    let proc = match cputype {
        CPU_TYPE_ANY => FLAGS_CPU_SUBTYPE_ANY,
        CPU_TYPE_VAX => FLAGS_CPU_SUBTYPE_VAX,
        CPU_TYPE_MC680X0 => FLAGS_CPU_SUBTYPE_MC680X0,
        CPU_TYPE_X86 => FLAGS_CPU_SUBTYPE_X86,
        CPU_TYPE_X86_64 => FLAGS_CPU_SUBTYPE_X86_64,
        CPU_TYPE_MIPS => FLAGS_CPU_SUBTYPE_MIPS,
        CPU_TYPE_MC98000 => FLAGS_CPU_SUBTYPE_MC98000,
        CPU_TYPE_HPPA => FLAGS_CPU_SUBTYPE_HPPA,
        CPU_TYPE_ARM => FLAGS_CPU_SUBTYPE_ARM,
        CPU_TYPE_ARM64 => FLAGS_CPU_SUBTYPE_ARM64,
        CPU_TYPE_ARM64_32 => FLAGS_CPU_SUBTYPE_ARM64_32,
        CPU_TYPE_MC88000 => FLAGS_CPU_SUBTYPE_MC88000,
        CPU_TYPE_SPARC => FLAGS_CPU_SUBTYPE_SPARC,
        CPU_TYPE_I860 => FLAGS_CPU_SUBTYPE_I860,
        CPU_TYPE_POWERPC | CPU_TYPE_POWERPC64 => FLAGS_CPU_SUBTYPE_POWERPC,
        _ => &[],
    };
    p.field_enum("CpuType", cputype, FLAGS_CPU_TYPE);
    p.field_hex("CpuSubtype", cpusubtype);
    p.flags(cpusubtype, !CPU_SUBTYPE_MASK, proc);
    p.flags(cpusubtype, 0, FLAGS_CPU_SUBTYPE);
}

const FLAGS_CPU_TYPE: &[Flag<u32>] = &flags!(
    CPU_TYPE_ANY,
    CPU_TYPE_VAX,
    CPU_TYPE_MC680X0,
    CPU_TYPE_X86,
    CPU_TYPE_X86_64,
    CPU_TYPE_MIPS,
    CPU_TYPE_MC98000,
    CPU_TYPE_HPPA,
    CPU_TYPE_ARM,
    CPU_TYPE_ARM64,
    CPU_TYPE_ARM64_32,
    CPU_TYPE_MC88000,
    CPU_TYPE_SPARC,
    CPU_TYPE_I860,
    CPU_TYPE_ALPHA,
    CPU_TYPE_POWERPC,
    CPU_TYPE_POWERPC64,
);
const FLAGS_CPU_SUBTYPE: &[Flag<u32>] = &flags!(CPU_SUBTYPE_LIB64);
const FLAGS_CPU_SUBTYPE_ANY: &[Flag<u32>] = &flags!(
    CPU_SUBTYPE_MULTIPLE,
    CPU_SUBTYPE_LITTLE_ENDIAN,
    CPU_SUBTYPE_BIG_ENDIAN,
);
const FLAGS_CPU_SUBTYPE_VAX: &[Flag<u32>] = &flags!(
    CPU_SUBTYPE_VAX_ALL,
    CPU_SUBTYPE_VAX780,
    CPU_SUBTYPE_VAX785,
    CPU_SUBTYPE_VAX750,
    CPU_SUBTYPE_VAX730,
    CPU_SUBTYPE_UVAXI,
    CPU_SUBTYPE_UVAXII,
    CPU_SUBTYPE_VAX8200,
    CPU_SUBTYPE_VAX8500,
    CPU_SUBTYPE_VAX8600,
    CPU_SUBTYPE_VAX8650,
    CPU_SUBTYPE_VAX8800,
    CPU_SUBTYPE_UVAXIII,
);
const FLAGS_CPU_SUBTYPE_MC680X0: &[Flag<u32>] = &flags!(
    CPU_SUBTYPE_MC680X0_ALL,
    CPU_SUBTYPE_MC68040,
    CPU_SUBTYPE_MC68030_ONLY,
);
const FLAGS_CPU_SUBTYPE_X86: &[Flag<u32>] = &flags!(
    CPU_SUBTYPE_I386_ALL,
    CPU_SUBTYPE_386,
    CPU_SUBTYPE_486,
    CPU_SUBTYPE_486SX,
    CPU_SUBTYPE_586,
    CPU_SUBTYPE_PENT,
    CPU_SUBTYPE_PENTPRO,
    CPU_SUBTYPE_PENTII_M3,
    CPU_SUBTYPE_PENTII_M5,
    CPU_SUBTYPE_CELERON,
    CPU_SUBTYPE_CELERON_MOBILE,
    CPU_SUBTYPE_PENTIUM_3,
    CPU_SUBTYPE_PENTIUM_3_M,
    CPU_SUBTYPE_PENTIUM_3_XEON,
    CPU_SUBTYPE_PENTIUM_M,
    CPU_SUBTYPE_PENTIUM_4,
    CPU_SUBTYPE_PENTIUM_4_M,
    CPU_SUBTYPE_ITANIUM,
    CPU_SUBTYPE_ITANIUM_2,
    CPU_SUBTYPE_XEON,
    CPU_SUBTYPE_XEON_MP,
);
const FLAGS_CPU_SUBTYPE_X86_64: &[Flag<u32>] = &flags!(
    CPU_SUBTYPE_X86_64_ALL,
    CPU_SUBTYPE_X86_ARCH1,
    CPU_SUBTYPE_X86_64_H,
);
const FLAGS_CPU_SUBTYPE_MIPS: &[Flag<u32>] = &flags!(
    CPU_SUBTYPE_MIPS_ALL,
    CPU_SUBTYPE_MIPS_R2300,
    CPU_SUBTYPE_MIPS_R2600,
    CPU_SUBTYPE_MIPS_R2800,
    CPU_SUBTYPE_MIPS_R2000A,
    CPU_SUBTYPE_MIPS_R2000,
    CPU_SUBTYPE_MIPS_R3000A,
    CPU_SUBTYPE_MIPS_R3000,
);
const FLAGS_CPU_SUBTYPE_MC98000: &[Flag<u32>] =
    &flags!(CPU_SUBTYPE_MC98000_ALL, CPU_SUBTYPE_MC98601);
const FLAGS_CPU_SUBTYPE_HPPA: &[Flag<u32>] = &flags!(CPU_SUBTYPE_HPPA_ALL, CPU_SUBTYPE_HPPA_7100LC);
const FLAGS_CPU_SUBTYPE_MC88000: &[Flag<u32>] = &flags!(
    CPU_SUBTYPE_MC88000_ALL,
    CPU_SUBTYPE_MC88100,
    CPU_SUBTYPE_MC88110,
);
const FLAGS_CPU_SUBTYPE_SPARC: &[Flag<u32>] = &flags!(CPU_SUBTYPE_SPARC_ALL);
const FLAGS_CPU_SUBTYPE_I860: &[Flag<u32>] = &flags!(CPU_SUBTYPE_I860_ALL, CPU_SUBTYPE_I860_860);
const FLAGS_CPU_SUBTYPE_POWERPC: &[Flag<u32>] = &flags!(
    CPU_SUBTYPE_POWERPC_ALL,
    CPU_SUBTYPE_POWERPC_601,
    CPU_SUBTYPE_POWERPC_602,
    CPU_SUBTYPE_POWERPC_603,
    CPU_SUBTYPE_POWERPC_603E,
    CPU_SUBTYPE_POWERPC_603EV,
    CPU_SUBTYPE_POWERPC_604,
    CPU_SUBTYPE_POWERPC_604E,
    CPU_SUBTYPE_POWERPC_620,
    CPU_SUBTYPE_POWERPC_750,
    CPU_SUBTYPE_POWERPC_7400,
    CPU_SUBTYPE_POWERPC_7450,
    CPU_SUBTYPE_POWERPC_970,
);
const FLAGS_CPU_SUBTYPE_ARM: &[Flag<u32>] = &flags!(
    CPU_SUBTYPE_ARM_ALL,
    CPU_SUBTYPE_ARM_V4T,
    CPU_SUBTYPE_ARM_V6,
    CPU_SUBTYPE_ARM_V5TEJ,
    CPU_SUBTYPE_ARM_XSCALE,
    CPU_SUBTYPE_ARM_V7,
    CPU_SUBTYPE_ARM_V7F,
    CPU_SUBTYPE_ARM_V7S,
    CPU_SUBTYPE_ARM_V7K,
    CPU_SUBTYPE_ARM_V8,
    CPU_SUBTYPE_ARM_V6M,
    CPU_SUBTYPE_ARM_V7M,
    CPU_SUBTYPE_ARM_V7EM,
    CPU_SUBTYPE_ARM_V8M,
);
const FLAGS_CPU_SUBTYPE_ARM64: &[Flag<u32>] = &flags!(
    CPU_SUBTYPE_ARM64_ALL,
    CPU_SUBTYPE_ARM64_V8,
    CPU_SUBTYPE_ARM64E,
);
const FLAGS_CPU_SUBTYPE_ARM64_32: &[Flag<u32>] =
    &flags!(CPU_SUBTYPE_ARM64_32_ALL, CPU_SUBTYPE_ARM64_32_V8);
const FLAGS_MH_FILETYPE: &[Flag<u32>] = &flags!(
    MH_OBJECT,
    MH_EXECUTE,
    MH_FVMLIB,
    MH_CORE,
    MH_PRELOAD,
    MH_DYLIB,
    MH_DYLINKER,
    MH_BUNDLE,
    MH_DYLIB_STUB,
    MH_DSYM,
    MH_KEXT_BUNDLE,
    MH_FILESET,
);
const FLAGS_MH: &[Flag<u32>] = &flags!(
    MH_NOUNDEFS,
    MH_INCRLINK,
    MH_DYLDLINK,
    MH_BINDATLOAD,
    MH_PREBOUND,
    MH_SPLIT_SEGS,
    MH_LAZY_INIT,
    MH_TWOLEVEL,
    MH_FORCE_FLAT,
    MH_NOMULTIDEFS,
    MH_NOFIXPREBINDING,
    MH_PREBINDABLE,
    MH_ALLMODSBOUND,
    MH_SUBSECTIONS_VIA_SYMBOLS,
    MH_CANONICAL,
    MH_WEAK_DEFINES,
    MH_BINDS_TO_WEAK,
    MH_ALLOW_STACK_EXECUTION,
    MH_ROOT_SAFE,
    MH_SETUID_SAFE,
    MH_NO_REEXPORTED_DYLIBS,
    MH_PIE,
    MH_DEAD_STRIPPABLE_DYLIB,
    MH_HAS_TLV_DESCRIPTORS,
    MH_NO_HEAP_EXECUTION,
    MH_APP_EXTENSION_SAFE,
    MH_NLIST_OUTOFSYNC_WITH_DYLDINFO,
    MH_SIM_SUPPORT,
    MH_DYLIB_IN_CACHE,
);
const FLAGS_LC: &[Flag<u32>] = &flags!(
    LC_SEGMENT,
    LC_SYMTAB,
    LC_SYMSEG,
    LC_THREAD,
    LC_UNIXTHREAD,
    LC_LOADFVMLIB,
    LC_IDFVMLIB,
    LC_IDENT,
    LC_FVMFILE,
    LC_PREPAGE,
    LC_DYSYMTAB,
    LC_LOAD_DYLIB,
    LC_ID_DYLIB,
    LC_LOAD_DYLINKER,
    LC_ID_DYLINKER,
    LC_PREBOUND_DYLIB,
    LC_ROUTINES,
    LC_SUB_FRAMEWORK,
    LC_SUB_UMBRELLA,
    LC_SUB_CLIENT,
    LC_SUB_LIBRARY,
    LC_TWOLEVEL_HINTS,
    LC_PREBIND_CKSUM,
    LC_LOAD_WEAK_DYLIB,
    LC_SEGMENT_64,
    LC_ROUTINES_64,
    LC_UUID,
    LC_RPATH,
    LC_CODE_SIGNATURE,
    LC_SEGMENT_SPLIT_INFO,
    LC_REEXPORT_DYLIB,
    LC_LAZY_LOAD_DYLIB,
    LC_ENCRYPTION_INFO,
    LC_DYLD_INFO,
    LC_DYLD_INFO_ONLY,
    LC_LOAD_UPWARD_DYLIB,
    LC_VERSION_MIN_MACOSX,
    LC_VERSION_MIN_IPHONEOS,
    LC_FUNCTION_STARTS,
    LC_DYLD_ENVIRONMENT,
    LC_MAIN,
    LC_DATA_IN_CODE,
    LC_SOURCE_VERSION,
    LC_DYLIB_CODE_SIGN_DRS,
    LC_ENCRYPTION_INFO_64,
    LC_LINKER_OPTION,
    LC_LINKER_OPTIMIZATION_HINT,
    LC_VERSION_MIN_TVOS,
    LC_VERSION_MIN_WATCHOS,
    LC_NOTE,
    LC_BUILD_VERSION,
    LC_DYLD_EXPORTS_TRIE,
    LC_DYLD_CHAINED_FIXUPS,
    LC_FILESET_ENTRY,
);
const FLAGS_VM: &[Flag<u32>] = &flags!(VM_PROT_READ, VM_PROT_WRITE, VM_PROT_EXECUTE);
const FLAGS_SG: &[Flag<u32>] = &flags!(
    SG_HIGHVM,
    SG_FVMLIB,
    SG_NORELOC,
    SG_PROTECTED_VERSION_1,
    SG_READ_ONLY,
);
const FLAGS_S_TYPE: &[Flag<u32>] = &flags!(
    S_REGULAR,
    S_ZEROFILL,
    S_CSTRING_LITERALS,
    S_4BYTE_LITERALS,
    S_8BYTE_LITERALS,
    S_LITERAL_POINTERS,
    S_NON_LAZY_SYMBOL_POINTERS,
    S_LAZY_SYMBOL_POINTERS,
    S_SYMBOL_STUBS,
    S_MOD_INIT_FUNC_POINTERS,
    S_MOD_TERM_FUNC_POINTERS,
    S_COALESCED,
    S_GB_ZEROFILL,
    S_INTERPOSING,
    S_16BYTE_LITERALS,
    S_DTRACE_DOF,
    S_LAZY_DYLIB_SYMBOL_POINTERS,
    S_THREAD_LOCAL_REGULAR,
    S_THREAD_LOCAL_ZEROFILL,
    S_THREAD_LOCAL_VARIABLES,
    S_THREAD_LOCAL_VARIABLE_POINTERS,
    S_THREAD_LOCAL_INIT_FUNCTION_POINTERS,
    S_INIT_FUNC_OFFSETS,
);
const FLAGS_S_ATTR: &[Flag<u32>] = &flags!(
    S_ATTR_PURE_INSTRUCTIONS,
    S_ATTR_NO_TOC,
    S_ATTR_STRIP_STATIC_SYMS,
    S_ATTR_NO_DEAD_STRIP,
    S_ATTR_LIVE_SUPPORT,
    S_ATTR_SELF_MODIFYING_CODE,
    S_ATTR_DEBUG,
    S_ATTR_SOME_INSTRUCTIONS,
    S_ATTR_EXT_RELOC,
    S_ATTR_LOC_RELOC,
);
const FLAGS_PLATFORM: &[Flag<u32>] = &flags!(
    PLATFORM_MACOS,
    PLATFORM_IOS,
    PLATFORM_TVOS,
    PLATFORM_WATCHOS,
    PLATFORM_BRIDGEOS,
    PLATFORM_MACCATALYST,
    PLATFORM_IOSSIMULATOR,
    PLATFORM_TVOSSIMULATOR,
    PLATFORM_WATCHOSSIMULATOR,
    PLATFORM_DRIVERKIT,
    PLATFORM_XROS,
    PLATFORM_XROSSIMULATOR
);
const FLAGS_N_EXT: &[Flag<u8>] = &flags!(N_PEXT, N_EXT);
const FLAGS_N_TYPE: &[Flag<u8>] = &flags!(N_UNDF, N_ABS, N_SECT, N_PBUD, N_INDR);
const FLAGS_N_STAB: &[Flag<u8>] = &flags!(
    N_GSYM, N_FNAME, N_FUN, N_STSYM, N_LCSYM, N_BNSYM, N_AST, N_OPT, N_RSYM, N_SLINE, N_ENSYM,
    N_SSYM, N_SO, N_OSO, N_LSYM, N_BINCL, N_SOL, N_PARAMS, N_VERSION, N_OLEVEL, N_PSYM, N_EINCL,
    N_ENTRY, N_LBRAC, N_EXCL, N_RBRAC, N_BCOMM, N_ECOMM, N_ECOML, N_LENG, N_PC,
);
const FLAGS_REFERENCE: &[Flag<u16>] = &flags!(
    REFERENCE_FLAG_UNDEFINED_NON_LAZY,
    REFERENCE_FLAG_UNDEFINED_LAZY,
    REFERENCE_FLAG_DEFINED,
    REFERENCE_FLAG_PRIVATE_DEFINED,
    REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY,
    REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY,
);
const FLAGS_N_DESC: &[Flag<u16>] = &flags!(
    REFERENCED_DYNAMICALLY,
    N_NO_DEAD_STRIP,
    N_DESC_DISCARDED,
    N_WEAK_REF,
    N_WEAK_DEF,
    N_REF_TO_WEAK,
    N_ARM_THUMB_DEF,
    N_SYMBOL_RESOLVER,
    N_ALT_ENTRY,
);
const FLAGS_GENERIC_RELOC: &[Flag<u8>] = &flags!(
    GENERIC_RELOC_VANILLA,
    GENERIC_RELOC_PAIR,
    GENERIC_RELOC_SECTDIFF,
    GENERIC_RELOC_PB_LA_PTR,
    GENERIC_RELOC_LOCAL_SECTDIFF,
    GENERIC_RELOC_TLV,
);
const FLAGS_ARM_RELOC: &[Flag<u8>] = &flags!(
    ARM_RELOC_VANILLA,
    ARM_RELOC_PAIR,
    ARM_RELOC_SECTDIFF,
    ARM_RELOC_LOCAL_SECTDIFF,
    ARM_RELOC_PB_LA_PTR,
    ARM_RELOC_BR24,
    ARM_THUMB_RELOC_BR22,
    ARM_THUMB_32BIT_BRANCH,
    ARM_RELOC_HALF,
    ARM_RELOC_HALF_SECTDIFF,
);
const FLAGS_ARM64_RELOC: &[Flag<u8>] = &flags!(
    ARM64_RELOC_UNSIGNED,
    ARM64_RELOC_SUBTRACTOR,
    ARM64_RELOC_BRANCH26,
    ARM64_RELOC_PAGE21,
    ARM64_RELOC_PAGEOFF12,
    ARM64_RELOC_GOT_LOAD_PAGE21,
    ARM64_RELOC_GOT_LOAD_PAGEOFF12,
    ARM64_RELOC_POINTER_TO_GOT,
    ARM64_RELOC_TLVP_LOAD_PAGE21,
    ARM64_RELOC_TLVP_LOAD_PAGEOFF12,
    ARM64_RELOC_ADDEND,
    ARM64_RELOC_AUTHENTICATED_POINTER,
);
const FLAGS_PPC_RELOC: &[Flag<u8>] = &flags!(
    PPC_RELOC_VANILLA,
    PPC_RELOC_PAIR,
    PPC_RELOC_BR14,
    PPC_RELOC_BR24,
    PPC_RELOC_HI16,
    PPC_RELOC_LO16,
    PPC_RELOC_HA16,
    PPC_RELOC_LO14,
    PPC_RELOC_SECTDIFF,
    PPC_RELOC_PB_LA_PTR,
    PPC_RELOC_HI16_SECTDIFF,
    PPC_RELOC_LO16_SECTDIFF,
    PPC_RELOC_HA16_SECTDIFF,
    PPC_RELOC_JBSR,
    PPC_RELOC_LO14_SECTDIFF,
    PPC_RELOC_LOCAL_SECTDIFF,
);
const FLAGS_X86_64_RELOC: &[Flag<u8>] = &flags!(
    X86_64_RELOC_UNSIGNED,
    X86_64_RELOC_SIGNED,
    X86_64_RELOC_BRANCH,
    X86_64_RELOC_GOT_LOAD,
    X86_64_RELOC_GOT,
    X86_64_RELOC_SUBTRACTOR,
    X86_64_RELOC_SIGNED_1,
    X86_64_RELOC_SIGNED_2,
    X86_64_RELOC_SIGNED_4,
    X86_64_RELOC_TLV,
);
