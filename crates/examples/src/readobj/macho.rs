use super::*;
use object::macho::*;
use object::read::macho::*;
use object::{BigEndian, Endian, U32};

pub(super) fn print_dyld_cache(p: &mut Printer<'_>, data: &[u8], subcache_data: &[&[u8]]) {
    print_dyld_subcache(p, data);
    for subcache in subcache_data {
        print_dyld_subcache(p, subcache);
    }
    if let Some(cache) = DyldCache::<Endianness>::parse(data, subcache_data).print_err(p) {
        print_dyld_cache_images(p, &cache);
    }
}

pub(super) fn print_dyld_subcache(p: &mut Printer<'_>, data: &[u8]) {
    if !p.options.file {
        return;
    }
    let Some(header) = DyldCacheHeader::<Endianness>::parse(data).print_err(p) else {
        return;
    };
    let Some((_, endian)) = header.parse_magic().print_err(p) else {
        return;
    };

    p.group("DyldCacheHeader", |p| {
        p.field_bytes("Magic", &header.magic);
        p.field_hex("MappingOffset", header.mapping_offset.get(endian));
        p.field("MappingCount", header.mapping_count.get(endian));
        p.field_hex("ImagesOffset", header.images_offset.get(endian));
        p.field("ImagesCount", header.images_count.get(endian));
        p.field_hex("DyldBaseAddress", header.dyld_base_address.get(endian));
    });

    if let Some(mappings) = header.mappings(endian, data).print_err(p) {
        match mappings {
            DyldCacheMappingSlice::V1(info) => {
                for mapping in info.iter() {
                    print_dyld_cache_mapping_info(p, endian, mapping);
                }
            }
            DyldCacheMappingSlice::V2(info) => {
                for mapping in info.iter() {
                    print_dyld_cache_mapping_and_slide_info(p, endian, data, mapping);
                }
            }
            _ => panic!(
                "If this case is hit, it means that someone added a variant to the (non-exhaustive) \
                 DyldCacheMappingSlice enum and forgot to update this example"
            ),
        }
    }
    p.blank();
}

pub(super) fn print_dyld_cache_mapping_info(
    p: &mut Printer<'_>,
    endian: Endianness,
    mapping: &DyldCacheMappingInfo<Endianness>,
) {
    p.group("DyldCacheMappingInfo", |p| {
        p.field_hex("Address", mapping.address.get(endian));
        p.field_hex("Size", mapping.size.get(endian));
        p.field_hex("FileOffset", mapping.file_offset.get(endian));
        p.field_flags("MaxProt", mapping.max_prot.get(endian), VmProt::NAMES);
        p.field_flags("InitProt", mapping.init_prot.get(endian), VmProt::NAMES);
    });
}

pub(super) fn print_dyld_cache_mapping_and_slide_info(
    p: &mut Printer<'_>,
    endian: Endianness,
    data: &[u8],
    mapping: &DyldCacheMappingAndSlideInfo<Endianness>,
) {
    p.group("DyldCacheMappingAndSlideInfo", |p| {
        p.field_hex("Address", mapping.address.get(endian));
        p.field_hex("Size", mapping.size.get(endian));
        p.field_hex("FileOffset", mapping.file_offset.get(endian));
        p.field_hex(
            "SlideInfoFileOffset",
            mapping.slide_info_file_offset.get(endian),
        );
        p.field_hex(
            "SlideInfoFileSize",
            mapping.slide_info_file_size.get(endian),
        );
        p.field_flags(
            "Flags",
            mapping.flags.get(endian),
            DyldCacheMappingFlags::NAMES,
        );
        p.field_flags("MaxProt", mapping.max_prot.get(endian), VmProt::NAMES);
        p.field_flags("InitProt", mapping.init_prot.get(endian), VmProt::NAMES);
    });

    if let Some(slide) = mapping.slide(endian, data).print_err(p) {
        match slide {
            DyldCacheSlideInfo::V2 { slide, .. } => {
                p.group("DyldCacheSlideInfo2", |p| {
                    p.field("Version", slide.version.get(endian));
                    p.field("PageSize", slide.page_size.get(endian));
                    p.field_hex("PageStartsOffset", slide.page_starts_offset.get(endian));
                    p.field_hex("PageStartsCount", slide.page_starts_count.get(endian));
                    p.field_hex("PageExtrasOffset", slide.page_extras_offset.get(endian));
                    p.field_hex("PageExtrasCount", slide.page_extras_count.get(endian));
                    p.field_hex("DeltaMask", slide.delta_mask.get(endian));
                    p.field_hex("ValueAdd", slide.value_add.get(endian));
                });
            }
            DyldCacheSlideInfo::V3 { slide, .. } => {
                p.group("DyldCacheSlideInfo3", |p| {
                    p.field("Version", slide.version.get(endian));
                    p.field("PageSize", slide.page_size.get(endian));
                    p.field_hex("PageStartsCount", slide.page_starts_count.get(endian));
                    p.field_hex("AuthValueAdd", slide.auth_value_add.get(endian));
                });
            }
            DyldCacheSlideInfo::V5 { slide, .. } => {
                p.group("DyldCacheSlideInfo5", |p| {
                    p.field("Version", slide.version.get(endian));
                    p.field("PageSize", slide.page_size.get(endian));
                    p.field_hex("PageStartsCount", slide.page_starts_count.get(endian));
                    p.field_hex("ValueAdd", slide.value_add.get(endian));
                });
            }
            _ => {}
        }
    }
}

pub(super) fn print_dyld_cache_images(p: &mut Printer<'_>, cache: &DyldCache) {
    let endian = cache.endianness();
    let data = cache.data();
    for image in cache.images() {
        if p.options.file {
            let info = image.info();
            p.group("DyldCacheImageInfo", |p| {
                p.field_hex("Address", info.address.get(endian));
                p.field_hex("ModTime", info.mod_time.get(endian));
                p.field_hex("Inode", info.inode.get(endian));
                p.field_string(
                    "Path",
                    info.path_file_offset.get(endian),
                    info.path(endian, data),
                );
                p.field_hex("Pad", info.pad.get(endian));
            });
        }
        if let Some((data, offset)) = image.image_data_and_offset().print_err(p) {
            print_dyld_cache_image(p, data, offset, cache);
            p.blank();
        }
    }
}

fn print_dyld_cache_image(p: &mut Printer<'_>, data: &[u8], offset: u64, cache: &DyldCache) {
    let Some(kind) = object::FileKind::parse_at(data, offset).print_err(p) else {
        return;
    };
    match kind {
        object::FileKind::MachO32 => macho::print_macho32(p, data, offset, Some(cache)),
        object::FileKind::MachO64 => macho::print_macho64(p, data, offset, Some(cache)),
        _ => writeln!(p.w(), "Format: {:?}", kind).unwrap(),
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
                print_object(p, data, &[]);
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
                print_object(p, data, &[]);
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

pub(super) fn print_macho32(
    p: &mut Printer<'_>,
    data: &[u8],
    offset: u64,
    cache: Option<&DyldCache>,
) {
    if let Some(header) = MachHeader32::parse(data, offset).print_err(p) {
        writeln!(p.w(), "Format: Mach-O 32-bit").unwrap();
        print_macho(p, header, data, offset, cache);
    }
}

pub(super) fn print_macho64(
    p: &mut Printer<'_>,
    data: &[u8],
    offset: u64,
    cache: Option<&DyldCache>,
) {
    if let Some(header) = MachHeader64::parse(data, offset).print_err(p) {
        writeln!(p.w(), "Format: Mach-O 64-bit").unwrap();
        print_macho(p, header, data, offset, cache);
    }
}

#[derive(Default)]
struct MachState<'a, E: Endian> {
    cputype: CpuType,
    filetype: FileType,
    twolevel: bool,
    linkedit_data: &'a [u8],
    symbols: Vec<Option<&'a [u8]>>,
    indirect_symbols: &'a [U32<E, macho::IndirectSymbol>],
    sections: Vec<Vec<u8>>,
    section_index: usize,
    text_segment_addr: u64,
}

fn print_macho<Mach: MachHeader<Endian = Endianness>>(
    p: &mut Printer<'_>,
    header: &Mach,
    data: &[u8],
    offset: u64,
    cache: Option<&DyldCache>,
) {
    if let Some(endian) = header.endian().print_err(p) {
        let mut state = MachState {
            cputype: header.cputype(endian),
            filetype: header.filetype(endian),
            twolevel: header.flags(endian).contains(MH_TWOLEVEL),
            linkedit_data: data,
            // Dummy first entry because section index starts at 1.
            sections: vec![vec![]],
            ..MachState::default()
        };
        // Scan the load commands for info that we need to reference during parsing.
        if let Ok(mut commands) = header.load_commands(endian, data, offset) {
            let mut symtab_command = None;
            let mut dysymtab_command = None;
            while let Ok(Some(command)) = commands.next() {
                if let Ok(Some((segment, section_data))) = Mach::Segment::from_command(command) {
                    if segment.name() == macho::SEG_TEXT.as_bytes() {
                        state.text_segment_addr = segment.vmaddr(endian).into();
                    }
                    if let Some(cache) = cache {
                        // The symbol table will be in the linkedit segment, but that may be in a
                        // different subcache, so we need to remember the data for that subcache.
                        // TODO: this logic should be in the object crate somehow. It already
                        // exists there for MachOFile but we're not using that here.
                        if segment.name() == macho::SEG_LINKEDIT.as_bytes() {
                            let addr = segment.vmaddr(endian).into();
                            if let Some((data, _offset)) = cache.data_and_offset_for_address(addr) {
                                state.linkedit_data = data;
                            }
                        }
                    }
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
                    symtab_command = Some(command);
                } else if let Ok(Some(command)) = command.dysymtab() {
                    dysymtab_command = Some(command);
                }
            }
            if let Some(symtab_command) = symtab_command
                && let Ok(symtab) = symtab_command.symbols::<Mach, _>(endian, state.linkedit_data)
            {
                state.symbols.extend(
                    symtab
                        .iter()
                        .map(|symbol| symbol.name(endian, symtab.strings()).ok()),
                );
            }
            if let Some(dysymtab) = dysymtab_command {
                state.indirect_symbols = dysymtab
                    .indirect_symbols(endian, state.linkedit_data)
                    .unwrap_or(&[]);
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
        p.field_consts("FileType", header.filetype(endian), FileType::NAMES);
        p.field("NumberOfCmds", header.ncmds(endian));
        p.field_hex("SizeOfCmds", header.sizeofcmds(endian));
        p.field_flags("Flags", header.flags(endian), FileFlags::NAMES);
    });
}

fn print_load_commands<Mach: MachHeader>(
    p: &mut Printer<'_>,
    endian: Mach::Endian,
    data: &[u8],
    offset: u64,
    header: &Mach,
    state: &mut MachState<Mach::Endian>,
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
    state: &mut MachState<Mach::Endian>,
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
                print_symtab::<Mach>(p, endian, state.linkedit_data, symtab, state);
            }
            LoadCommandVariant::Dysymtab(dysymtab) => {
                print_dysymtab::<Mach>(p, endian, dysymtab);
            }
            LoadCommandVariant::LinkeditData(linkedit) => {
                print_linkedit_data::<Mach>(p, endian, linkedit, state);
            }
            _ => {}
        }
        if !p.options.macho_load_commands {
            return;
        }
        match variant {
            LoadCommandVariant::Segment32(..)
            | LoadCommandVariant::Segment64(..)
            | LoadCommandVariant::Symtab(..)
            | LoadCommandVariant::Dysymtab(..)
            | LoadCommandVariant::LinkeditData(..) => {}
            LoadCommandVariant::Thread(x, _thread_data) => {
                p.group("ThreadCommand", |p| {
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    // TODO: thread_data
                });
            }
            LoadCommandVariant::Dylib(x) | LoadCommandVariant::IdDylib(x) => {
                p.group("DylibCommand", |p| {
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.group("Dylib", |p| {
                        p.field_string(
                            "Name",
                            x.dylib.name.offset.get(endian),
                            command.string(endian, x.dylib.name),
                        );
                        let flags = command.dylib_use_flags(endian, x).print_err(p).flatten();
                        if flags.is_some() {
                            p.field_hex("Marker", x.dylib.timestamp.get(endian));
                        } else {
                            p.field("Timestamp", x.dylib.timestamp.get(endian));
                        }
                        p.field("CurrentVersion", x.dylib.current_version.get(endian));
                        p.field(
                            "CompatibilityVersion",
                            x.dylib.compatibility_version.get(endian),
                        );
                        if let Some(flags) = flags {
                            p.field_flags("Flags", flags, macho::DylibUseFlags::NAMES);
                        }
                    });
                });
            }
            LoadCommandVariant::LoadDylinker(x)
            | LoadCommandVariant::IdDylinker(x)
            | LoadCommandVariant::DyldEnvironment(x) => {
                p.group("DylinkerCommand", |p| {
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
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
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
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
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
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
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
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
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
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
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
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
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
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
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
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
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_hex("Offset", x.offset.get(endian));
                    p.field_hex("NumberOfHints", x.nhints.get(endian));
                    // TODO: display hints
                });
            }
            LoadCommandVariant::PrebindCksum(x) => {
                p.group("PrebindCksumCommand", |p| {
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_hex("Cksum", x.cksum.get(endian));
                });
            }
            LoadCommandVariant::Uuid(x) => {
                p.group("UuidCommand", |p| {
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field("Uuid", format!("{:X?}", x.uuid));
                });
            }
            LoadCommandVariant::Rpath(x) => {
                p.group("RpathCommand", |p| {
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_string(
                        "Path",
                        x.path.offset.get(endian),
                        command.string(endian, x.path),
                    );
                });
            }
            LoadCommandVariant::TargetTriple(x) => {
                p.group("TargetTripleCommand", |p| {
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_string(
                        "Triple",
                        x.triple.offset.get(endian),
                        command.string(endian, x.triple),
                    );
                });
            }
            LoadCommandVariant::EncryptionInfo32(x) => {
                p.group("EncryptionInfoCommand32", |p| {
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_hex("CryptOffset", x.cryptoff.get(endian));
                    p.field_hex("CryptSize", x.cryptsize.get(endian));
                    p.field_hex("CryptId", x.cryptid.get(endian));
                });
            }
            LoadCommandVariant::EncryptionInfo64(x) => {
                p.group("EncryptionInfoCommand64", |p| {
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_hex("CryptOffset", x.cryptoff.get(endian));
                    p.field_hex("CryptSize", x.cryptsize.get(endian));
                    p.field_hex("CryptId", x.cryptid.get(endian));
                    p.field_hex("Pad", x.pad.get(endian));
                });
            }
            LoadCommandVariant::DyldInfo(x) => {
                print_dyld_info::<Mach>(p, endian, x, state);
            }
            LoadCommandVariant::VersionMin(x) => {
                p.group("VersionMinCommand", |p| {
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field("Version", x.version.get(endian));
                    p.field("Sdk", x.sdk.get(endian));
                });
            }
            LoadCommandVariant::EntryPoint(x) => {
                p.group("EntryPointCommand", |p| {
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_hex("EntryOffset", x.entryoff.get(endian));
                    p.field_hex("StackSize", x.stacksize.get(endian));
                });
            }
            LoadCommandVariant::SourceVersion(x) => {
                p.group("SourceVersionCommand", |p| {
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_hex("Version", x.version.get(endian));
                });
            }
            LoadCommandVariant::LinkerOption(x) => {
                p.group("LinkerOptionCommand", |p| {
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_hex("Count", x.count.get(endian));
                    // TODO: dump strings
                });
            }
            LoadCommandVariant::Note(x) => {
                p.group("NoteCommand", |p| {
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    // TODO: string?
                    p.field("DataOwner", format!("{:X?}", x.data_owner));
                    p.field_hex("Offset", x.offset.get(endian));
                    p.field_hex("Size", x.size.get(endian));
                });
            }
            LoadCommandVariant::BuildVersion(x, data) => {
                p.group("BuildVersionCommand", |p| {
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
                    p.field_hex("CmdSize", x.cmdsize.get(endian));
                    p.field_consts("Platform", x.platform.get(endian), Platform::NAMES);
                    p.field("MinOs", x.minos.get(endian));
                    p.field("Sdk", x.sdk.get(endian));
                    p.field_hex("NumberOfTools", x.ntools.get(endian));
                    if let Some(tools) = x.tools(endian, data).print_err(p) {
                        for tool in tools {
                            p.group("BuildToolVersion", |p| {
                                p.field_consts("Tool", tool.tool.get(endian), Tool::NAMES);
                                p.field("Version", tool.version.get(endian));
                            });
                        }
                    }
                });
            }
            LoadCommandVariant::FilesetEntry(x) => {
                p.group("FilesetEntryCommand", |p| {
                    p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
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
                    p.field_consts("Cmd", command.cmd(), LoadCommandType::NAMES);
                    p.field_hex("CmdSize", command.cmdsize());
                });
            }
        }
    } else {
        p.group("LoadCommand", |p| {
            p.field_consts("Cmd", command.cmd(), LoadCommandType::NAMES);
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
    state: &mut MachState<S::Endian>,
) {
    if !p.options.macho_load_commands
        && !p.options.segments
        && !p.options.sections
        && !p.options.relocations
    {
        return;
    }
    p.group("SegmentCommand", |p| {
        p.field_consts("Cmd", segment.cmd(endian), LoadCommandType::NAMES);
        p.field_hex("CmdSize", segment.cmdsize(endian));
        p.field_inline_string("SegmentName", segment.name());
        if p.options.macho_load_commands || p.options.segments {
            p.field_hex("VmAddress", segment.vmaddr(endian).into());
            p.field_hex("VmSize", segment.vmsize(endian).into());
            p.field_hex("FileOffset", segment.fileoff(endian).into());
            p.field_hex("FileSize", segment.filesize(endian).into());
            p.field_flags("MaxProt", segment.maxprot(endian), VmProt::NAMES);
            p.field_flags("InitProt", segment.initprot(endian), VmProt::NAMES);
            p.field("NumberOfSections", segment.nsects(endian));
            p.field_flags("Flags", segment.flags(endian), SegmentFlags::NAMES);
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
    state: &mut MachState<S::Endian>,
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
            p.field_flags("Flags", section.flags(endian), SectionFlags::NAMES);
            p.field_hex("Reserved1", section.reserved1(endian));
            p.field_hex("Reserved2", section.reserved2(endian));
            if let Some(indirect_symbols) = section
                .indirect_symbols(endian, state.indirect_symbols)
                .print_err(p)
            {
                for (index, val) in indirect_symbols.iter().enumerate() {
                    p.group("IndirectSymbol", |p| {
                        p.field("Index", index);
                        let indirect = val.get(endian);
                        if let Some(index) = indirect.index() {
                            if let Some(name) = state.symbols.get(index as usize).copied() {
                                p.field_string_option("Symbol", index, name);
                            } else {
                                p.field_hex("Symbol", index);
                            }
                        } else {
                            p.field_flags("Symbol", indirect, IndirectSymbol::NAMES);
                        }
                    });
                }
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
    state: &MachState<S::Endian>,
) {
    if !p.options.relocations {
        return;
    }
    if let Some(relocations) = section.relocations(endian, data).print_err(p) {
        let names = macho::machine_names(state.cputype);
        for relocation in relocations {
            if relocation.r_scattered(endian, state.cputype) {
                let info = relocation.scattered_info(endian);
                p.group("ScatteredRelocationInfo", |p| {
                    p.field_hex("Address", info.r_address);
                    p.field("PcRel", if info.r_pcrel { "yes" } else { "no" });
                    p.field("Length", info.r_length);
                    p.field_consts("Type", info.r_type, names.reloc);
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
                    p.field_consts("Type", info.r_type, names.reloc);
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
    state: &MachState<Mach::Endian>,
) {
    if !p.options.macho_load_commands && !p.options.symbols {
        return;
    }
    p.group("SymtabCommand", |p| {
        p.field_consts("Cmd", symtab.cmd.get(endian), LoadCommandType::NAMES);
        p.field_hex("CmdSize", symtab.cmdsize.get(endian));
        p.field_hex("SymbolOffset", symtab.symoff.get(endian));
        p.field_hex("NumberOfSymbols", symtab.nsyms.get(endian));
        p.field_hex("StringOffset", symtab.stroff.get(endian));
        p.field_hex("StringSize", symtab.strsize.get(endian));
        print_symtab_symbols::<Mach>(p, endian, data, symtab, state);
    });
}

fn print_dysymtab<Mach: MachHeader>(
    p: &mut Printer<'_>,
    endian: Mach::Endian,
    dysymtab: &DysymtabCommand<Mach::Endian>,
) {
    if !p.options.macho_load_commands && !p.options.symbols {
        return;
    }
    p.group("DysymtabCommand", |p| {
        p.field_consts("Cmd", dysymtab.cmd.get(endian), LoadCommandType::NAMES);
        p.field_hex("CmdSize", dysymtab.cmdsize.get(endian));
        // TODO: dump the tables these are all pointing to
        p.field("IndexOfLocalSymbols", dysymtab.ilocalsym.get(endian));
        p.field("NumberOfLocalSymbols", dysymtab.nlocalsym.get(endian));
        p.field(
            "IndexOfExternallyDefinedSymbols",
            dysymtab.iextdefsym.get(endian),
        );
        p.field(
            "NumberOfExternallyDefinedSymbols",
            dysymtab.nextdefsym.get(endian),
        );
        p.field("IndexOfUndefinedSymbols", dysymtab.iundefsym.get(endian));
        p.field("NumberOfUndefinedSymbols", dysymtab.nundefsym.get(endian));
        p.field_hex("TocOffset", dysymtab.tocoff.get(endian));
        p.field("NumberOfTocEntries", dysymtab.ntoc.get(endian));
        p.field_hex("ModuleTableOffset", dysymtab.modtaboff.get(endian));
        p.field("NumberOfModuleTableEntries", dysymtab.nmodtab.get(endian));
        p.field_hex("ExternalRefSymbolOffset", dysymtab.extrefsymoff.get(endian));
        p.field(
            "NumberOfExternalRefSymbols",
            dysymtab.nextrefsyms.get(endian),
        );
        p.field_hex("IndirectSymbolOffset", dysymtab.indirectsymoff.get(endian));
        p.field(
            "NumberOfIndirectSymbols",
            dysymtab.nindirectsyms.get(endian),
        );
        p.field_hex("ExternalRelocationOffset", dysymtab.extreloff.get(endian));
        p.field("NumberOfExternalRelocations", dysymtab.nextrel.get(endian));
        p.field_hex("LocalRelocationOffset", dysymtab.locreloff.get(endian));
        p.field("NumberOfLocalRelocations", dysymtab.nlocrel.get(endian));
    });
}

fn print_symtab_symbols<Mach: MachHeader>(
    p: &mut Printer<'_>,
    endian: Mach::Endian,
    data: &[u8],
    symtab: &SymtabCommand<Mach::Endian>,
    state: &MachState<Mach::Endian>,
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
                if let Some(stab) = nlist.stab() {
                    p.field_consts("Type", stab, SymbolStab::NAMES);
                } else {
                    p.field_flags("Type", n_type, SymbolFlags::NAMES);
                }
                let n_sect = nlist.n_sect();
                let name = state.sections.get(n_sect as usize).map(|name| &name[..]);
                p.field_string_option("Section", n_sect, name);
                let n_desc = nlist.n_desc(endian);
                if nlist.is_stab() {
                    p.field_hex("Desc", n_desc);
                } else if nlist.is_undefined() {
                    if state.filetype == MH_OBJECT {
                        p.field_flags("Desc", n_desc, SymbolDesc::NAMES_UNDEFINED);
                        // TODO: alignment for common symbols
                    } else {
                        let mut n_desc_bits = n_desc.with_reference(SymbolReference(0));
                        if state.twolevel {
                            n_desc_bits = n_desc_bits.with_library(SymbolLibrary(0));
                        }
                        p.field_hex("Desc", n_desc);
                        p.flag_const::<SymbolDesc, _>(n_desc.reference(), SymbolReference::NAMES);
                        p.flag_bits(n_desc_bits, SymbolDesc::NAMES_UNDEFINED);
                        if state.twolevel {
                            // TODO: display library name
                            p.field_consts("DylibOrdinal", n_desc.library(), SymbolLibrary::NAMES);
                        }
                    }
                } else {
                    p.field_flags("Desc", n_desc, SymbolDesc::NAMES_DEFINED);
                }
                p.field_hex("Value", nlist.n_value(endian).into());
            });
        }
    }
}

fn print_linkedit_data<Mach: MachHeader>(
    p: &mut Printer<'_>,
    endian: Mach::Endian,
    linkedit: &LinkeditDataCommand<Mach::Endian>,
    state: &MachState<Mach::Endian>,
) {
    let cmd = linkedit.cmd.get(endian);
    let function_starts = p.options.macho_function_starts && cmd == LC_FUNCTION_STARTS;
    let exports_trie = p.options.macho_exports_trie && cmd == LC_DYLD_EXPORTS_TRIE;
    if !p.options.macho_load_commands && !function_starts && !exports_trie {
        return;
    }
    p.group("LinkeditDataCommand", |p| {
        p.field_consts("Cmd", cmd, LoadCommandType::NAMES);
        p.field_hex("CmdSize", linkedit.cmdsize.get(endian));
        p.field_hex("DataOffset", linkedit.dataoff.get(endian));
        p.field_hex("DataSize", linkedit.datasize.get(endian));
        if function_starts {
            print_function_starts::<Mach>(p, endian, linkedit, state);
        }
        if exports_trie {
            print_exports_trie(p, linkedit.exports_trie(endian, state.linkedit_data));
        }
    });
}

fn print_function_starts<Mach: MachHeader>(
    p: &mut Printer<'_>,
    endian: Mach::Endian,
    linkedit: &LinkeditDataCommand<Mach::Endian>,
    state: &MachState<Mach::Endian>,
) {
    let Some(mut function_starts) = linkedit
        .function_starts(endian, state.linkedit_data, state.text_segment_addr)
        .print_err(p)
    else {
        return;
    };
    p.group("FunctionStarts", |p| {
        while let Some(Some(addr)) = function_starts.next().print_err(p) {
            p.field_hex("Address", addr);
        }
    });
}

fn print_exports_trie(
    p: &mut Printer<'_>,
    exports_trie: object::read::Result<ExportsTrieIterator<'_>>,
) {
    let Some(mut exports_trie) = exports_trie.print_err(p) else {
        return;
    };
    while let Some(Some(export_symbol)) = exports_trie.next().print_err(p) {
        p.group("ExportSymbol", |p| {
            p.field_inline_string("Name", export_symbol.name());
            p.field_flags("Flags", export_symbol.flags(), ExportSymbolFlags::NAMES);
            match export_symbol.data() {
                ExportData::Regular { address } => p.field_hex("Address", address),
                ExportData::Reexport {
                    dylib_ordinal,
                    import_name,
                } => {
                    p.field_hex("DylibOrdinal", dylib_ordinal);
                    p.field_inline_string("ImportName", import_name);
                }
                ExportData::StubAndResolver {
                    stub_address,
                    resolver_address,
                } => {
                    p.field_hex("StubAddress", stub_address);
                    p.field_hex("ResolverAddress", resolver_address);
                }
            }
        });
    }
}

fn print_dyld_info<Mach: MachHeader>(
    p: &mut Printer<'_>,
    endian: Mach::Endian,
    x: &DyldInfoCommand<Mach::Endian>,
    state: &MachState<Mach::Endian>,
) {
    p.group("DyldInfoCommand", |p| {
        p.field_consts("Cmd", x.cmd.get(endian), LoadCommandType::NAMES);
        p.field_hex("CmdSize", x.cmdsize.get(endian));
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

        let pointer_size = Mach::pointer_size();
        if x.rebase_size.get(endian) != 0 {
            p.group("RebaseOperations", |p| {
                print_rebase_operations(p, x.rebase_operations(endian, state.linkedit_data));
            });
            p.group("Rebases", |p| {
                print_rebases(p, x.rebases(endian, state.linkedit_data, pointer_size));
            });
        }
        if x.bind_size.get(endian) != 0 {
            p.group("BindOperations", |p| {
                print_bind_operations(p, x.bind_operations(endian, state.linkedit_data));
            });
            p.group("Binds", |p| {
                print_binds(p, x.binds(endian, state.linkedit_data, pointer_size));
            });
        }
        if x.weak_bind_size.get(endian) != 0 {
            p.group("WeakBindOperations", |p| {
                print_bind_operations(p, x.weak_bind_operations(endian, state.linkedit_data));
            });
            p.group("WeakBinds", |p| {
                print_binds(p, x.weak_binds(endian, state.linkedit_data, pointer_size));
            });
        }
        if x.lazy_bind_size.get(endian) != 0 {
            p.group("LazyBindOperations", |p| {
                print_bind_operations(p, x.lazy_bind_operations(endian, state.linkedit_data));
            });
            p.group("LazyBinds", |p| {
                print_binds(p, x.lazy_binds(endian, state.linkedit_data, pointer_size));
            });
        }
        if x.export_size.get(endian) != 0 {
            p.group("ExportsTrie", |p| {
                print_exports_trie(p, x.exports_trie(endian, state.linkedit_data));
            });
        }
    });
}

fn print_rebase_operations(
    p: &mut Printer<'_>,
    operations: object::read::Result<RebaseOperationIterator<'_>>,
) {
    let Some(mut operations) = operations.print_err(p) else {
        return;
    };
    while let Some(Some((opcode, operation))) = operations.next().print_err(p) {
        p.group("Operation", |p| {
            p.field_consts("Opcode", opcode, RebaseOpcode::NAMES);
            match operation {
                RebaseOperation::Done => {}
                RebaseOperation::SetType { kind } => {
                    p.field_consts("Type", kind, RebaseType::NAMES);
                }
                RebaseOperation::SetSegmentAndOffset {
                    index: segment_index,
                    offset,
                } => {
                    p.field("SegmentIndex", segment_index);
                    p.field_hex("Offset", offset);
                }
                RebaseOperation::AddAddr { offset } => {
                    p.field_hex("Offset", offset);
                }
                RebaseOperation::AddAddrScaled { count } => {
                    p.field("Count", count);
                }
                RebaseOperation::DoRebaseTimes { count } => {
                    p.field("Count", count);
                }
                RebaseOperation::DoRebaseAddAddr { offset } => {
                    p.field_hex("Offset", offset);
                }
                RebaseOperation::DoRebaseTimesSkipping { count, skip } => {
                    p.field("Count", count);
                    p.field_hex("Skip", skip);
                }
            }
        });
    }
}

fn print_bind_operations(
    p: &mut Printer<'_>,
    operations: object::read::Result<BindOperationIterator<'_>>,
) {
    let Some(mut operations) = operations.print_err(p) else {
        return;
    };
    while let Some(Some((opcode, operation))) = operations.next().print_err(p) {
        p.group("Operation", |p| {
            p.field_consts("Opcode", opcode, BindOpcode::NAMES);
            match operation {
                BindOperation::Done => {}
                BindOperation::SetDylibOrdinal { ordinal } => {
                    p.field("Ordinal", ordinal);
                }
                BindOperation::SetDylibSpecial { ordinal } => {
                    p.field_consts_display("Ordinal", ordinal, BindDylib::NAMES);
                }
                BindOperation::SetSymbol { flags, name } => {
                    p.field_flags("Flags", flags, BindSymbolFlags::NAMES);
                    p.field_inline_string("Name", name);
                }
                BindOperation::SetType { kind } => {
                    p.field_consts("Type", kind, BindType::NAMES);
                }
                BindOperation::SetAddend { addend } => {
                    p.field("Addend", addend);
                }
                BindOperation::SetSegmentAndOffset {
                    segment_index,
                    offset,
                } => {
                    p.field("SegmentIndex", segment_index);
                    p.field_hex("Offset", offset);
                }
                BindOperation::AddAddr { offset } => {
                    p.field_hex("Offset", offset);
                }
                BindOperation::DoBind => {}
                BindOperation::DoBindAddAddr { offset } => {
                    p.field_hex("Offset", offset);
                }
                BindOperation::DoBindAddAddrScaled { count } => {
                    p.field("Count", count);
                }
                BindOperation::DoBindTimesSkipping { count, skip } => {
                    p.field("Count", count);
                    p.field_hex("Skip", skip);
                }
            }
        });
    }
}

fn print_rebases(p: &mut Printer<'_>, rebases: object::read::Result<RebaseIterator<'_>>) {
    let Some(mut rebases) = rebases.print_err(p) else {
        return;
    };
    while let Some(Some(rebase)) = rebases.next().print_err(p) {
        p.group("Rebase", |p| {
            p.field("SegmentIndex", rebase.segment_index);
            p.field_hex("SegmentOffset", rebase.segment_offset);
            p.field_consts("Type", rebase.kind, RebaseType::NAMES);
        });
    }
}

fn print_binds(p: &mut Printer<'_>, binds: object::read::Result<BindIterator<'_>>) {
    let Some(mut binds) = binds.print_err(p) else {
        return;
    };
    while let Some(Some(bind)) = binds.next().print_err(p) {
        p.group("Bind", |p| {
            p.field("SegmentIndex", bind.segment_index);
            p.field_hex("SegmentOffset", bind.segment_offset);
            p.field_consts("Type", bind.kind, BindType::NAMES);
            p.field_consts_display("LibraryOrdinal", bind.dylib, BindDylib::NAMES);
            p.field_flags("Flags", bind.flags, BindSymbolFlags::NAMES);
            p.field_inline_string("Symbol", bind.symbol);
            p.field("Addend", bind.addend);
        });
    }
}

fn print_cputype(p: &mut Printer<'_>, cputype: CpuType, cpusubtype: CpuSubtype) {
    let names = macho::machine_names(cputype);
    p.field_consts("CpuType", cputype, macho::CpuType::NAMES);
    p.field_flags("CpuSubtype", cpusubtype, names.cpusubtype);
}
