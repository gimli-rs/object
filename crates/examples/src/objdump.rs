use object::read::archive::ArchiveFile;
use object::read::macho::{DyldCache, FatArch, FatHeader};
use object::{Endianness, Object, ObjectComdat, ObjectSection, ObjectSymbol};
use std::io::{Result, Write};

pub fn print<W: Write, E: Write>(
    w: &mut W,
    e: &mut E,
    file: &[u8],
    extra_files: &[&[u8]],
    member_names: Vec<String>,
) -> Result<()> {
    let mut member_names: Vec<_> = member_names.into_iter().map(|name| (name, false)).collect();

    if let Ok(archive) = ArchiveFile::parse(file) {
        writeln!(w, "Format: Archive (kind: {:?})", archive.kind())?;
        for member in archive.members() {
            match member {
                Ok(member) => {
                    if find_member(&mut member_names, member.name()) {
                        writeln!(w)?;
                        writeln!(w, "{}:", String::from_utf8_lossy(member.name()))?;
                        if let Ok(data) = member.data(file) {
                            dump_object(w, e, data)?;
                        }
                    }
                }
                Err(err) => writeln!(e, "Failed to parse archive member: {}", err)?,
            }
        }
    } else if let Ok(arches) = FatHeader::parse_arch32(file) {
        writeln!(w, "Format: Mach-O Fat 32")?;
        for arch in arches {
            writeln!(w)?;
            writeln!(w, "Fat Arch: {:?}", arch.architecture())?;
            match arch.data(file) {
                Ok(data) => dump_object(w, e, data)?,
                Err(err) => writeln!(e, "Failed to parse Fat 32 data: {}", err)?,
            }
        }
    } else if let Ok(arches) = FatHeader::parse_arch64(file) {
        writeln!(w, "Format: Mach-O Fat 64")?;
        for arch in arches {
            writeln!(w)?;
            writeln!(w, "Fat Arch: {:?}", arch.architecture())?;
            match arch.data(file) {
                Ok(data) => dump_object(w, e, data)?,
                Err(err) => writeln!(e, "Failed to parse Fat 64 data: {}", err)?,
            }
        }
    } else if let Ok(cache) = DyldCache::<Endianness>::parse(file, extra_files) {
        writeln!(w, "Format: dyld cache {:?}-endian", cache.endianness())?;
        writeln!(w, "Architecture: {:?}", cache.architecture())?;
        for image in cache.images() {
            let path = match image.path() {
                Ok(path) => path,
                Err(err) => {
                    writeln!(e, "Failed to parse dydld image name: {}", err)?;
                    continue;
                }
            };
            if !find_member(&mut member_names, path.as_bytes()) {
                continue;
            }
            writeln!(w)?;
            writeln!(w, "{}:", path)?;
            let file = match image.parse_object() {
                Ok(file) => file,
                Err(err) => {
                    writeln!(e, "Failed to parse file: {}", err)?;
                    continue;
                }
            };
            dump_parsed_object(w, e, &file)?;
        }
    } else {
        dump_object(w, e, file)?;
    }

    for (name, found) in member_names {
        if !found {
            writeln!(e, "Failed to find member '{}", name)?;
        }
    }
    Ok(())
}

fn find_member(member_names: &mut [(String, bool)], name: &[u8]) -> bool {
    if member_names.is_empty() {
        return true;
    }
    match member_names.iter().position(|x| x.0.as_bytes() == name) {
        Some(i) => {
            member_names[i].1 = true;
            true
        }
        None => false,
    }
}

fn dump_object<W: Write, E: Write>(w: &mut W, e: &mut E, data: &[u8]) -> Result<()> {
    match object::File::parse(data) {
        Ok(file) => {
            dump_parsed_object(w, e, &file)?;
        }
        Err(err) => {
            writeln!(e, "Failed to parse file: {}", err)?;
        }
    }
    Ok(())
}

fn dump_parsed_object<W: Write, E: Write>(w: &mut W, e: &mut E, file: &object::File) -> Result<()> {
    writeln!(
        w,
        "Format: {:?} {:?}-endian {}-bit",
        file.format(),
        file.endianness(),
        if file.is_64() { "64" } else { "32" }
    )?;
    writeln!(w, "Kind: {:?}", file.kind())?;
    writeln!(w, "Architecture: {:?}", file.architecture())?;
    writeln!(w, "Flags: {:x?}", file.flags())?;
    writeln!(
        w,
        "Relative Address Base: {:x?}",
        file.relative_address_base()
    )?;
    writeln!(w, "Entry Address: {:x?}", file.entry())?;

    match file.mach_uuid() {
        Ok(Some(uuid)) => writeln!(w, "Mach UUID: {:x?}", uuid)?,
        Ok(None) => {}
        Err(err) => writeln!(e, "Failed to parse Mach UUID: {}", err)?,
    }
    match file.build_id() {
        Ok(Some(build_id)) => writeln!(w, "Build ID: {:x?}", build_id)?,
        Ok(None) => {}
        Err(err) => writeln!(e, "Failed to parse build ID: {}", err)?,
    }
    match file.gnu_debuglink() {
        Ok(Some((filename, crc))) => writeln!(
            w,
            "GNU debug link: {} CRC: {:08x}",
            String::from_utf8_lossy(filename),
            crc,
        )?,
        Ok(None) => {}
        Err(err) => writeln!(e, "Failed to parse GNU debug link: {}", err)?,
    }
    match file.gnu_debugaltlink() {
        Ok(Some((filename, build_id))) => writeln!(
            w,
            "GNU debug alt link: {}, build ID: {:x?}",
            String::from_utf8_lossy(filename),
            build_id,
        )?,
        Ok(None) => {}
        Err(err) => writeln!(e, "Failed to parse GNU debug alt link: {}", err)?,
    }
    match file.pdb_info() {
        Ok(Some(info)) => writeln!(
            w,
            "PDB file: {}, GUID: {:x?}, Age: {}",
            String::from_utf8_lossy(info.path()),
            info.guid(),
            info.age()
        )?,
        Ok(None) => {}
        Err(err) => writeln!(e, "Failed to parse PE CodeView info: {}", err)?,
    }

    for segment in file.segments() {
        writeln!(w, "{:x?}", segment)?;
    }

    for section in file.sections() {
        writeln!(w, "{}: {:x?}", section.index().0, section)?;
    }

    for comdat in file.comdats() {
        write!(w, "{:?} Sections:", comdat)?;
        for section in comdat.sections() {
            write!(w, " {}", section.0)?;
        }
        writeln!(w)?;
    }

    writeln!(w)?;
    writeln!(w, "Symbols")?;
    for symbol in file.symbols() {
        writeln!(w, "{}: {:x?}", symbol.index().0, symbol)?;
    }

    for section in file.sections() {
        if section.relocations().next().is_some() {
            writeln!(
                w,
                "\n{} relocations",
                section.name().unwrap_or("<invalid name>")
            )?;
            for relocation in section.relocations() {
                writeln!(w, "{:x?}", relocation)?;
            }
        }
    }

    writeln!(w)?;
    writeln!(w, "Dynamic symbols")?;
    for symbol in file.dynamic_symbols() {
        writeln!(w, "{}: {:x?}", symbol.index().0, symbol)?;
    }

    if let Some(relocations) = file.dynamic_relocations() {
        writeln!(w)?;
        writeln!(w, "Dynamic relocations")?;
        for relocation in relocations {
            writeln!(w, "{:x?}", relocation)?;
        }
    }

    match file.imports() {
        Ok(imports) => {
            if !imports.is_empty() {
                writeln!(w)?;
                for import in imports {
                    writeln!(w, "{:x?}", import)?;
                }
            }
        }
        Err(err) => writeln!(e, "Failed to parse imports: {}", err)?,
    }

    match file.exports() {
        Ok(exports) => {
            if !exports.is_empty() {
                writeln!(w)?;
                for export in exports {
                    writeln!(w, "{:x?}", export)?;
                }
            }
        }
        Err(err) => writeln!(e, "Failed to parse exports: {}", err)?,
    }

    Ok(())
}
