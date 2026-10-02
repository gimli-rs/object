use object::build;
use object::macho;

fn read_base() -> Vec<u8> {
    std::fs::read("testfiles/macho/base-x86_64").unwrap()
}

fn read_base_object() -> Vec<u8> {
    std::fs::read("testfiles/macho/base-x86_64.o").unwrap()
}

fn write(builder: build::macho::Builder<'_>) -> Result<Vec<u8>, build::Error> {
    let mut buf = Vec::new();
    builder.write(&mut buf)?;
    Ok(buf)
}

// Test that the builder can rewrite a Mach-O executable and object file.
#[test]
fn test_rewrite() {
    for data in [read_base(), read_base_object()] {
        let builder = build::macho::Builder::read(&*data).unwrap();
        let out = write(builder).unwrap();
        let builder = build::macho::Builder::read(&*out).unwrap();
        assert_eq!(write(builder).unwrap(), out);
    }
}

// Test that invalid section alignments and addresses return an error.
#[test]
fn test_invalid_section() {
    // The alignment is a power of 2 exponent. Only used for the layout of object files.
    let data = read_base_object();
    for align in [32, 63, 64, u32::MAX] {
        let mut builder = build::macho::Builder::read(&*data).unwrap();
        // Not the first section: the first one starts at address 0, which any alignment fits.
        let section = builder.sections.iter_mut().nth(1).unwrap();
        section.align = align;
        assert!(write(builder).is_err(), "align {align}");
    }

    let data = read_base();

    // A section address near the end of the address space.
    let mut builder = build::macho::Builder::read(&*data).unwrap();
    for section in builder.sections.iter_mut() {
        section.addr = u64::MAX - 1;
    }
    assert!(write(builder).is_err());

    // A segment address range near the end of the address space.
    let mut builder = build::macho::Builder::read(&*data).unwrap();
    for segment in builder.segments.iter_mut() {
        segment.vmsize = u64::MAX;
    }
    assert!(write(builder).is_err());
}

// Test that section data that would be written before the end of the preceding data
// (the load commands or an earlier section) returns an error.
#[test]
fn test_overlapping_section_data() {
    let data = read_base();
    let mut builder = build::macho::Builder::read(&*data).unwrap();
    // Make the segment that contains the header and load commands start its first section at
    // the start of the segment, so the section data would overwrite the load commands.
    let segment = builder
        .segments
        .iter()
        .find(|s| s.segname() == b"__TEXT")
        .unwrap();
    let vmaddr = segment.vmaddr;
    let first = segment.sections[0];
    builder.sections.get_mut(first).addr = vmaddr;
    assert!(write(builder).is_err());
}

// Test that multiple LC_SYMTAB or LC_CODE_SIGNATURE commands return an error when writing.
#[test]
fn test_duplicate_load_commands() {
    let data = read_base();

    let mut builder = build::macho::Builder::read(&*data).unwrap();
    builder.commands.push(build::macho::LoadCommand::Symtab);
    assert!(write(builder).is_err());

    let mut builder = build::macho::Builder::read(&*data).unwrap();
    for _ in 0..2 {
        builder
            .commands
            .push(build::macho::LoadCommand::LinkeditData {
                cmd: macho::LC_CODE_SIGNATURE,
                data: vec![0u8; 16].into(),
            });
    }
    assert!(write(builder).is_err());
}
