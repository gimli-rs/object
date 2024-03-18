use object::{build, elf};

// Test that offset 0 is supported for SHT_NOBITS sections.
#[test]
fn test_nobits_offset() {
    let mut builder = build::elf::Builder::new(object::Endianness::Little, true);
    builder.header.e_type = elf::ET_EXEC;
    builder.header.e_phoff = 0x40;

    let section = builder.sections.add();
    section.name = b".shstrtab"[..].into();
    section.sh_type = elf::SHT_STRTAB;
    section.data = build::elf::SectionData::SectionString;

    let section = builder.sections.add();
    section.name = b".bss"[..].into();
    section.sh_type = elf::SHT_NOBITS;
    section.sh_flags = (elf::SHF_ALLOC | elf::SHF_WRITE) as u64;
    section.sh_addr = 0x1000;
    section.sh_offset = 0;
    section.sh_size = 0x1000;
    section.sh_addralign = 16;
    section.data = build::elf::SectionData::UninitializedData(0x1000);
    let section_id = section.id();

    let segment = builder.segments.add();
    segment.p_type = elf::PT_LOAD;
    segment.p_flags = elf::PF_R | elf::PF_W;
    segment.p_offset = 0x1000;
    segment.p_vaddr = 0x1000;
    segment.p_paddr = 0x1000;
    segment.p_filesz = 0;
    segment.p_memsz = 0x1000;
    segment.p_align = 16;
    segment.sections.push(section_id);

    let mut buf = Vec::new();
    builder.write(&mut buf).unwrap();
}
