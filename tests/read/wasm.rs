#![cfg(all(feature = "wasm", feature = "std"))]

use object::read::wasm::WasmFile;
use object::read::{Object, ObjectSection, RelocationTarget, SectionIndex};
use object::wasm;
use std::path::PathBuf;

fn read_testfile(name: &str) -> Vec<u8> {
    let path: PathBuf = ["testfiles", "wasm", name].iter().collect();
    std::fs::read(&path).unwrap_or_else(|err| panic!("{}: {}", path.display(), err))
}

#[test]
fn wasm_relocations_raw() {
    let data = read_testfile("reloc.o");
    let file = WasmFile::parse(&*data).unwrap();

    let code = file.wasm_section_by_id(wasm::SEC_CODE).unwrap();
    let code_relocs = code.wasm_relocations();
    assert_eq!(code_relocs.len(), code.relocations().count());

    // `R_WASM_TYPE_INDEX_LEB` keeps the raw type index instead of a section target.
    let type_reloc = code_relocs
        .iter()
        .find(|r| r.r_type == wasm::R_WASM_TYPE_INDEX_LEB)
        .unwrap();
    assert_eq!(
        *type_reloc,
        wasm::Relocation {
            r_type: wasm::R_WASM_TYPE_INDEX_LEB,
            r_offset: 0x3b,
            r_index: 0,
            r_addend: 0,
        }
    );
    let (_, generic) = code
        .relocations()
        .find(|(offset, _)| *offset == 0x3b)
        .unwrap();
    assert_eq!(
        generic.target(),
        RelocationTarget::Section(file.wasm_section_by_id(wasm::SEC_TYPE).unwrap().index())
    );

    // Data section relocations are relative to the data section payload.
    let data_section = file.wasm_section_by_id(wasm::SEC_DATA).unwrap();
    let data_relocs = data_section.wasm_relocations();
    assert_eq!(
        data_relocs
            .iter()
            .map(|r| (r.r_type, r.r_offset, r.r_index, r.r_addend))
            .collect::<Vec<_>>(),
        [
            (wasm::R_WASM_MEMORY_ADDR_I32, 0x25, 5, 0),
            (wasm::R_WASM_MEMORY_ADDR_I32, 0x2e, 5, 4),
            (wasm::R_WASM_TABLE_INDEX_I32, 0x37, 2, 0),
        ]
    );

    // Data segment sections return the subset of the data section relocations,
    // without adjusting the offsets.
    let (data_section_start, _) = data_section.file_range().unwrap();
    let mut segment_relocs = Vec::new();
    for section in file.sections() {
        if section.wasm_index().is_some() {
            continue;
        }
        let relocs = section.wasm_relocations();
        let (segment_start, segment_size) = section.file_range().unwrap();
        let segment_offset = segment_start - data_section_start;
        for reloc in relocs {
            let offset = u64::from(reloc.r_offset);
            assert!(offset >= segment_offset && offset < segment_offset + segment_size);
        }
        let generic_offsets = section
            .relocations()
            .map(|(offset, _)| offset + segment_offset)
            .collect::<Vec<_>>();
        let raw_offsets = relocs
            .iter()
            .map(|r| u64::from(r.r_offset))
            .collect::<Vec<_>>();
        assert_eq!(generic_offsets, raw_offsets);
        segment_relocs.extend_from_slice(relocs);
    }
    assert_eq!(segment_relocs, data_relocs);

    // Custom section relocations.
    let debug_info = file.section_by_name(".debug_info").unwrap();
    let debug_info_relocs = debug_info.wasm_relocations();
    assert!(!debug_info_relocs.is_empty());
    assert!(
        debug_info_relocs
            .iter()
            .all(|r| u64::from(r.r_offset) < debug_info.size())
    );

    // Sections without a `reloc.*` section have no relocations.
    let type_section = file.wasm_section_by_id(wasm::SEC_TYPE).unwrap();
    assert!(type_section.wasm_relocations().is_empty());
    assert!(
        file.wasm_section_by_index(SectionIndex(0))
            .unwrap()
            .wasm_relocations()
            .is_empty()
    );
}
