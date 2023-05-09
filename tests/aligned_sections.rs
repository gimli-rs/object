#![cfg(feature = "write")]

use object::{
    write::{Object, StreamingBuffer},
    Architecture, BinaryFormat, Endianness, SectionKind,
};

#[test]
fn aligned_sections() {
    let mut object = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);

    let text_section_id = object.add_section(vec![], b".text".to_vec(), SectionKind::Text);
    let text_section = object.section_mut(text_section_id);
    text_section.set_data(&[][..], 4096);

    let data_section_id = object.add_section(vec![], b".data".to_vec(), SectionKind::Data);
    let data_section = object.section_mut(data_section_id);
    data_section.set_data(&b"1234"[..], 16);

    let mut buffer = StreamingBuffer::new(vec![]);
    object.emit(&mut buffer).unwrap();
    buffer.result().unwrap();
}
