#![cfg(all(feature = "read", feature = "write", feature = "goff"))]

use object::read::goff::GoffFile;
use object::{Architecture, BinaryFormat, Endianness, SectionKind, write};

fn build() -> Vec<u8> {
    let mut object = write::Object::new(BinaryFormat::Goff, Architecture::S390x, Endianness::Big);
    let sec = object.add_section(
        Vec::new(),
        vec![0xC4, 0x6D, 0xC9, 0xD5, 0xC6, 0xD6],
        SectionKind::Debug,
    );
    object.append_section_data(sec, &[0x01, 0x02, 0x03, 0x04], 1);
    object.write().unwrap()
}

#[test]
fn txt_esdid_zero() {
    let mut bytes = build();
    // Locate the TXT record (ptv 0x031000 / 0x031100) on an 80-byte boundary and zero element_esdid.
    let mut patched = 0;
    for rec in bytes.chunks_mut(80) {
        if rec.len() == 80 && rec[0] == 0x03 && (rec[1] == 0x10 || rec[1] == 0x11) && rec[2] == 0x00
        {
            rec[4..8].copy_from_slice(&[0, 0, 0, 0]);
            patched += 1;
        }
    }
    assert!(patched > 0, "no TXT record found to patch");
    println!(
        "patched {} TXT record(s), {} bytes total",
        patched,
        bytes.len()
    );
    let r = GoffFile::parse(&bytes[..]);
    println!("parse result: {:?}", r.err());
}
