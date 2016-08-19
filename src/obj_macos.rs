extern crate mach_o;

use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::mem;
use std::path::Path;

pub type File = Vec<u8>;

pub fn open<P>(path: P) -> File
    where P: AsRef<Path>
{
    let mut file = fs::File::open(path).expect("Could not open file");
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).expect("Could not read file");
    buf
}

// Translate the "." prefix to the "__" prefix used by OSX/Mach-O, eg
// ".debug_info" to "__debug_info".
fn translate_section_name(section_name: &str) -> CString {
    let mut name = Vec::with_capacity(section_name.len() + 1);
    name.push(b'_');
    name.push(b'_');
    for ch in &section_name.as_bytes()[1..] {
        name.push(*ch);
    }
    unsafe { CString::from_vec_unchecked(name) }
}

pub fn get_section<'a>(file: &'a File, section_name: &str) -> Option<&'a [u8]> {
    let parsed = mach_o::Header::new(&file[..]).expect("Could not parse macho-o file");

    let segment_name = CString::new("__DWARF").unwrap();
    let section_name = translate_section_name(section_name);
    parsed.get_section(&segment_name, &section_name).map(|s| s.data())
}

pub fn is_little_endian(file: &File) -> bool {
    let parsed = mach_o::Header::new(&file[..]).expect("Could not parse macho-o file");

    let bytes = [1, 0, 0, 0u8];
    let int: u32 = unsafe { mem::transmute(bytes) };
    let native_byteorder_is_little = int == 1;

    match (native_byteorder_is_little, parsed.is_native_byteorder()) {
        (true, b) => b,
        (false, b) => !b,
    }
}
