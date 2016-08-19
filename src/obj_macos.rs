extern crate mach_o;

use object_trait::Object;

use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::mem;
use std::path::Path;

pub struct MachO(Vec<u8>);

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

impl Object for MachO {
    fn open<P>(path: P) -> MachO
        where P: AsRef<Path>
    {
        let mut file = fs::File::open(path).expect("Could not open file");
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).expect("Could not read file");
        MachO(buf)
    }

    fn get_section(&self, section_name: &str) -> Option<&[u8]> {
        let parsed = mach_o::Header::new(&self.0[..]).expect("Could not parse macho-o file");

        let segment_name = CString::new("__DWARF").unwrap();
        let section_name = translate_section_name(section_name);
        parsed.get_section(&segment_name, &section_name).map(|s| s.data())
    }

    fn is_little_endian(&self) -> bool {
        let parsed = mach_o::Header::new(&self.0[..]).expect("Could not parse macho-o file");

        let bytes = [1, 0, 0, 0u8];
        let int: u32 = unsafe { mem::transmute(bytes) };
        let native_byteorder_is_little = int == 1;

        match (native_byteorder_is_little, parsed.is_native_byteorder()) {
            (true, b) => b,
            (false, b) => !b,
        }
    }
}
