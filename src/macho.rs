extern crate mach_o;

use object_trait::Object;

use std::ffi::CString;
use std::mem;

/// An error parsing a mach-o object file.
pub use mach_o::Error;

/// A mach-o object file.
pub struct MachO<'a>(mach_o::Header<'a>);

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

impl<'a> Object<'a> for MachO<'a> {
    type Error = Error;

    fn parse(input: &'a [u8]) -> Result<MachO<'a>, Self::Error> {
        mach_o::Header::new(input).map(MachO)
    }

    fn get_section(&self, section_name: &str) -> Option<&[u8]> {
        let segment_name = CString::new("__DWARF").unwrap();
        let section_name = translate_section_name(section_name);
        self.0.get_section(&segment_name, &section_name)
            .map(|s| s.data())
    }

    fn is_little_endian(&self) -> bool {
        let bytes = [1, 0, 0, 0u8];
        let int: u32 = unsafe { mem::transmute(bytes) };
        let native_byteorder_is_little = int == 1;

        match (native_byteorder_is_little, self.0.is_native_byteorder()) {
            (true, b) => b,
            (false, b) => !b,
        }
    }
}
