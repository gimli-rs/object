use std::fs::File;
use std::io::Read;
use object::{Object, ObjectSection, File as ObjectFile};

/// Reads a ELF-file and displays the content of the ".boot" section.
fn main() {
    let mut file = File::open("<path to ELF-file>").unwrap();
    let mut data = vec![];
    file.read_to_end(&mut data).unwrap();
    let data = data.into_boxed_slice();
    let obj_file = ObjectFile::parse(&*data).unwrap();
    let section = obj_file.section_by_name(".boot").unwrap();
    let data = section.data().unwrap();
    println!("{:#x?}", data)
}
