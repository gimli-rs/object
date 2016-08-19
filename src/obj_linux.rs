extern crate elf;
use std::path::Path;

/// The parsed object file type.
pub type File = elf::File;

/// Open and parse the object file at the given path.
pub fn open<P>(path: P) -> File
    where P: AsRef<Path>
{
    let path = path.as_ref();
    elf::File::open_path(path).expect("Could not open file")
}

/// Get the contents of the section named `section_name`, if such
/// a section exists.
pub fn get_section<'a>(file: &'a File, section_name: &str) -> Option<&'a [u8]> {
    file.sections
        .iter()
        .find(|s| s.shdr.name == section_name)
        .map(|s| &s.data[..])
}

/// Return true if the file is little endian, false if it is big endian.
pub fn is_little_endian(file: &File) -> bool {
    match file.ehdr.data {
        elf::types::ELFDATA2LSB => true,
        elf::types::ELFDATA2MSB => false,
        otherwise => panic!("Unknown endianity: {}", otherwise),
    }
}
