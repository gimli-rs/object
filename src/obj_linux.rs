extern crate elf;
use std::path::Path;

use object_trait::Object;

pub struct Elf(elf::File);

impl Object for Elf {
    fn open<P>(path: P) -> Self
        where P: AsRef<Path>
    {
        let path = path.as_ref();
        Elf(elf::File::open_path(path).expect("Could not open file"))
    }

    fn get_section(&self, section_name: &str) -> Option<&[u8]> {
        self.0.sections
            .iter()
            .find(|s| s.shdr.name == section_name)
            .map(|s| &s.data[..])
    }

    fn is_little_endian(&self) -> bool {
        match self.0.ehdr.data {
            elf::types::ELFDATA2LSB => true,
            elf::types::ELFDATA2MSB => false,
            otherwise => panic!("Unknown endianity: {}", otherwise),
        }
    }
}
