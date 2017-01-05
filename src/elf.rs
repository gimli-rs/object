extern crate xmas_elf;

use object_trait::Object;

/// An ELF object file.
pub struct Elf<'a>(xmas_elf::ElfFile<'a>);

impl<'a> Object<'a> for Elf<'a> {
    type Error = ();

    fn parse(input: &'a [u8]) -> Result<Elf<'a>, Self::Error> {
        Ok(Elf(xmas_elf::ElfFile::new(input)))
    }

    fn get_section(&self, section_name: &str) -> Option<&[u8]> {
        self.0.find_section_by_name(section_name)
            .map(|s| s.raw_data(&self.0))
    }

    fn is_little_endian(&self) -> bool {
        match self.0.header.pt1.data() {
            xmas_elf::header::Data::LittleEndian => true,
            xmas_elf::header::Data::BigEndian => false,
            ref otherwise => panic!("Unknown endianity: {:?}", otherwise),
        }
    }
}
