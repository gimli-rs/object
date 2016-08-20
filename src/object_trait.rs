pub trait Object<'a> {
    /// Parse the raw object file data.
    fn parse(input: &'a [u8]) -> Self;

    /// Get the contents of the section named `section_name`, if such
    /// a section exists.
    fn get_section(&self, section_name: &str) -> Option<&[u8]>;

    /// Return true if the file is little endian, false if it is big endian.
    fn is_little_endian(&self) -> bool;
}
