/// An object file.
pub trait Object<'a>: Sized {
    /// An associated error type for when parsing or some other operation fails.
    type Error;

    /// Parse the raw object file data.
    fn parse(input: &'a [u8]) -> Result<Self, Self::Error>;

    /// Get the contents of the section named `section_name`, if such
    /// a section exists.
    fn get_section(&self, section_name: &str) -> Option<&[u8]>;

    /// Return true if the file is little endian, false if it is big endian.
    fn is_little_endian(&self) -> bool;
}
