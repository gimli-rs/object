use std::path::Path;

pub trait Object {
    /// Open and parse the object file at the given path.
    fn open<P>(path: P) -> Self where P: AsRef<Path>;

    /// Get the contents of the section named `section_name`, if such
    /// a section exists.
    fn get_section(&self, section_name: &str) -> Option<&[u8]>;

    /// Return true if the file is little endian, false if it is big endian.
    fn is_little_endian(&self) -> bool;
}
