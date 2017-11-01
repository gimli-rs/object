use Symbol;

/// An object file.
pub trait Object<'a>: Sized {
    /// A section in the object file.
    type Section: ObjectSection<'a>;

    /// An iterator over the sections in the object file.
    type SectionIterator: Iterator<Item = Self::Section>;

    /// Parse the raw object file data.
    fn parse(data: &'a [u8]) -> Result<Self, &'static str>;

    /// Get the contents of the section named `section_name`, if such
    /// a section exists.
    fn section_data_by_name(&self, section_name: &str) -> Option<&'a [u8]>;

    /// Get an iterator over the sections in the file.
    // TODO: avoid 'a on self using Associated Type Constructor
    fn sections(&'a self) -> Self::SectionIterator;

    /// Get a `Vec` of the symbols defined in the file.
    /// The symbols are unsorted and have the same order as the symbols in the file.
    fn symbols(&self) -> Vec<Symbol<'a>>;

    /// Return true if the file is little endian, false if it is big endian.
    fn is_little_endian(&self) -> bool;
}

/// A section defined in an object file.
pub trait ObjectSection<'a> {
    /// Returns the address of the section.
    fn address(&self) -> u64;

    /// Returns the size of the section.
    fn size(&self) -> u64;

    /// Returns a reference to the contents of the section.
    fn data(&self) -> &'a [u8];

    /// Returns the name of the section.
    fn name(&self) -> Option<&str>;

    /// Returns the name of the segment for this section.
    fn segment_name(&self) -> Option<&str>;
}
