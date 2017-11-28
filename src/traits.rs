use {Machine, Symbol};

/// An object file.
pub trait Object<'data>: Sized {
    /// A segment in the object file.
    type Segment: ObjectSegment<'data>;

    /// An iterator over the segments in the object file.
    type SegmentIterator: Iterator<Item = Self::Segment>;

    /// A section in the object file.
    type Section: ObjectSection<'data>;

    /// An iterator over the sections in the object file.
    type SectionIterator: Iterator<Item = Self::Section>;

    /// Parse the raw object file data.
    fn parse(data: &'data [u8]) -> Result<Self, &'static str>;

    /// Get the machine type of the file.
    fn machine(&self) -> Machine;

    /// Get an iterator over the segments in the file.
    // TODO: avoid 'data on self using Associated Type Constructor
    fn segments(&'data self) -> Self::SegmentIterator;

    /// Get the contents of the section named `section_name`, if such
    /// a section exists.
    ///
    /// If `section_name` starts with a '.' then it is treated as a system section name,
    /// and is compared using the conventions specific to the object file format.
    /// For example, if ".text" is requested for a Mach-O object file, then the actual
    /// section name that is searched for is "__text".
    ///
    /// For some object files, multiple segments may contain sections with the same
    /// name. In this case, the first matching section will be used.
    fn section_data_by_name(&self, section_name: &str) -> Option<&'data [u8]>;

    /// Get an iterator over the sections in the file.
    // TODO: avoid 'data on self using Associated Type Constructor
    fn sections(&'data self) -> Self::SectionIterator;

    /// Get a `Vec` of the symbols defined in the file.
    /// The symbols are unsorted and have the same order as the symbols in the file.
    fn symbols(&self) -> Vec<Symbol<'data>>;

    /// Return true if the file is little endian, false if it is big endian.
    fn is_little_endian(&self) -> bool;
}

/// A loadable segment defined in an object file.
///
/// For ELF, this is a program header with type `PT_LOAD`.
/// For Mach-O, this is a load command with type `LC_SEGMENT` or `LC_SEGMENT_64`.
pub trait ObjectSegment<'data> {
    /// Returns the virtual address of the segment.
    fn address(&self) -> u64;

    /// Returns the size of the segment in memory.
    fn size(&self) -> u64;

    /// Returns a reference to the file contents of the segment.
    /// The length of this data may be different from the size of the
    /// segment in memory.
    fn data(&self) -> &'data [u8];

    /// Returns the name of the segment.
    fn name(&self) -> Option<&str>;
}

/// A section defined in an object file.
pub trait ObjectSection<'data> {
    /// Returns the address of the section.
    fn address(&self) -> u64;

    /// Returns the size of the section in memory.
    fn size(&self) -> u64;

    /// Returns a reference to the contents of the section.
    /// The length of this data may be different from the size of the
    /// section in memory.
    fn data(&self) -> &'data [u8];

    /// Returns the name of the section.
    fn name(&self) -> Option<&str>;

    /// Returns the name of the segment for this section.
    fn segment_name(&self) -> Option<&str>;
}
