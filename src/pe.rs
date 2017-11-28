use std::slice;

use goblin::pe;

use {Machine, Object, ObjectSection, ObjectSegment, Symbol};

/// A PE object file.
#[derive(Debug)]
pub struct PeFile<'data> {
    pe: pe::PE<'data>,
    data: &'data [u8],
}

/// An iterator over the loadable sections of a `PeFile`.
#[derive(Debug)]
pub struct PeSegmentIterator<'data> {
    file: &'data PeFile<'data>,
    iter: slice::Iter<'data, pe::section_table::SectionTable>,
}

/// A loadable section of a `PeFile`.
#[derive(Debug)]
pub struct PeSegment<'data> {
    file: &'data PeFile<'data>,
    section: &'data pe::section_table::SectionTable,
}

/// An iterator over the sections of a `PeFile`.
#[derive(Debug)]
pub struct PeSectionIterator<'data> {
    file: &'data PeFile<'data>,
    iter: slice::Iter<'data, pe::section_table::SectionTable>,
}

/// A section of a `PeFile`.
#[derive(Debug)]
pub struct PeSection<'data> {
    file: &'data PeFile<'data>,
    section: &'data pe::section_table::SectionTable,
}

impl<'data> PeFile<'data> {
    /// Get the PE headers of the file.
    // TODO: this is temporary to allow access to features this crate doesn't provide yet
    #[inline]
    pub fn pe(&self) -> &pe::PE<'data> {
        &self.pe
    }
}

impl<'data> Object<'data> for PeFile<'data> {
    type Segment = PeSegment<'data>;
    type SegmentIterator = PeSegmentIterator<'data>;
    type Section = PeSection<'data>;
    type SectionIterator = PeSectionIterator<'data>;

    fn parse(data: &'data [u8]) -> Result<Self, &'static str> {
        let pe = pe::PE::parse(data).map_err(|_| "Could not parse PE header")?;
        Ok(PeFile { pe, data })
    }

    fn machine(&self) -> Machine {
        match self.pe.header.coff_header.machine {
            // TODO: Arm/Arm64
            pe::header::COFF_MACHINE_X86 => Machine::X86,
            pe::header::COFF_MACHINE_X86_64 => Machine::X86_64,
            _ => Machine::Other,
        }
    }

    fn segments(&'data self) -> PeSegmentIterator<'data> {
        PeSegmentIterator {
            file: self,
            iter: self.pe.sections.iter(),
        }
    }

    fn section_data_by_name(&self, section_name: &str) -> Option<&'data [u8]> {
        for section in &self.pe.sections {
            if let Ok(name) = section.name() {
                if name == section_name {
                    return Some(
                        &self.data[section.pointer_to_raw_data as usize..]
                            [..section.size_of_raw_data as usize],
                    );
                }
            }
        }
        None
    }

    fn sections(&'data self) -> PeSectionIterator<'data> {
        PeSectionIterator {
            file: self,
            iter: self.pe.sections.iter(),
        }
    }

    fn symbols(&self) -> Vec<Symbol<'data>> {
        // TODO
        Vec::new()
    }

    #[inline]
    fn is_little_endian(&self) -> bool {
        // TODO: always little endian?  The COFF header has some bits in the
        // characteristics flags, but these are obsolete.
        true
    }
}

impl<'data> Iterator for PeSegmentIterator<'data> {
    type Item = PeSegment<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|section| {
            PeSegment {
                file: self.file,
                section,
            }
        })
    }
}

impl<'data> ObjectSegment<'data> for PeSegment<'data> {
    #[inline]
    fn address(&self) -> u64 {
        u64::from(self.section.virtual_address)
    }

    #[inline]
    fn size(&self) -> u64 {
        u64::from(self.section.virtual_size)
    }

    fn data(&self) -> &'data [u8] {
        &self.file.data[self.section.pointer_to_raw_data as usize..]
            [..self.section.size_of_raw_data as usize]
    }

    #[inline]
    fn name(&self) -> Option<&str> {
        self.section.name().ok()
    }
}

impl<'data> Iterator for PeSectionIterator<'data> {
    type Item = PeSection<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|section| {
            PeSection {
                file: self.file,
                section,
            }
        })
    }
}

impl<'data> ObjectSection<'data> for PeSection<'data> {
    #[inline]
    fn address(&self) -> u64 {
        u64::from(self.section.virtual_address)
    }

    #[inline]
    fn size(&self) -> u64 {
        u64::from(self.section.virtual_size)
    }

    fn data(&self) -> &'data [u8] {
        &self.file.data[self.section.pointer_to_raw_data as usize..]
            [..self.section.size_of_raw_data as usize]
    }

    fn name(&self) -> Option<&str> {
        self.section.name().ok()
    }

    #[inline]
    fn segment_name(&self) -> Option<&str> {
        None
    }
}
