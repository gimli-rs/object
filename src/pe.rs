use std::slice;

use goblin::pe;

use {Machine, Object, ObjectSection, ObjectSegment, Symbol};

/// A PE object file.
#[derive(Debug)]
pub struct PeFile<'a> {
    pe: pe::PE<'a>,
    data: &'a [u8],
}

/// An iterator over the loadable sections of a `PeFile`.
#[derive(Debug)]
pub struct PeSegmentIterator<'a> {
    file: &'a PeFile<'a>,
    iter: slice::Iter<'a, pe::section_table::SectionTable>,
}

/// A loadable section of a `PeFile`.
#[derive(Debug)]
pub struct PeSegment<'a> {
    file: &'a PeFile<'a>,
    section: &'a pe::section_table::SectionTable,
}

/// An iterator over the sections of a `PeFile`.
#[derive(Debug)]
pub struct PeSectionIterator<'a> {
    file: &'a PeFile<'a>,
    iter: slice::Iter<'a, pe::section_table::SectionTable>,
}

/// A section of a `PeFile`.
#[derive(Debug)]
pub struct PeSection<'a> {
    file: &'a PeFile<'a>,
    section: &'a pe::section_table::SectionTable,
}

impl<'a> PeFile<'a> {
    /// Get the PE headers of the file.
    // TODO: this is temporary to allow access to features this crate doesn't provide yet
    #[inline]
    pub fn pe(&self) -> &pe::PE<'a> {
        &self.pe
    }
}

impl<'a> Object<'a> for PeFile<'a> {
    type Segment = PeSegment<'a>;
    type SegmentIterator = PeSegmentIterator<'a>;
    type Section = PeSection<'a>;
    type SectionIterator = PeSectionIterator<'a>;

    fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
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

    fn segments(&'a self) -> PeSegmentIterator<'a> {
        PeSegmentIterator {
            file: self,
            iter: self.pe.sections.iter(),
        }
    }

    fn section_data_by_name(&self, section_name: &str) -> Option<&'a [u8]> {
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

    fn sections(&'a self) -> PeSectionIterator<'a> {
        PeSectionIterator {
            file: self,
            iter: self.pe.sections.iter(),
        }
    }

    fn symbols(&self) -> Vec<Symbol<'a>> {
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

impl<'a> Iterator for PeSegmentIterator<'a> {
    type Item = PeSegment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|section| {
            PeSegment {
                file: self.file,
                section,
            }
        })
    }
}

impl<'a> ObjectSegment<'a> for PeSegment<'a> {
    #[inline]
    fn address(&self) -> u64 {
        u64::from(self.section.virtual_address)
    }

    #[inline]
    fn size(&self) -> u64 {
        u64::from(self.section.virtual_size)
    }

    fn data(&self) -> &'a [u8] {
        &self.file.data[self.section.pointer_to_raw_data as usize..]
            [..self.section.size_of_raw_data as usize]
    }

    #[inline]
    fn name(&self) -> Option<&str> {
        self.section.name().ok()
    }
}

impl<'a> Iterator for PeSectionIterator<'a> {
    type Item = PeSection<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|section| {
            PeSection {
                file: self.file,
                section,
            }
        })
    }
}

impl<'a> ObjectSection<'a> for PeSection<'a> {
    #[inline]
    fn address(&self) -> u64 {
        u64::from(self.section.virtual_address)
    }

    #[inline]
    fn size(&self) -> u64 {
        u64::from(self.section.virtual_size)
    }

    fn data(&self) -> &'a [u8] {
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
