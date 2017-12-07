use std::cmp::Ordering;
use std::fmt;
use std::slice;

use goblin::mach;

use {Machine, Object, ObjectSection, ObjectSegment, SectionKind, Symbol, SymbolKind};

/// A Mach-O object file.
#[derive(Debug)]
pub struct MachOFile<'data> {
    macho: mach::MachO<'data>,
}

/// An iterator over the segments of a `MachOFile`.
#[derive(Debug)]
pub struct MachOSegmentIterator<'data, 'file>
where
    'data: 'file,
{
    segments: slice::Iter<'file, mach::segment::Segment<'data>>,
}

/// A segment of a `MachOFile`.
#[derive(Debug)]
pub struct MachOSegment<'data, 'file>
where
    'data: 'file,
{
    segment: &'file mach::segment::Segment<'data>,
}

/// An iterator over the sections of a `MachOFile`.
pub struct MachOSectionIterator<'data, 'file>
where
    'data: 'file,
{
    segments: slice::Iter<'file, mach::segment::Segment<'data>>,
    sections: Option<mach::segment::SectionIterator<'data>>,
}

/// A section of a `MachOFile`.
#[derive(Debug)]
pub struct MachOSection<'data> {
    section: mach::segment::Section,
    data: mach::segment::SectionData<'data>,
}

impl<'data> MachOFile<'data> {
    /// Get the Mach-O headers of the file.
    // TODO: this is temporary to allow access to features this crate doesn't provide yet
    #[inline]
    pub fn macho(&self) -> &mach::MachO<'data> {
        &self.macho
    }

    /// Parse the raw Mach-O file data.
    pub fn parse(data: &'data [u8]) -> Result<Self, &'static str> {
        let macho = mach::MachO::parse(data, 0).map_err(|_| "Could not parse Mach-O header")?;
        Ok(MachOFile { macho })
    }
}

impl<'data, 'file> Object<'data, 'file> for MachOFile<'data>
where
    'data: 'file,
{
    type Segment = MachOSegment<'data, 'file>;
    type SegmentIterator = MachOSegmentIterator<'data, 'file>;
    type Section = MachOSection<'data>;
    type SectionIterator = MachOSectionIterator<'data, 'file>;

    fn machine(&self) -> Machine {
        match self.macho.header.cputype {
            mach::cputype::CPU_TYPE_ARM => Machine::Arm,
            mach::cputype::CPU_TYPE_ARM64 => Machine::Arm64,
            mach::cputype::CPU_TYPE_X86 => Machine::X86,
            mach::cputype::CPU_TYPE_X86_64 => Machine::X86_64,
            _ => Machine::Other,
        }
    }

    fn segments(&'file self) -> MachOSegmentIterator<'data, 'file> {
        MachOSegmentIterator {
            segments: self.macho.segments.iter(),
        }
    }

    fn section_data_by_name(&self, section_name: &str) -> Option<&'data [u8]> {
        // Translate the "." prefix to the "__" prefix used by OSX/Mach-O, eg
        // ".debug_info" to "__debug_info".
        let (system_section, section_name) = if section_name.starts_with('.') {
            (true, &section_name[1..])
        } else {
            (false, section_name)
        };
        let cmp_section_name = |name: &str| if system_section {
            name.starts_with("__") && section_name == &name[2..]
        } else {
            section_name == name
        };

        for segment in &self.macho.segments {
            for section in segment {
                if let Ok((section, data)) = section {
                    if let Ok(name) = section.name() {
                        if cmp_section_name(name) {
                            return Some(data);
                        }
                    }
                }
            }
        }
        None
    }

    fn sections(&'file self) -> MachOSectionIterator<'data, 'file> {
        MachOSectionIterator {
            segments: self.macho.segments.iter(),
            sections: None,
        }
    }

    fn symbols(&self) -> Vec<Symbol<'data>> {
        // Determine section kinds and end addresses.
        // The section kinds are inherited by symbols in those sections.
        // The section end addresses are needed for calculating symbol sizes.
        let mut section_kinds = Vec::new();
        let mut section_ends = Vec::new();
        for segment in &self.macho.segments {
            for section in segment {
                if let Ok((section, _)) = section {
                    let sectname = section.name().ok();
                    let segname = section.segname().ok();
                    let (section_kind, symbol_kind) = match (segname, sectname) {
                        (Some("__TEXT"), Some("__text")) => (SectionKind::Text, SymbolKind::Text),
                        (Some("__DATA"), Some("__data")) => (SectionKind::Data, SymbolKind::Data),
                        (Some("__DATA"), Some("__bss")) => {
                            (SectionKind::UninitializedData, SymbolKind::Data)
                        }
                        _ => (SectionKind::Other, SymbolKind::Unknown),
                    };
                    let section_index = section_kinds.len();
                    section_kinds.push((section_kind, symbol_kind));
                    section_ends.push(Symbol {
                        kind: SymbolKind::Section,
                        section: section_index + 1,
                        section_kind: Some(section_kind),
                        global: false,
                        name: None,
                        address: section.addr + section.size,
                        size: 0,
                    });
                } else {
                    // Add placeholder so that indexing works.
                    section_kinds.push((SectionKind::Unknown, SymbolKind::Unknown));
                }
            }
        }

        let mut symbols = Vec::new();
        for sym in self.macho.symbols() {
            if let Ok((name, nlist)) = sym {
                // Skip STAB debugging symbols.
                // FIXME: use N_STAB constant
                if nlist.n_type & 0xe0 != 0 {
                    continue;
                }
                let n_type = nlist.n_type & mach::symbols::NLIST_TYPE_MASK;
                let (section_kind, kind) = if n_type == mach::symbols::N_SECT {
                    if nlist.n_sect == 0 || nlist.n_sect - 1 >= section_kinds.len() {
                        (None, SymbolKind::Unknown)
                    } else {
                        let (section_kind, kind) = section_kinds[nlist.n_sect - 1];
                        (Some(section_kind), kind)
                    }
                } else {
                    (None, SymbolKind::Unknown)
                };
                symbols.push(Symbol {
                    kind,
                    section: nlist.n_sect,
                    section_kind,
                    global: nlist.is_global(),
                    name: Some(name),
                    address: nlist.n_value,
                    size: 0,
                });
            }
        }

        {
            // Calculate symbol sizes by sorting and finding the next symbol.
            let mut symbol_refs = Vec::with_capacity(symbols.len() + section_ends.len());
            symbol_refs.extend(symbols.iter_mut().filter(|s| !s.is_undefined()));
            symbol_refs.extend(section_ends.iter_mut());
            symbol_refs.sort_by(|a, b| {
                let ord = a.section.cmp(&b.section);
                if ord != Ordering::Equal {
                    return ord;
                }
                let ord = a.address.cmp(&b.address);
                if ord != Ordering::Equal {
                    return ord;
                }
                // Place the dummy end of section symbols last.
                (a.kind == SymbolKind::Section).cmp(&(b.kind == SymbolKind::Section))
            });

            for i in 0..symbol_refs.len() {
                let (before, after) = symbol_refs.split_at_mut(i + 1);
                let sym = &mut before[i];
                if sym.kind != SymbolKind::Section {
                    if let Some(next) = after
                        .iter()
                        .skip_while(|x| {
                            x.kind != SymbolKind::Section && x.address == sym.address
                        })
                        .next()
                    {
                        sym.size = next.address - sym.address;
                    }
                }
            }
        }

        symbols
    }

    #[inline]
    fn is_little_endian(&self) -> bool {
        self.macho.header.is_little_endian()
    }
}

impl<'data, 'file> Iterator for MachOSegmentIterator<'data, 'file> {
    type Item = MachOSegment<'data, 'file>;

    fn next(&mut self) -> Option<Self::Item> {
        self.segments.next().map(|segment| MachOSegment { segment })
    }
}

impl<'data, 'file> ObjectSegment<'data> for MachOSegment<'data, 'file> {
    #[inline]
    fn address(&self) -> u64 {
        self.segment.vmaddr
    }

    #[inline]
    fn size(&self) -> u64 {
        self.segment.vmsize
    }

    #[inline]
    fn data(&self) -> &'data [u8] {
        self.segment.data
    }

    #[inline]
    fn name(&self) -> Option<&str> {
        self.segment.name().ok()
    }
}

impl<'data, 'file> fmt::Debug for MachOSectionIterator<'data, 'file> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // It's painful to do much better than this
        f.debug_struct("MachOSectionIterator").finish()
    }
}

impl<'data, 'file> Iterator for MachOSectionIterator<'data, 'file> {
    type Item = MachOSection<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ref mut sections) = self.sections {
                while let Some(section) = sections.next() {
                    if let Ok((section, data)) = section {
                        return Some(MachOSection { section, data });
                    }
                }
            }
            match self.segments.next() {
                None => return None,
                Some(segment) => {
                    self.sections = Some(segment.into_iter());
                }
            }
        }
    }
}

impl<'data> ObjectSection<'data> for MachOSection<'data> {
    #[inline]
    fn address(&self) -> u64 {
        self.section.addr
    }

    #[inline]
    fn size(&self) -> u64 {
        self.section.size
    }

    #[inline]
    fn data(&self) -> &'data [u8] {
        self.data
    }

    #[inline]
    fn name(&self) -> Option<&str> {
        self.section.name().ok()
    }

    #[inline]
    fn segment_name(&self) -> Option<&str> {
        self.section.segname().ok()
    }

    fn kind(&self) -> SectionKind {
        match (self.segment_name(), self.name()) {
            (Some("__TEXT"), Some("__text")) => SectionKind::Text,
            (Some("__DATA"), Some("__data")) => SectionKind::Data,
            (Some("__DATA"), Some("__bss")) => SectionKind::UninitializedData,
            _ => SectionKind::Other,
        }
    }
}