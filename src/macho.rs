use crate::alloc::borrow::Cow;
use crate::alloc::vec::Vec;
use std::fmt;
use std::slice;

use goblin::container;
use goblin::mach;
use goblin::mach::load_command::CommandVariant;
use uuid::Uuid;

use crate::{
    Machine, Object, ObjectSection, ObjectSegment, Relocation, RelocationKind, SectionKind, Symbol,
    SymbolKind, SymbolMap,
};

/// A Mach-O object file.
#[derive(Debug)]
pub struct MachOFile<'data> {
    macho: mach::MachO<'data>,
    data: &'data [u8],
    ctx: container::Ctx,
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
    file: &'file MachOFile<'data>,
    segments: slice::Iter<'file, mach::segment::Segment<'data>>,
    sections: Option<mach::segment::SectionIterator<'data>>,
}

/// A section of a `MachOFile`.
#[derive(Debug)]
pub struct MachOSection<'data, 'file>
where
    'data: 'file,
{
    file: &'file MachOFile<'data>,
    section: mach::segment::Section,
    data: mach::segment::SectionData<'data>,
}

/// An iterator over the symbols of a `MachOFile`.
pub struct MachOSymbolIterator<'data> {
    symbols: mach::symbols::SymbolIterator<'data>,
    section_kinds: Vec<SectionKind>,
}

/// An iterator over the relocations in an `MachOSection`.
pub struct MachORelocationIterator<'data, 'file>
where
    'data: 'file,
{
    file: &'file MachOFile<'data>,
    relocations: mach::segment::RelocationIterator<'data>,
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
        let (_magic, ctx) =
            mach::parse_magic_and_ctx(data, 0).map_err(|_| "Could not parse Mach-O magic")?;
        let ctx = ctx.ok_or("Invalid Mach-O magic")?;
        let macho = mach::MachO::parse(data, 0).map_err(|_| "Could not parse Mach-O header")?;
        Ok(MachOFile { macho, data, ctx })
    }
}

impl<'data, 'file> Object<'data, 'file> for MachOFile<'data>
where
    'data: 'file,
{
    type Segment = MachOSegment<'data, 'file>;
    type SegmentIterator = MachOSegmentIterator<'data, 'file>;
    type Section = MachOSection<'data, 'file>;
    type SectionIterator = MachOSectionIterator<'data, 'file>;
    type SymbolIterator = MachOSymbolIterator<'data>;

    fn machine(&self) -> Machine {
        match self.macho.header.cputype {
            mach::cputype::CPU_TYPE_ARM => Machine::Arm,
            mach::cputype::CPU_TYPE_ARM64 => Machine::Arm64,
            mach::cputype::CPU_TYPE_X86 => Machine::X86,
            mach::cputype::CPU_TYPE_X86_64 => Machine::X86_64,
            mach::cputype::CPU_TYPE_MIPS => Machine::Mips,
            _ => Machine::Other,
        }
    }

    fn segments(&'file self) -> MachOSegmentIterator<'data, 'file> {
        MachOSegmentIterator {
            segments: self.macho.segments.iter(),
        }
    }

    fn section_by_name(&'file self, section_name: &str) -> Option<MachOSection<'data, 'file>> {
        // Translate the "." prefix to the "__" prefix used by OSX/Mach-O, eg
        // ".debug_info" to "__debug_info".
        let (system_section, section_name) = if section_name.starts_with('.') {
            (true, &section_name[1..])
        } else {
            (false, section_name)
        };
        let cmp_section_name = |name: Option<&str>| {
            name.map(|name| {
                if system_section {
                    name.starts_with("__") && section_name == &name[2..]
                } else {
                    section_name == name
                }
            })
            .unwrap_or(false)
        };

        for segment in &self.macho.segments {
            for section in segment {
                if let Ok((section, data)) = section {
                    if cmp_section_name(section.name().ok()) {
                        return Some(MachOSection {
                            file: self,
                            section,
                            data,
                        });
                    }
                } else {
                    break;
                }
            }
        }
        None
    }

    fn sections(&'file self) -> MachOSectionIterator<'data, 'file> {
        MachOSectionIterator {
            file: self,
            segments: self.macho.segments.iter(),
            sections: None,
        }
    }

    fn symbol_by_index(&self, index: u64) -> Option<Symbol<'data>> {
        // TODO: determine section_kind too
        self.macho
            .symbols
            .as_ref()
            .and_then(|symbols| symbols.get(index as usize).ok())
            .and_then(|(name, nlist)| parse_symbol(name, &nlist, &[]))
    }

    fn symbols(&'file self) -> MachOSymbolIterator<'data> {
        let symbols = match self.macho.symbols {
            Some(ref symbols) => symbols.into_iter(),
            None => mach::symbols::SymbolIterator::default(),
        };

        let mut section_kinds = Vec::new();
        // Don't use MachOSectionIterator because it skips sections it fails to parse,
        // and the section index is important.
        'segment: for segment in &self.macho.segments {
            for section in segment {
                if let Ok((section, data)) = section {
                    let section = MachOSection {
                        file: self,
                        section,
                        data,
                    };
                    section_kinds.push(section.kind());
                } else {
                    // We can't process more segments because the section index will be wrong.
                    break 'segment;
                }
            }
        }

        MachOSymbolIterator {
            symbols,
            section_kinds,
        }
    }

    fn dynamic_symbols(&'file self) -> MachOSymbolIterator<'data> {
        // The LC_DYSYMTAB command contains indices into the same symbol
        // table as the LC_SYMTAB command, so return all of them.
        self.symbols()
    }

    fn symbol_map(&self) -> SymbolMap<'data> {
        let mut symbols: Vec<_> = self.symbols().collect();

        // Add symbols for the end of each section.
        for section in self.sections() {
            symbols.push(Symbol {
                name: None,
                address: section.address() + section.size(),
                size: 0,
                kind: SymbolKind::Section,
                section_kind: None,
                global: false,
            });
        }

        // Calculate symbol sizes by sorting and finding the next symbol.
        symbols.sort_by(|a, b| {
            a.address.cmp(&b.address).then_with(|| {
                // Place the end of section symbols last.
                (a.kind == SymbolKind::Section).cmp(&(b.kind == SymbolKind::Section))
            })
        });

        for i in 0..symbols.len() {
            let (before, after) = symbols.split_at_mut(i + 1);
            let symbol = &mut before[i];
            if symbol.kind != SymbolKind::Section {
                if let Some(next) = after
                    .iter()
                    .skip_while(|x| x.kind != SymbolKind::Section && x.address == symbol.address)
                    .next()
                {
                    symbol.size = next.address - symbol.address;
                }
            }
        }

        symbols.retain(SymbolMap::filter);
        SymbolMap { symbols }
    }

    #[inline]
    fn is_little_endian(&self) -> bool {
        self.macho.little_endian
    }

    fn has_debug_symbols(&self) -> bool {
        self.section_data_by_name(".debug_info").is_some()
    }

    fn mach_uuid(&self) -> Option<Uuid> {
        // Return the UUID from the `LC_UUID` load command, if one is present.
        self.macho
            .load_commands
            .iter()
            .filter_map(|lc| {
                match lc.command {
                    CommandVariant::Uuid(ref cmd) => {
                        //TODO: Uuid should have a `from_array` method that can't fail.
                        Uuid::from_slice(&cmd.uuid).ok()
                    }
                    _ => None,
                }
            })
            .nth(0)
    }

    fn entry(&self) -> u64 {
        self.macho.entry
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // It's painful to do much better than this
        f.debug_struct("MachOSectionIterator").finish()
    }
}

impl<'data, 'file> Iterator for MachOSectionIterator<'data, 'file> {
    type Item = MachOSection<'data, 'file>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ref mut sections) = self.sections {
                if let Some(Ok((section, data))) = sections.next() {
                    return Some(MachOSection {
                        file: self.file,
                        section,
                        data,
                    });
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

impl<'data, 'file> ObjectSection<'data> for MachOSection<'data, 'file> {
    type RelocationIterator = MachORelocationIterator<'data, 'file>;

    #[inline]
    fn address(&self) -> u64 {
        self.section.addr
    }

    #[inline]
    fn size(&self) -> u64 {
        self.section.size
    }

    #[inline]
    fn data(&self) -> Cow<'data, [u8]> {
        Cow::from(self.data)
    }

    #[inline]
    fn uncompressed_data(&self) -> Cow<'data, [u8]> {
        // TODO: does MachO support compression?
        self.data()
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

    fn relocations(&self) -> MachORelocationIterator<'data, 'file> {
        MachORelocationIterator {
            file: self.file,
            relocations: self.section.iter_relocations(self.file.data, self.file.ctx),
        }
    }
}

impl<'data> fmt::Debug for MachOSymbolIterator<'data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachOSymbolIterator").finish()
    }
}

impl<'data> Iterator for MachOSymbolIterator<'data> {
    type Item = Symbol<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(Ok((name, nlist))) = self.symbols.next() {
            let symbol = parse_symbol(name, &nlist, &self.section_kinds);
            if symbol.is_some() {
                return symbol;
            }
        }
        None
    }
}

fn parse_symbol<'data>(
    name: &'data str,
    nlist: &mach::symbols::Nlist,
    section_kinds: &[SectionKind],
) -> Option<Symbol<'data>> {
    if nlist.n_type & mach::symbols::N_STAB != 0 {
        return None;
    }
    let n_type = nlist.n_type & mach::symbols::NLIST_TYPE_MASK;
    let section_kind = if n_type == mach::symbols::N_SECT {
        if nlist.n_sect == 0 {
            None
        } else {
            Some(
                section_kinds
                    .get(nlist.n_sect - 1)
                    .cloned()
                    .unwrap_or(SectionKind::Unknown),
            )
        }
    } else {
        // TODO: better handling for other n_type values
        None
    };
    let kind = match section_kind {
        Some(SectionKind::Text) => SymbolKind::Text,
        Some(SectionKind::Data)
        | Some(SectionKind::ReadOnlyData)
        | Some(SectionKind::UninitializedData) => SymbolKind::Data,
        _ => SymbolKind::Unknown,
    };
    Some(Symbol {
        name: Some(name),
        address: nlist.n_value,
        // Only calculated for symbol maps
        size: 0,
        kind,
        section_kind,
        global: nlist.is_global(),
    })
}

impl<'data, 'file> Iterator for MachORelocationIterator<'data, 'file> {
    type Item = (u64, Relocation);

    fn next(&mut self) -> Option<Self::Item> {
        self.relocations.next()?.ok().map(|reloc| {
            let kind = match self.file.macho.header.cputype {
                mach::cputype::CPU_TYPE_ARM => match (reloc.r_type(), reloc.r_length()) {
                    (mach::relocation::ARM_RELOC_VANILLA, 2) => RelocationKind::Direct32,
                    (mach::relocation::ARM_RELOC_VANILLA, 3) => RelocationKind::Direct64,
                    _ => RelocationKind::Other(reloc.r_info),
                },
                mach::cputype::CPU_TYPE_ARM64 => match (reloc.r_type(), reloc.r_length()) {
                    (mach::relocation::ARM64_RELOC_UNSIGNED, 2) => RelocationKind::Direct32,
                    (mach::relocation::ARM64_RELOC_UNSIGNED, 3) => RelocationKind::Direct64,
                    _ => RelocationKind::Other(reloc.r_info),
                },
                mach::cputype::CPU_TYPE_X86 => match (reloc.r_type(), reloc.r_length()) {
                    (mach::relocation::GENERIC_RELOC_VANILLA, 2) => RelocationKind::Direct32,
                    (mach::relocation::GENERIC_RELOC_VANILLA, 3) => RelocationKind::Direct64,
                    _ => RelocationKind::Other(reloc.r_info),
                },
                mach::cputype::CPU_TYPE_X86_64 => match (reloc.r_type(), reloc.r_length()) {
                    (mach::relocation::X86_64_RELOC_UNSIGNED, 2) => RelocationKind::Direct32,
                    (mach::relocation::X86_64_RELOC_UNSIGNED, 3) => RelocationKind::Direct64,
                    _ => RelocationKind::Other(reloc.r_info),
                },
                _ => RelocationKind::Other(reloc.r_info),
            };
            (
                reloc.r_address as u64,
                Relocation {
                    kind,
                    symbol: reloc.r_symbolnum() as u64,
                    addend: 0,
                    implicit_addend: true,
                },
            )
        })
    }
}

impl<'data, 'file> fmt::Debug for MachORelocationIterator<'data, 'file> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachORelocationIterator").finish()
    }
}
