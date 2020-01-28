//! Support for reading Mach-O files.
//!
//! Defines traits to abstract over the difference between 32-bit and 64-bit
//! Mach-O files, and implements read functionality in terms of these traits.
//!
//! Also provides `MachOFile` and related types which implement the `Object` trait.

use crate::alloc::borrow::Cow;
use crate::alloc::vec::Vec;
use crate::endian::{self, BigEndian, Endian, RunTimeEndian};
use crate::macho;
use crate::pod::{self, Pod};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::{fmt, mem, ops, slice, str};
use target_lexicon::{Aarch64Architecture, Architecture, ArmArchitecture};
use uuid::Uuid;

use crate::read::util::StringTable;
use crate::read::{
    self, FileFlags, Object, ObjectSection, ObjectSegment, Relocation, RelocationEncoding,
    RelocationKind, RelocationTarget, SectionFlags, SectionIndex, SectionKind, Symbol, SymbolFlags,
    SymbolIndex, SymbolKind, SymbolMap, SymbolScope, SymbolSection,
};

/// A 32-bit Mach-O object file.
pub type MachOFile32<'data, Endian = RunTimeEndian> = MachOFile<'data, macho::MachHeader32<Endian>>;
/// A 64-bit Mach-O object file.
pub type MachOFile64<'data, Endian = RunTimeEndian> = MachOFile<'data, macho::MachHeader64<Endian>>;

/// A partially parsed Mach-O file.
///
/// Most of the functionality of this type is provided by the `Object` trait implementation.
#[derive(Debug)]
pub struct MachOFile<'data, Mach: MachHeader> {
    endian: Mach::Endian,
    header: &'data Mach,
    sections: Vec<MachOSectionInternal<'data, Mach>>,
    symbols: SymbolTable<'data, Mach>,
    data: &'data [u8],
}

impl<'data, Mach: MachHeader> MachOFile<'data, Mach> {
    /// Parse the raw Mach-O file data.
    pub fn parse(data: &'data [u8]) -> Result<Self, &'static str> {
        let (header, _) =
            pod::from_bytes::<Mach>(data).ok_or("Invalid Mach-O header size or alignment")?;
        if !header.is_supported() {
            return Err("Unsupported Mach-O header");
        }

        let endian = header.endian().ok_or("Unsupported endian")?;

        let mut symbols = &[][..];
        let mut strings = &[][..];
        // Build a list of sections to make some operations more efficient.
        let mut sections = Vec::new();
        if let Some(commands) = header.load_commands(endian, data) {
            for command in commands {
                if let Some((segment, section_data)) = Mach::Segment::from_command(command) {
                    for section in segment.sections(endian, section_data).unwrap_or(&[]) {
                        sections.push(MachOSectionInternal::parse(section));
                    }
                } else if let Some(symtab) = command.symtab() {
                    symbols = pod::slice_from_bytes(
                        data,
                        symtab.symoff.get(endian) as usize,
                        symtab.nsyms.get(endian) as usize,
                    )
                    .map(|x| x.0)
                    .unwrap_or(&[]);
                    strings = pod::slice_from_bytes(
                        data,
                        symtab.stroff.get(endian) as usize,
                        symtab.strsize.get(endian) as usize,
                    )
                    .map(|x| x.0)
                    .unwrap_or(&[]);
                }
            }
        }

        let strings = StringTable { data: strings };
        let symbols = SymbolTable { symbols, strings };

        Ok(MachOFile {
            endian,
            header,
            sections,
            symbols,
            data,
        })
    }

    /// Return the section at the given index.
    #[inline]
    fn section_internal(&self, index: SectionIndex) -> Option<&MachOSectionInternal<'data, Mach>> {
        index
            .0
            .checked_sub(1)
            .and_then(|index| self.sections.get(index))
    }
}

impl<'data, 'file, Mach> Object<'data, 'file> for MachOFile<'data, Mach>
where
    'data: 'file,
    Mach: MachHeader,
{
    type Segment = MachOSegment<'data, 'file, Mach>;
    type SegmentIterator = MachOSegmentIterator<'data, 'file, Mach>;
    type Section = MachOSection<'data, 'file, Mach>;
    type SectionIterator = MachOSectionIterator<'data, 'file, Mach>;
    type SymbolIterator = MachOSymbolIterator<'data, 'file, Mach>;

    fn architecture(&self) -> Architecture {
        match self.header.cputype(self.endian) {
            macho::CPU_TYPE_ARM => Architecture::Arm(ArmArchitecture::Arm),
            macho::CPU_TYPE_ARM64 => Architecture::Aarch64(Aarch64Architecture::Aarch64),
            macho::CPU_TYPE_X86 => Architecture::I386,
            macho::CPU_TYPE_X86_64 => Architecture::X86_64,
            macho::CPU_TYPE_MIPS => Architecture::Mips,
            _ => Architecture::Unknown,
        }
    }

    #[inline]
    fn is_little_endian(&self) -> bool {
        self.header.is_little_endian()
    }

    #[inline]
    fn is_64(&self) -> bool {
        self.header.is_type_64()
    }

    fn segments(&'file self) -> MachOSegmentIterator<'data, 'file, Mach> {
        MachOSegmentIterator {
            file: self,
            commands: self
                .header
                .load_commands(self.endian, self.data)
                .unwrap_or_else(Default::default),
        }
    }

    fn section_by_name(
        &'file self,
        section_name: &str,
    ) -> Option<MachOSection<'data, 'file, Mach>> {
        // Translate the "." prefix to the "__" prefix used by OSX/Mach-O, eg
        // ".debug_info" to "__debug_info".
        let system_section = section_name.starts_with('.');
        let cmp_section_name = |section: &MachOSection<Mach>| {
            section
                .name()
                .map(|name| {
                    section_name == name
                        || (system_section
                            && name.starts_with("__")
                            && section_name[1..] == name[2..])
                })
                .unwrap_or(false)
        };

        self.sections().find(cmp_section_name)
    }

    fn section_by_index(
        &'file self,
        index: SectionIndex,
    ) -> Option<MachOSection<'data, 'file, Mach>> {
        self.section_internal(index)
            .map(|_| MachOSection { file: self, index })
    }

    fn sections(&'file self) -> MachOSectionIterator<'data, 'file, Mach> {
        MachOSectionIterator {
            file: self,
            iter: 0..self.sections.len(),
        }
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> Option<Symbol<'data>> {
        let nlist = self.symbols.symbols.get(index.0)?;
        parse_symbol(self, nlist, self.symbols.strings)
    }

    fn symbols(&'file self) -> MachOSymbolIterator<'data, 'file, Mach> {
        MachOSymbolIterator {
            file: self,
            symbols: self.symbols,
            index: 0,
        }
    }

    fn dynamic_symbols(&'file self) -> MachOSymbolIterator<'data, 'file, Mach> {
        // The LC_DYSYMTAB command contains indices into the same symbol
        // table as the LC_SYMTAB command, so return all of them.
        self.symbols()
    }

    fn symbol_map(&self) -> SymbolMap<'data> {
        let mut symbols: Vec<_> = self.symbols().map(|(_, s)| s).collect();

        // Add symbols for the end of each section.
        for section in self.sections() {
            symbols.push(Symbol {
                name: None,
                address: section.address() + section.size(),
                size: 0,
                kind: SymbolKind::Section,
                section: SymbolSection::Undefined,
                weak: false,
                scope: SymbolScope::Compilation,
                flags: SymbolFlags::None,
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

    fn has_debug_symbols(&self) -> bool {
        self.section_data_by_name(".debug_info").is_some()
    }

    fn mach_uuid(&self) -> Option<Uuid> {
        // Return the UUID from the `LC_UUID` load command, if one is present.
        if let Some(commands) = self.header.load_commands(self.endian, self.data) {
            for command in commands {
                if let Some(command) = command.uuid() {
                    return Some(Uuid::from_bytes(command.uuid));
                }
            }
        }
        None
    }

    fn entry(&self) -> u64 {
        if let Some(commands) = self.header.load_commands(self.endian, self.data) {
            for command in commands {
                if let Some(command) = command.entry_point() {
                    return command.entryoff.get(self.endian);
                }
            }
        }
        0
    }

    fn flags(&self) -> FileFlags {
        FileFlags::MachO {
            flags: self.header.flags(self.endian),
        }
    }
}

/// An iterator over the segments of a `MachOFile32`.
pub type MachOSegmentIterator32<'data, 'file, Endian = RunTimeEndian> =
    MachOSegmentIterator<'data, 'file, macho::MachHeader32<Endian>>;
/// An iterator over the segments of a `MachOFile64`.
pub type MachOSegmentIterator64<'data, 'file, Endian = RunTimeEndian> =
    MachOSegmentIterator<'data, 'file, macho::MachHeader64<Endian>>;

/// An iterator over the segments of a `MachOFile`.
#[derive(Debug)]
pub struct MachOSegmentIterator<'data, 'file, Mach>
where
    'data: 'file,
    Mach: MachHeader,
{
    file: &'file MachOFile<'data, Mach>,
    commands: MachOLoadCommandIterator<'data, Mach::Endian>,
}

impl<'data, 'file, Mach: MachHeader> Iterator for MachOSegmentIterator<'data, 'file, Mach> {
    type Item = MachOSegment<'data, 'file, Mach>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let command = self.commands.next()?;
            if let Some((segment, _)) = Mach::Segment::from_command(command) {
                return Some(MachOSegment {
                    file: self.file,
                    segment,
                });
            }
        }
    }
}

/// A segment of a `MachOFile32`.
pub type MachOSegment32<'data, 'file, Endian = RunTimeEndian> =
    MachOSegment<'data, 'file, macho::MachHeader32<Endian>>;
/// A segment of a `MachOFile64`.
pub type MachOSegment64<'data, 'file, Endian = RunTimeEndian> =
    MachOSegment<'data, 'file, macho::MachHeader64<Endian>>;

/// A segment of a `MachOFile`.
#[derive(Debug)]
pub struct MachOSegment<'data, 'file, Mach>
where
    'data: 'file,
    Mach: MachHeader,
{
    file: &'file MachOFile<'data, Mach>,
    segment: &'data Mach::Segment,
}

impl<'data, 'file, Mach: MachHeader> ObjectSegment<'data> for MachOSegment<'data, 'file, Mach> {
    #[inline]
    fn address(&self) -> u64 {
        self.segment.vmaddr(self.file.endian).into()
    }

    #[inline]
    fn size(&self) -> u64 {
        self.segment.vmsize(self.file.endian).into()
    }

    #[inline]
    fn align(&self) -> u64 {
        // Page size.
        0x1000
    }

    #[inline]
    fn file_range(&self) -> (u64, u64) {
        self.segment.file_range(self.file.endian)
    }

    fn data(&self) -> &'data [u8] {
        self.segment
            .data(self.file.endian, self.file.data)
            .unwrap_or(&[])
    }

    fn data_range(&self, address: u64, size: u64) -> Option<&'data [u8]> {
        read::data_range(self.data(), self.address(), address, size)
    }

    #[inline]
    fn name(&self) -> Option<&str> {
        str::from_utf8(self.segment.name()).ok()
    }
}

/// An iterator over the sections of a `MachOFile32`.
pub type MachOSectionIterator32<'data, 'file, Endian = RunTimeEndian> =
    MachOSectionIterator<'data, 'file, macho::MachHeader32<Endian>>;
/// An iterator over the sections of a `MachOFile64`.
pub type MachOSectionIterator64<'data, 'file, Endian = RunTimeEndian> =
    MachOSectionIterator<'data, 'file, macho::MachHeader64<Endian>>;

/// An iterator over the sections of a `MachOFile`.
pub struct MachOSectionIterator<'data, 'file, Mach>
where
    'data: 'file,
    Mach: MachHeader,
{
    file: &'file MachOFile<'data, Mach>,
    iter: ops::Range<usize>,
}

impl<'data, 'file, Mach: MachHeader> fmt::Debug for MachOSectionIterator<'data, 'file, Mach> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // It's painful to do much better than this
        f.debug_struct("MachOSectionIterator").finish()
    }
}

impl<'data, 'file, Mach: MachHeader> Iterator for MachOSectionIterator<'data, 'file, Mach> {
    type Item = MachOSection<'data, 'file, Mach>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|index| MachOSection {
            file: self.file,
            index: SectionIndex(index + 1),
        })
    }
}

/// A section of a `MachOFile32`.
pub type MachOSection32<'data, 'file, Endian = RunTimeEndian> =
    MachOSection<'data, 'file, macho::MachHeader32<Endian>>;
/// A section of a `MachOFile64`.
pub type MachOSection64<'data, 'file, Endian = RunTimeEndian> =
    MachOSection<'data, 'file, macho::MachHeader64<Endian>>;

/// A section of a `MachOFile`.
#[derive(Debug)]
pub struct MachOSection<'data, 'file, Mach>
where
    'data: 'file,
    Mach: MachHeader,
{
    file: &'file MachOFile<'data, Mach>,
    index: SectionIndex,
}

impl<'data, 'file, Mach: MachHeader> MachOSection<'data, 'file, Mach> {
    #[inline]
    fn internal(&self) -> &'file MachOSectionInternal<'data, Mach> {
        // We ensure the index is always valid.
        &self.file.section_internal(self.index).unwrap()
    }

    fn raw_data(&self) -> &'data [u8] {
        self.internal()
            .section
            .data(self.file.endian, self.file.data)
            .unwrap_or(&[])
    }
}

impl<'data, 'file, Mach: MachHeader> ObjectSection<'data> for MachOSection<'data, 'file, Mach> {
    type RelocationIterator = MachORelocationIterator<'data, 'file, Mach>;

    #[inline]
    fn index(&self) -> SectionIndex {
        self.index
    }

    #[inline]
    fn address(&self) -> u64 {
        self.internal().section.addr(self.file.endian).into()
    }

    #[inline]
    fn size(&self) -> u64 {
        self.internal().section.size(self.file.endian).into()
    }

    #[inline]
    fn align(&self) -> u64 {
        1 << self.internal().section.align(self.file.endian)
    }

    #[inline]
    fn file_range(&self) -> Option<(u64, u64)> {
        self.internal().section.file_range(self.file.endian)
    }

    #[inline]
    fn data(&self) -> &'data [u8] {
        self.raw_data()
    }

    fn data_range(&self, address: u64, size: u64) -> Option<&'data [u8]> {
        read::data_range(self.raw_data(), self.address(), address, size)
    }

    #[inline]
    fn uncompressed_data(&self) -> Cow<'data, [u8]> {
        Cow::from(self.data())
    }

    #[inline]
    fn name(&self) -> Option<&str> {
        str::from_utf8(self.internal().section.name()).ok()
    }

    #[inline]
    fn segment_name(&self) -> Option<&str> {
        str::from_utf8(self.internal().section.segment_name()).ok()
    }

    fn kind(&self) -> SectionKind {
        self.internal().kind
    }

    fn relocations(&self) -> MachORelocationIterator<'data, 'file, Mach> {
        MachORelocationIterator {
            file: self.file,
            relocations: self
                .internal()
                .section
                .relocations(self.file.endian, self.file.data)
                .unwrap_or(&[])
                .iter(),
        }
    }

    fn flags(&self) -> SectionFlags {
        SectionFlags::MachO {
            flags: self.internal().section.flags(self.file.endian),
        }
    }
}

#[derive(Debug)]
struct MachOSectionInternal<'data, Mach: MachHeader> {
    section: &'data Mach::Section,
    kind: SectionKind,
}

impl<'data, Mach: MachHeader> MachOSectionInternal<'data, Mach> {
    fn parse(section: &'data Mach::Section) -> Self {
        let kind = match (section.segment_name(), section.name()) {
            (b"__TEXT", b"__text") => SectionKind::Text,
            (b"__TEXT", b"__const") => SectionKind::ReadOnlyData,
            (b"__TEXT", b"__cstring") => SectionKind::ReadOnlyString,
            (b"__TEXT", b"__eh_frame") => SectionKind::ReadOnlyData,
            (b"__TEXT", b"__gcc_except_tab") => SectionKind::ReadOnlyData,
            (b"__DATA", b"__data") => SectionKind::Data,
            (b"__DATA", b"__const") => SectionKind::ReadOnlyData,
            (b"__DATA", b"__bss") => SectionKind::UninitializedData,
            (b"__DATA", b"__common") => SectionKind::Common,
            (b"__DATA", b"__thread_data") => SectionKind::Tls,
            (b"__DATA", b"__thread_bss") => SectionKind::UninitializedTls,
            (b"__DATA", b"__thread_vars") => SectionKind::TlsVariables,
            (b"__DWARF", _) => SectionKind::Debug,
            _ => SectionKind::Unknown,
        };
        MachOSectionInternal { section, kind }
    }
}

/// An iterator over the symbols of a `MachOFile32`.
pub type MachOSymbolIterator32<'data, 'file, Endian = RunTimeEndian> =
    MachOSymbolIterator<'data, 'file, macho::MachHeader32<Endian>>;
/// An iterator over the symbols of a `MachOFile64`.
pub type MachOSymbolIterator64<'data, 'file, Endian = RunTimeEndian> =
    MachOSymbolIterator<'data, 'file, macho::MachHeader64<Endian>>;

/// An iterator over the symbols of a `MachOFile`.
pub struct MachOSymbolIterator<'data, 'file, Mach: MachHeader> {
    file: &'file MachOFile<'data, Mach>,
    symbols: SymbolTable<'data, Mach>,
    index: usize,
}

impl<'data, 'file, Mach: MachHeader> fmt::Debug for MachOSymbolIterator<'data, 'file, Mach> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachOSymbolIterator").finish()
    }
}

impl<'data, 'file, Mach: MachHeader> Iterator for MachOSymbolIterator<'data, 'file, Mach> {
    type Item = (SymbolIndex, Symbol<'data>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let index = self.index;
            let nlist = self.symbols.symbols.get(index)?;
            self.index += 1;
            if let Some(symbol) = parse_symbol(self.file, nlist, self.symbols.strings) {
                return Some((SymbolIndex(index), symbol));
            }
        }
    }
}

fn parse_symbol<'data, Mach: MachHeader>(
    file: &MachOFile<'data, Mach>,
    nlist: &Mach::Nlist,
    strings: StringTable<'data>,
) -> Option<Symbol<'data>> {
    let endian = file.endian;
    let name = strings
        .get(nlist.n_strx(endian))
        .and_then(|s| str::from_utf8(s).ok());
    let n_type = nlist.n_type();
    let n_desc = nlist.n_desc(endian);
    if n_type & macho::N_STAB != 0 {
        return None;
    }
    let section = match n_type & macho::N_TYPE {
        macho::N_UNDF => SymbolSection::Undefined,
        macho::N_ABS => SymbolSection::Absolute,
        macho::N_SECT => {
            let n_sect = nlist.n_sect();
            if n_sect != 0 {
                SymbolSection::Section(SectionIndex(n_sect as usize))
            } else {
                SymbolSection::Unknown
            }
        }
        _ => SymbolSection::Unknown,
    };
    let kind = section
        .index()
        .and_then(|index| file.section_internal(index))
        .map(|section| match section.kind {
            SectionKind::Text => SymbolKind::Text,
            SectionKind::Data
            | SectionKind::ReadOnlyData
            | SectionKind::ReadOnlyString
            | SectionKind::UninitializedData
            | SectionKind::Common => SymbolKind::Data,
            SectionKind::Tls | SectionKind::UninitializedTls | SectionKind::TlsVariables => {
                SymbolKind::Tls
            }
            _ => SymbolKind::Unknown,
        })
        .unwrap_or(SymbolKind::Unknown);
    let weak = n_desc & (macho::N_WEAK_REF | macho::N_WEAK_DEF) != 0;
    let scope = if section == SymbolSection::Undefined {
        SymbolScope::Unknown
    } else if n_type & macho::N_EXT == 0 {
        SymbolScope::Compilation
    } else if n_type & macho::N_PEXT != 0 {
        SymbolScope::Linkage
    } else {
        SymbolScope::Dynamic
    };
    let flags = SymbolFlags::MachO { n_desc };
    Some(Symbol {
        name,
        address: nlist.n_value(endian).into(),
        // Only calculated for symbol maps
        size: 0,
        kind,
        section,
        weak,
        scope,
        flags,
    })
}

/// An iterator over the relocations in a `MachOSection32`.
pub type MachORelocationIterator32<'data, 'file, Endian = RunTimeEndian> =
    MachORelocationIterator<'data, 'file, macho::MachHeader32<Endian>>;
/// An iterator over the relocations in a `MachOSection64`.
pub type MachORelocationIterator64<'data, 'file, Endian = RunTimeEndian> =
    MachORelocationIterator<'data, 'file, macho::MachHeader64<Endian>>;

/// An iterator over the relocations in a `MachOSection`.
pub struct MachORelocationIterator<'data, 'file, Mach>
where
    'data: 'file,
    Mach: MachHeader,
{
    file: &'file MachOFile<'data, Mach>,
    relocations: slice::Iter<'data, macho::Relocation<Mach::Endian>>,
}

impl<'data, 'file, Mach: MachHeader> Iterator for MachORelocationIterator<'data, 'file, Mach> {
    type Item = (u64, Relocation);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let reloc = self.relocations.next()?;
            let endian = self.file.endian;
            let cputype = self.file.header.cputype(endian);
            if reloc.r_scattered(endian, cputype) {
                // FIXME: handle scattered relocations
                // We need to add `RelocationTarget::Address` for this.
                continue;
            }
            let reloc = reloc.info(self.file.endian);
            let mut encoding = RelocationEncoding::Generic;
            let kind = match cputype {
                macho::CPU_TYPE_ARM => match (reloc.r_type, reloc.r_pcrel) {
                    (macho::ARM_RELOC_VANILLA, false) => RelocationKind::Absolute,
                    _ => RelocationKind::MachO {
                        value: reloc.r_type,
                        relative: reloc.r_pcrel,
                    },
                },
                macho::CPU_TYPE_ARM64 => match (reloc.r_type, reloc.r_pcrel) {
                    (macho::ARM64_RELOC_UNSIGNED, false) => RelocationKind::Absolute,
                    _ => RelocationKind::MachO {
                        value: reloc.r_type,
                        relative: reloc.r_pcrel,
                    },
                },
                macho::CPU_TYPE_X86 => match (reloc.r_type, reloc.r_pcrel) {
                    (macho::GENERIC_RELOC_VANILLA, false) => RelocationKind::Absolute,
                    _ => RelocationKind::MachO {
                        value: reloc.r_type,
                        relative: reloc.r_pcrel,
                    },
                },
                macho::CPU_TYPE_X86_64 => match (reloc.r_type, reloc.r_pcrel) {
                    (macho::X86_64_RELOC_UNSIGNED, false) => RelocationKind::Absolute,
                    (macho::X86_64_RELOC_SIGNED, true) => {
                        encoding = RelocationEncoding::X86RipRelative;
                        RelocationKind::Relative
                    }
                    (macho::X86_64_RELOC_BRANCH, true) => {
                        encoding = RelocationEncoding::X86Branch;
                        RelocationKind::Relative
                    }
                    (macho::X86_64_RELOC_GOT, true) => RelocationKind::GotRelative,
                    (macho::X86_64_RELOC_GOT_LOAD, true) => {
                        encoding = RelocationEncoding::X86RipRelativeMovq;
                        RelocationKind::GotRelative
                    }
                    _ => RelocationKind::MachO {
                        value: reloc.r_type,
                        relative: reloc.r_pcrel,
                    },
                },
                _ => RelocationKind::MachO {
                    value: reloc.r_type,
                    relative: reloc.r_pcrel,
                },
            };
            let size = 8 << reloc.r_length;
            let target = if reloc.r_extern {
                RelocationTarget::Symbol(SymbolIndex(reloc.r_symbolnum as usize))
            } else {
                RelocationTarget::Section(SectionIndex(reloc.r_symbolnum as usize))
            };
            let addend = if reloc.r_pcrel { -4 } else { 0 };
            return Some((
                reloc.r_address as u64,
                Relocation {
                    kind,
                    encoding,
                    size,
                    target,
                    addend,
                    implicit_addend: true,
                },
            ));
        }
    }
}

impl<'data, 'file, Mach: MachHeader> fmt::Debug for MachORelocationIterator<'data, 'file, Mach> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachORelocationIterator").finish()
    }
}

/// An iterator over the load commands of a `MachHeader`.
#[derive(Debug, Default, Clone, Copy)]
pub struct MachOLoadCommandIterator<'data, E: Endian> {
    endian: E,
    data: &'data [u8],
    ncmds: u32,
}

impl<'data, E: Endian> MachOLoadCommandIterator<'data, E> {
    fn new(endian: E, data: &'data [u8], ncmds: u32) -> Self {
        MachOLoadCommandIterator {
            endian,
            data,
            ncmds,
        }
    }
}

impl<'data, E: Endian> Iterator for MachOLoadCommandIterator<'data, E> {
    type Item = MachOLoadCommand<'data, E>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ncmds == 0 {
            return None;
        }
        let (header, _) = pod::from_bytes::<macho::LoadCommand<E>>(self.data)?;
        let cmd = header.cmd.get(self.endian);
        let cmdsize = header.cmdsize.get(self.endian) as usize;
        let data = self.data.get(..cmdsize)?;
        self.data = self.data.get(cmdsize..)?;
        self.ncmds -= 1;
        Some(MachOLoadCommand {
            cmd,
            data,
            marker: Default::default(),
        })
    }
}

/// A parsed `LoadCommand`.
#[derive(Debug, Clone, Copy)]
pub struct MachOLoadCommand<'data, E: Endian> {
    cmd: u32,
    // Includes the header.
    data: &'data [u8],
    marker: PhantomData<E>,
}

impl<'data, E: Endian> MachOLoadCommand<'data, E> {
    /// Try to parse this command as a `SegmentCommand32`.
    pub fn segment_32(self) -> Option<(&'data macho::SegmentCommand32<E>, &'data [u8])> {
        if self.cmd == macho::LC_SEGMENT {
            pod::from_bytes(self.data)
        } else {
            None
        }
    }

    /// Try to parse this command as a `SymtabCommand`.
    pub fn symtab(self) -> Option<&'data macho::SymtabCommand<E>> {
        if self.cmd == macho::LC_SYMTAB {
            let (command, _) = pod::from_bytes(self.data)?;
            Some(command)
        } else {
            None
        }
    }

    /// Try to parse this command as a `UuidCommand`.
    pub fn uuid(self) -> Option<&'data macho::UuidCommand<E>> {
        if self.cmd == macho::LC_UUID {
            let (command, _) = pod::from_bytes(self.data)?;
            Some(command)
        } else {
            None
        }
    }

    /// Try to parse this command as a `SegmentCommand64`.
    pub fn segment_64(self) -> Option<(&'data macho::SegmentCommand64<E>, &'data [u8])> {
        if self.cmd == macho::LC_SEGMENT_64 {
            pod::from_bytes(self.data)
        } else {
            None
        }
    }

    /// Try to parse this command as an `EntryPointCommand`.
    pub fn entry_point(self) -> Option<&'data macho::EntryPointCommand<E>> {
        if self.cmd == macho::LC_MAIN {
            let (command, _) = pod::from_bytes(self.data)?;
            Some(command)
        } else {
            None
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct SymbolTable<'data, Mach: MachHeader> {
    symbols: &'data [Mach::Nlist],
    strings: StringTable<'data>,
}

/// A trait for generic access to `MachHeader32` and `MachHeader64`.
#[allow(missing_docs)]
pub trait MachHeader: Debug + Pod {
    type Word: Into<u64>;
    type Endian: endian::Endian;
    type Segment: Segment<Endian = Self::Endian, Section = Self::Section>;
    type Section: Section<Endian = Self::Endian>;
    type Nlist: Nlist<Endian = Self::Endian>;

    /// Return true if this type is a 64-bit header.
    ///
    /// This is a property of the type, not a value in the header data.
    fn is_type_64(&self) -> bool;

    /// Return true if the `magic` field signifies big-endian.
    fn is_big_endian(&self) -> bool;

    /// Return true if the `magic` field signifies little-endian.
    fn is_little_endian(&self) -> bool;

    fn magic(&self) -> u32;
    fn cputype(&self, endian: Self::Endian) -> u32;
    fn cpusubtype(&self, endian: Self::Endian) -> u32;
    fn filetype(&self, endian: Self::Endian) -> u32;
    fn ncmds(&self, endian: Self::Endian) -> u32;
    fn sizeofcmds(&self, endian: Self::Endian) -> u32;
    fn flags(&self, endian: Self::Endian) -> u32;

    // Provided methods.

    fn is_supported(&self) -> bool {
        self.is_little_endian() || self.is_big_endian()
    }

    fn endian(&self) -> Option<Self::Endian> {
        Self::Endian::from_big_endian(self.is_big_endian())
    }

    fn load_commands<'data>(
        &self,
        endian: Self::Endian,
        data: &'data [u8],
    ) -> Option<MachOLoadCommandIterator<'data, Self::Endian>> {
        let data = data
            .get(mem::size_of::<Self>()..)?
            .get(..self.sizeofcmds(endian) as usize)?;
        Some(MachOLoadCommandIterator::new(
            endian,
            data,
            self.ncmds(endian),
        ))
    }
}

/// A trait for generic access to `SegmentCommand32` and `SegmentCommand64`.
#[allow(missing_docs)]
pub trait Segment: Debug + Pod {
    type Word: Into<u64>;
    type Endian: endian::Endian;
    type Section: Section<Endian = Self::Endian>;

    fn from_command(command: MachOLoadCommand<Self::Endian>) -> Option<(&Self, &[u8])>;

    fn cmd(&self, endian: Self::Endian) -> u32;
    fn cmdsize(&self, endian: Self::Endian) -> u32;
    fn segname(&self) -> &[u8; 16];
    fn vmaddr(&self, endian: Self::Endian) -> Self::Word;
    fn vmsize(&self, endian: Self::Endian) -> Self::Word;
    fn fileoff(&self, endian: Self::Endian) -> Self::Word;
    fn filesize(&self, endian: Self::Endian) -> Self::Word;
    fn maxprot(&self, endian: Self::Endian) -> u32;
    fn initprot(&self, endian: Self::Endian) -> u32;
    fn nsects(&self, endian: Self::Endian) -> u32;
    fn flags(&self, endian: Self::Endian) -> u32;

    /// Return the `segname` bytes up until the null terminator.
    fn name(&self) -> &[u8] {
        let segname = &self.segname()[..];
        match segname.iter().position(|&x| x == 0) {
            Some(end) => &segname[..end],
            None => segname,
        }
    }

    /// Return the offset and size of the segment in the file.
    fn file_range(&self, endian: Self::Endian) -> (u64, u64) {
        (self.fileoff(endian).into(), self.filesize(endian).into())
    }

    /// Get the segment data from the file data.
    ///
    /// Returns `None` for invalid values.
    fn data<'data>(&self, endian: Self::Endian, data: &'data [u8]) -> Option<&'data [u8]> {
        let (offset, size) = self.file_range(endian);
        data.get(offset as usize..)?.get(..size as usize)
    }

    /// Get the array of sections from the data following the segment command.
    ///
    /// Returns `None` for invalid values.
    fn sections<'data>(
        &self,
        endian: Self::Endian,
        data: &'data [u8],
    ) -> Option<&'data [Self::Section]> {
        pod::slice_from_bytes(data, 0, self.nsects(endian) as usize).map(|x| x.0)
    }
}

/// A trait for generic access to `Section32` and `Section64`.
#[allow(missing_docs)]
pub trait Section: Debug + Pod {
    type Word: Into<u64>;
    type Endian: endian::Endian;

    fn sectname(&self) -> &[u8; 16];
    fn segname(&self) -> &[u8; 16];
    fn addr(&self, endian: Self::Endian) -> Self::Word;
    fn size(&self, endian: Self::Endian) -> Self::Word;
    fn offset(&self, endian: Self::Endian) -> u32;
    fn align(&self, endian: Self::Endian) -> u32;
    fn reloff(&self, endian: Self::Endian) -> u32;
    fn nreloc(&self, endian: Self::Endian) -> u32;
    fn flags(&self, endian: Self::Endian) -> u32;

    /// Return the `sectname` bytes up until the null terminator.
    fn name(&self) -> &[u8] {
        let sectname = &self.sectname()[..];
        match sectname.iter().position(|&x| x == 0) {
            Some(end) => &sectname[..end],
            None => sectname,
        }
    }

    /// Return the `segname` bytes up until the null terminator.
    fn segment_name(&self) -> &[u8] {
        let segname = &self.segname()[..];
        match segname.iter().position(|&x| x == 0) {
            Some(end) => &segname[..end],
            None => segname,
        }
    }

    /// Return the offset and size of the section in the file.
    ///
    /// Returns `None` for sections that have no data in the file.
    fn file_range(&self, endian: Self::Endian) -> Option<(u64, u64)> {
        match self.flags(endian) & macho::SECTION_TYPE {
            macho::S_ZEROFILL | macho::S_GB_ZEROFILL | macho::S_THREAD_LOCAL_ZEROFILL => None,
            _ => Some((self.offset(endian).into(), self.size(endian).into())),
        }
    }

    /// Return the section data.
    ///
    /// Returns `Some(&[])` if the section has no data.
    /// Returns `None` for invalid values.
    fn data<'data>(&self, endian: Self::Endian, data: &'data [u8]) -> Option<&'data [u8]> {
        if let Some((offset, size)) = self.file_range(endian) {
            data.get(offset as usize..)?.get(..size as usize)
        } else {
            Some(&[])
        }
    }

    /// Return the relocation array.
    ///
    /// Returns `None` for invalid values.
    fn relocations<'data>(
        &self,
        endian: Self::Endian,
        data: &'data [u8],
    ) -> Option<&'data [macho::Relocation<Self::Endian>]> {
        pod::slice_from_bytes(
            data,
            self.reloff(endian) as usize,
            self.nreloc(endian) as usize,
        )
        .map(|x| x.0)
    }
}

/// A trait for generic access to `Nlist32` and `Nlist64`.
#[allow(missing_docs)]
pub trait Nlist: Debug + Pod {
    type Word: Into<u64>;
    type Endian: endian::Endian;

    fn n_strx(&self, endian: Self::Endian) -> u32;
    fn n_type(&self) -> u8;
    fn n_sect(&self) -> u8;
    fn n_desc(&self, endian: Self::Endian) -> u16;
    fn n_value(&self, endian: Self::Endian) -> Self::Word;
}

impl<Endian: endian::Endian> MachHeader for macho::MachHeader32<Endian> {
    type Word = u32;
    type Endian = Endian;
    type Segment = macho::SegmentCommand32<Endian>;
    type Section = macho::Section32<Endian>;
    type Nlist = macho::Nlist32<Endian>;

    fn is_type_64(&self) -> bool {
        false
    }

    fn is_big_endian(&self) -> bool {
        self.magic() == macho::MH_MAGIC
    }

    fn is_little_endian(&self) -> bool {
        self.magic() == macho::MH_CIGAM
    }

    fn magic(&self) -> u32 {
        self.magic.get(BigEndian)
    }

    fn cputype(&self, endian: Self::Endian) -> u32 {
        self.cputype.get(endian)
    }

    fn cpusubtype(&self, endian: Self::Endian) -> u32 {
        self.cpusubtype.get(endian)
    }

    fn filetype(&self, endian: Self::Endian) -> u32 {
        self.filetype.get(endian)
    }

    fn ncmds(&self, endian: Self::Endian) -> u32 {
        self.ncmds.get(endian)
    }

    fn sizeofcmds(&self, endian: Self::Endian) -> u32 {
        self.sizeofcmds.get(endian)
    }

    fn flags(&self, endian: Self::Endian) -> u32 {
        self.flags.get(endian)
    }
}

impl<Endian: endian::Endian> MachHeader for macho::MachHeader64<Endian> {
    type Word = u64;
    type Endian = Endian;
    type Segment = macho::SegmentCommand64<Endian>;
    type Section = macho::Section64<Endian>;
    type Nlist = macho::Nlist64<Endian>;

    fn is_type_64(&self) -> bool {
        true
    }

    fn is_big_endian(&self) -> bool {
        self.magic() == macho::MH_MAGIC_64
    }

    fn is_little_endian(&self) -> bool {
        self.magic() == macho::MH_CIGAM_64
    }

    fn magic(&self) -> u32 {
        self.magic.get(BigEndian)
    }

    fn cputype(&self, endian: Self::Endian) -> u32 {
        self.cputype.get(endian)
    }

    fn cpusubtype(&self, endian: Self::Endian) -> u32 {
        self.cpusubtype.get(endian)
    }

    fn filetype(&self, endian: Self::Endian) -> u32 {
        self.filetype.get(endian)
    }

    fn ncmds(&self, endian: Self::Endian) -> u32 {
        self.ncmds.get(endian)
    }

    fn sizeofcmds(&self, endian: Self::Endian) -> u32 {
        self.sizeofcmds.get(endian)
    }

    fn flags(&self, endian: Self::Endian) -> u32 {
        self.flags.get(endian)
    }
}

impl<Endian: endian::Endian> Segment for macho::SegmentCommand32<Endian> {
    type Word = u32;
    type Endian = Endian;
    type Section = macho::Section32<Self::Endian>;

    fn from_command(command: MachOLoadCommand<Self::Endian>) -> Option<(&Self, &[u8])> {
        command.segment_32()
    }

    fn cmd(&self, endian: Self::Endian) -> u32 {
        self.cmd.get(endian)
    }
    fn cmdsize(&self, endian: Self::Endian) -> u32 {
        self.cmdsize.get(endian)
    }
    fn segname(&self) -> &[u8; 16] {
        &self.segname
    }
    fn vmaddr(&self, endian: Self::Endian) -> Self::Word {
        self.vmaddr.get(endian)
    }
    fn vmsize(&self, endian: Self::Endian) -> Self::Word {
        self.vmsize.get(endian)
    }
    fn fileoff(&self, endian: Self::Endian) -> Self::Word {
        self.fileoff.get(endian)
    }
    fn filesize(&self, endian: Self::Endian) -> Self::Word {
        self.filesize.get(endian)
    }
    fn maxprot(&self, endian: Self::Endian) -> u32 {
        self.maxprot.get(endian)
    }
    fn initprot(&self, endian: Self::Endian) -> u32 {
        self.initprot.get(endian)
    }
    fn nsects(&self, endian: Self::Endian) -> u32 {
        self.nsects.get(endian)
    }
    fn flags(&self, endian: Self::Endian) -> u32 {
        self.flags.get(endian)
    }
}

impl<Endian: endian::Endian> Segment for macho::SegmentCommand64<Endian> {
    type Word = u64;
    type Endian = Endian;
    type Section = macho::Section64<Self::Endian>;

    fn from_command(command: MachOLoadCommand<Self::Endian>) -> Option<(&Self, &[u8])> {
        command.segment_64()
    }

    fn cmd(&self, endian: Self::Endian) -> u32 {
        self.cmd.get(endian)
    }
    fn cmdsize(&self, endian: Self::Endian) -> u32 {
        self.cmdsize.get(endian)
    }
    fn segname(&self) -> &[u8; 16] {
        &self.segname
    }
    fn vmaddr(&self, endian: Self::Endian) -> Self::Word {
        self.vmaddr.get(endian)
    }
    fn vmsize(&self, endian: Self::Endian) -> Self::Word {
        self.vmsize.get(endian)
    }
    fn fileoff(&self, endian: Self::Endian) -> Self::Word {
        self.fileoff.get(endian)
    }
    fn filesize(&self, endian: Self::Endian) -> Self::Word {
        self.filesize.get(endian)
    }
    fn maxprot(&self, endian: Self::Endian) -> u32 {
        self.maxprot.get(endian)
    }
    fn initprot(&self, endian: Self::Endian) -> u32 {
        self.initprot.get(endian)
    }
    fn nsects(&self, endian: Self::Endian) -> u32 {
        self.nsects.get(endian)
    }
    fn flags(&self, endian: Self::Endian) -> u32 {
        self.flags.get(endian)
    }
}

impl<Endian: endian::Endian> Section for macho::Section32<Endian> {
    type Word = u32;
    type Endian = Endian;

    fn sectname(&self) -> &[u8; 16] {
        &self.sectname
    }
    fn segname(&self) -> &[u8; 16] {
        &self.segname
    }
    fn addr(&self, endian: Self::Endian) -> Self::Word {
        self.addr.get(endian)
    }
    fn size(&self, endian: Self::Endian) -> Self::Word {
        self.size.get(endian)
    }
    fn offset(&self, endian: Self::Endian) -> u32 {
        self.offset.get(endian)
    }
    fn align(&self, endian: Self::Endian) -> u32 {
        self.align.get(endian)
    }
    fn reloff(&self, endian: Self::Endian) -> u32 {
        self.reloff.get(endian)
    }
    fn nreloc(&self, endian: Self::Endian) -> u32 {
        self.nreloc.get(endian)
    }
    fn flags(&self, endian: Self::Endian) -> u32 {
        self.flags.get(endian)
    }
}

impl<Endian: endian::Endian> Section for macho::Section64<Endian> {
    type Word = u64;
    type Endian = Endian;

    fn sectname(&self) -> &[u8; 16] {
        &self.sectname
    }
    fn segname(&self) -> &[u8; 16] {
        &self.segname
    }
    fn addr(&self, endian: Self::Endian) -> Self::Word {
        self.addr.get(endian)
    }
    fn size(&self, endian: Self::Endian) -> Self::Word {
        self.size.get(endian)
    }
    fn offset(&self, endian: Self::Endian) -> u32 {
        self.offset.get(endian)
    }
    fn align(&self, endian: Self::Endian) -> u32 {
        self.align.get(endian)
    }
    fn reloff(&self, endian: Self::Endian) -> u32 {
        self.reloff.get(endian)
    }
    fn nreloc(&self, endian: Self::Endian) -> u32 {
        self.nreloc.get(endian)
    }
    fn flags(&self, endian: Self::Endian) -> u32 {
        self.flags.get(endian)
    }
}

impl<Endian: endian::Endian> Nlist for macho::Nlist32<Endian> {
    type Word = u32;
    type Endian = Endian;

    fn n_strx(&self, endian: Self::Endian) -> u32 {
        self.n_strx.get(endian)
    }
    fn n_type(&self) -> u8 {
        self.n_type
    }
    fn n_sect(&self) -> u8 {
        self.n_sect
    }
    fn n_desc(&self, endian: Self::Endian) -> u16 {
        self.n_desc.get(endian)
    }
    fn n_value(&self, endian: Self::Endian) -> Self::Word {
        self.n_value.get(endian)
    }
}

impl<Endian: endian::Endian> Nlist for macho::Nlist64<Endian> {
    type Word = u64;
    type Endian = Endian;

    fn n_strx(&self, endian: Self::Endian) -> u32 {
        self.n_strx.get(endian)
    }
    fn n_type(&self) -> u8 {
        self.n_type
    }
    fn n_sect(&self) -> u8 {
        self.n_sect
    }
    fn n_desc(&self, endian: Self::Endian) -> u16 {
        self.n_desc.get(endian)
    }
    fn n_value(&self, endian: Self::Endian) -> Self::Word {
        self.n_value.get(endian)
    }
}
