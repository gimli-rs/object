use std::collections::{HashMap, HashSet};

#[cfg(feature = "logging")]
use log::info;
use object::{build, elf};

use super::{Error, Result, Rewriter};

/// Options for modifying an ELF file.
///
/// This struct contains options for modifying an ELF file. It is
/// contained in the [`Options`](super::Options) struct.
///
/// Options are listed in the order they are processed.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct ElfOptions {
    /// Add a `DT_DEBUG` entry to the dynamic section.
    ///
    /// See [`Rewriter::elf_add_dynamic_debug`].
    pub add_dynamic_debug: bool,
    /// Delete any `DT_RUNPATH` and `DT_RPATH` entries in the dynamic section.
    ///
    /// See [`Rewriter::elf_delete_runpath`].
    pub delete_runpath: bool,
    /// Set the path for any `DT_RUNPATH` or `DT_RPATH` entry in the dynamic section.
    ///
    /// See [`Rewriter::elf_set_runpath`].
    pub set_runpath: Option<Vec<u8>>,
    /// Add additional paths to any `DT_RUNPATH` or `DT_RPATH` entry in the dynamic section.
    ///
    /// See [`Rewriter::elf_add_runpath`].
    pub add_runpath: Vec<Vec<u8>>,
    /// Change any `DT_RPATH` entry in the dynamic section to `DT_RUNPATH`.
    ///
    /// See [`Rewriter::elf_use_runpath`].
    pub use_runpath: bool,
    /// Change any `DT_RUNPATH` entry in the dynamic section to `DT_RPATH`.
    ///
    /// See [`Rewriter::elf_use_rpath`].
    pub use_rpath: bool,
    /// Delete `DT_NEEDED` entries from the dynamic section.
    ///
    /// See [`Rewriter::elf_delete_needed`].
    pub delete_needed: HashSet<Vec<u8>>,
    /// Replace `DT_NEEDED` entries in the dynamic section.
    ///
    /// See [`Rewriter::elf_replace_needed`].
    pub replace_needed: HashMap<Vec<u8>, Vec<u8>>,
    /// Add `DT_NEEDED` entries to the start of the dynamic section.
    ///
    /// See [`Rewriter::elf_add_needed`].
    pub add_needed: Vec<Vec<u8>>,
    /// Set the `DT_SONAME` entry in the dynamic section.
    ///
    /// See [`Rewriter::elf_set_soname`].
    pub set_soname: Option<Vec<u8>>,
    /// Set the interpreter path in the `PT_INTERP` segment.
    ///
    /// See [`Rewriter::elf_set_interpreter`].
    pub set_interpreter: Option<Vec<u8>>,
}

impl<'data> Rewriter<'data> {
    /// Delete symbols from the symbol table.
    pub fn elf_delete_symbols(&mut self, names: &HashSet<Vec<u8>>) {
        for symbol in &mut self.builder.dynamic_symbols {
            if names.contains(&*symbol.name) {
                #[cfg(feature = "logging")]
                info!("Deleting symbol {}", symbol.name);
                symbol.delete = true;
                self.modified = true;
            }
        }
    }

    /// Delete symbols from the dynamic symbol table.
    pub fn elf_delete_dynamic_symbols(&mut self, names: &HashSet<Vec<u8>>) {
        for symbol in &mut self.builder.symbols {
            if names.contains(&*symbol.name) {
                #[cfg(feature = "logging")]
                info!("Deleting dynamic symbol {}", symbol.name);
                symbol.delete = true;
                self.modified = true;
            }
        }
    }

    /// Rename symbols in the symbol table.
    ///
    /// The `names` map is from old names to new names.
    pub fn elf_rename_symbols(&mut self, names: &HashMap<Vec<u8>, Vec<u8>>) {
        for symbol in &mut self.builder.dynamic_symbols {
            if let Some(name) = names.get(&*symbol.name) {
                let name = name.clone().into();
                #[cfg(feature = "logging")]
                info!("Renaming symbol {} to {}", symbol.name, name);
                symbol.name = name;
                self.modified = true;
            }
        }
    }

    /// Rename symbols in the dynamic symbol table.
    ///
    /// The `names` map is from old names to new names.
    pub fn elf_rename_dynamic_symbols(&mut self, names: &HashMap<Vec<u8>, Vec<u8>>) {
        for symbol in &mut self.builder.dynamic_symbols {
            if let Some(name) = names.get(&*symbol.name) {
                let name = name.clone().into();
                #[cfg(feature = "logging")]
                info!("Renaming dynamic symbol {} to {}", symbol.name, name);
                symbol.name = name;
                self.modified = true;
            }
        }
    }

    pub(crate) fn elf_delete_sections(&mut self, names: &HashSet<Vec<u8>>) {
        for section in &mut self.builder.sections {
            if names.contains(&*section.name) {
                #[cfg(feature = "logging")]
                info!("Deleting section {}", section.name);
                // Associated program header will be deleted by delete_orphan_segments.
                section.delete = true;
                self.modified = true;
            }
        }
    }

    pub(crate) fn elf_rename_sections(&mut self, names: &HashMap<Vec<u8>, Vec<u8>>) {
        for section in &mut self.builder.sections {
            if let Some(name) = names.get(&*section.name) {
                let name = name.clone().into();
                #[cfg(feature = "logging")]
                info!("Renaming section {} to {}", section.name, name);
                section.name = name;
                self.modified = true;
            }
        }
    }

    pub(crate) fn elf_modify(&mut self, options: ElfOptions) -> Result<()> {
        if options.add_dynamic_debug {
            self.elf_add_dynamic_debug()?;
        }
        if options.delete_runpath {
            self.elf_delete_runpath()?;
        }
        if let Some(path) = options.set_runpath {
            self.elf_set_runpath(path)?;
        }
        if !options.add_runpath.is_empty() {
            self.elf_add_runpath(&options.add_runpath)?;
        }
        if options.use_runpath {
            self.elf_use_runpath()?;
        }
        if options.use_rpath {
            self.elf_use_rpath()?;
        }
        if !options.delete_needed.is_empty() {
            self.elf_delete_needed(&options.delete_needed)?;
        }
        if !options.replace_needed.is_empty() {
            self.elf_replace_needed(&options.replace_needed)?;
        }
        if !options.add_needed.is_empty() {
            self.elf_add_needed(&options.add_needed)?;
        }
        if let Some(name) = options.set_soname {
            self.elf_set_soname(name)?;
        }
        if let Some(interpreter) = options.set_interpreter {
            self.elf_set_interpreter(interpreter)?;
        }
        Ok(())
    }

    /// Add a `DT_DEBUG` entry to the dynamic section.
    pub fn elf_add_dynamic_debug(&mut self) -> Result<()> {
        let dynamic = self
            .builder
            .dynamic_data_mut()
            .ok_or_else(|| Error::modify("No dynamic section found; can't add debug entry"))?;
        if dynamic.iter().any(|entry| entry.tag() == elf::DT_DEBUG) {
            return Ok(());
        }

        #[cfg(feature = "logging")]
        info!("Adding DT_DEBUG entry");
        dynamic.push(build::elf::Dynamic::Integer {
            tag: elf::DT_DEBUG,
            val: 0,
        });
        self.modified = true;
        Ok(())
    }

    /// Find the first `DT_RUNPATH` or `DT_RPATH` entry in the dynamic section.
    pub fn elf_runpath(&self) -> Option<&[u8]> {
        let dynamic = self.builder.dynamic_data()?;
        for entry in dynamic.iter() {
            let build::elf::Dynamic::String { tag, val } = entry else {
                continue;
            };
            if *tag != elf::DT_RPATH && *tag != elf::DT_RUNPATH {
                continue;
            }
            return Some(val);
        }
        None
    }

    /// Delete any `DT_RUNPATH` or `DT_RPATH` entries in the dynamic section.
    pub fn elf_delete_runpath(&mut self) -> Result<()> {
        let dynamic = self
            .builder
            .dynamic_data_mut()
            .ok_or_else(|| Error::modify("No dynamic section found; can't delete runpath"))?;
        let mut modified = false;
        dynamic.retain(|entry| {
            let tag = entry.tag();
            if tag != elf::DT_RPATH && tag != elf::DT_RUNPATH {
                return true;
            }

            #[cfg(feature = "logging")]
            info!(
                "Deleting {} entry",
                if tag == elf::DT_RPATH {
                    "DT_RPATH"
                } else {
                    "DT_RUNPATH"
                }
            );
            modified = true;
            false
        });
        if modified {
            self.modified = true;
        }
        Ok(())
    }

    /// Set the path for any `DT_RUNPATH` or `DT_RPATH` entry in the dynamic section.
    pub fn elf_set_runpath(&mut self, runpath: Vec<u8>) -> Result<()> {
        let dynamic = self
            .builder
            .dynamic_data_mut()
            .ok_or_else(|| Error::modify("No dynamic section found; can't set runpath"))?;
        let mut found = false;
        for entry in dynamic.iter_mut() {
            let build::elf::Dynamic::String { tag, val } = entry else {
                continue;
            };
            if *tag != elf::DT_RPATH && *tag != elf::DT_RUNPATH {
                continue;
            }

            *val = build::ByteString::from(runpath.clone());
            #[cfg(feature = "logging")]
            info!(
                "Setting {} entry to {}",
                if *tag == elf::DT_RPATH {
                    "DT_RPATH"
                } else {
                    "DT_RUNPATH"
                },
                *val
            );
            found = true;
        }
        if !found {
            let val = build::ByteString::from(runpath);
            #[cfg(feature = "logging")]
            info!("Adding DT_RUNPATH entry {}", val);
            dynamic.push(build::elf::Dynamic::String {
                tag: elf::DT_RUNPATH,
                val,
            });
        }
        self.modified = true;
        Ok(())
    }

    /// Add additional paths to any `DT_RUNPATH` or `DT_RPATH` entry in the dynamic section.
    pub fn elf_add_runpath(&mut self, runpaths: &[Vec<u8>]) -> Result<()> {
        let dynamic = self
            .builder
            .dynamic_data_mut()
            .ok_or_else(|| Error::modify("No dynamic section found; can't add runpath"))?;
        let mut found = false;
        for entry in dynamic.iter_mut() {
            let build::elf::Dynamic::String { tag, val } = entry else {
                continue;
            };
            if *tag != elf::DT_RPATH && *tag != elf::DT_RUNPATH {
                continue;
            }

            for path in runpaths {
                if !val.is_empty() {
                    val.to_mut().push(b':');
                }
                val.to_mut().extend_from_slice(path);
            }
            #[cfg(feature = "logging")]
            info!(
                "Changing {} entry to {}",
                if *tag == elf::DT_RPATH {
                    "DT_RPATH"
                } else {
                    "DT_RUNPATH"
                },
                val
            );
            found = true;
        }
        if !found {
            let val = runpaths.join(&[b':'][..]).into();
            #[cfg(feature = "logging")]
            info!("Adding DT_RUNPATH entry {}", val);
            dynamic.push(build::elf::Dynamic::String {
                tag: elf::DT_RUNPATH,
                val,
            });
        }
        self.modified = true;
        Ok(())
    }

    /// Change any `DT_RPATH` entry in the dynamic section to `DT_RUNPATH`.
    pub fn elf_use_runpath(&mut self) -> Result<()> {
        let dynamic = self
            .builder
            .dynamic_data_mut()
            .ok_or_else(|| Error::modify("No dynamic section found; can't change runpath"))?;
        for entry in dynamic.iter_mut() {
            let build::elf::Dynamic::String { tag, .. } = entry else {
                continue;
            };
            if *tag != elf::DT_RPATH {
                continue;
            }

            #[cfg(feature = "logging")]
            info!("Changing DT_RPATH to DT_RUNPATH");
            *tag = elf::DT_RUNPATH;
            self.modified = true;
        }
        Ok(())
    }

    /// Change any `DT_RUNPATH` entry in the dynamic section to `DT_RPATH`.
    pub fn elf_use_rpath(&mut self) -> Result<()> {
        let dynamic = self
            .builder
            .dynamic_data_mut()
            .ok_or_else(|| Error::modify("No dynamic section found; can't change rpath"))?;
        for entry in dynamic.iter_mut() {
            let build::elf::Dynamic::String { tag, .. } = entry else {
                continue;
            };
            if *tag != elf::DT_RUNPATH {
                continue;
            }

            #[cfg(feature = "logging")]
            info!("Changing DT_RUNPATH to DT_RPATH");
            *tag = elf::DT_RPATH;
            self.modified = true;
        }
        Ok(())
    }

    /// Find the `DT_NEEDED` entries in the dynamic section.
    pub fn elf_needed(&self) -> impl Iterator<Item = &[u8]> {
        let dynamic = self.builder.dynamic_data().unwrap_or(&[]);
        dynamic.iter().filter_map(|entry| {
            if let build::elf::Dynamic::String { tag, val } = entry {
                if *tag == elf::DT_NEEDED {
                    return Some(val.as_slice());
                }
            }
            None
        })
    }

    /// Delete `DT_NEEDED` entries from the dynamic section.
    pub fn elf_delete_needed(&mut self, names: &HashSet<Vec<u8>>) -> Result<()> {
        let dynamic = self.builder.dynamic_data_mut().ok_or_else(|| {
            Error::modify("No dynamic section found; can't delete needed library")
        })?;
        let mut modified = false;
        dynamic.retain(|entry| {
            let build::elf::Dynamic::String { tag, val } = entry else {
                return true;
            };
            if *tag != elf::DT_NEEDED || !names.contains(val.as_slice()) {
                return true;
            }

            #[cfg(feature = "logging")]
            info!("Deleting DT_NEEDED entry {}", val);
            modified = true;
            false
        });
        if modified {
            self.modified = true;
        }
        Ok(())
    }

    /// Replace `DT_NEEDED` entries in the dynamic section.
    pub fn elf_replace_needed(&mut self, names: &HashMap<Vec<u8>, Vec<u8>>) -> Result<()> {
        let dynamic = self.builder.dynamic_data_mut().ok_or_else(|| {
            Error::modify("No dynamic section found; can't replace needed library")
        })?;
        for entry in dynamic.iter_mut() {
            let build::elf::Dynamic::String { tag, val } = entry else {
                continue;
            };
            if *tag != elf::DT_NEEDED {
                continue;
            }
            let Some(name) = names.get(val.as_slice()) else {
                continue;
            };

            let name = name.clone().into();
            #[cfg(feature = "logging")]
            info!("Replacing DT_NEEDED entry {} with {}", val, name);
            *val = name;
            self.modified = true;
        }
        Ok(())
    }

    /// Add `DT_NEEDED` entries to the start of the dynamic section.
    ///
    /// This does not add a `DT_NEEDED` entry if the library is already listed.
    pub fn elf_add_needed(&mut self, names: &[Vec<u8>]) -> Result<()> {
        let dynamic = self
            .builder
            .dynamic_data_mut()
            .ok_or_else(|| Error::modify("No dynamic section found; can't add needed library"))?;
        let mut found = HashSet::new();
        for entry in dynamic.iter() {
            let build::elf::Dynamic::String { tag, val } = entry else {
                continue;
            };
            if *tag != elf::DT_NEEDED {
                continue;
            }
            found.insert(val.clone());
        }
        for name in names
            .iter()
            .rev()
            .filter(|name| !found.contains(name.as_slice()))
        {
            let val = name.clone().into();
            #[cfg(feature = "logging")]
            info!("Adding DT_NEEDED entry {}", val);
            dynamic.insert(
                0,
                build::elf::Dynamic::String {
                    tag: elf::DT_NEEDED,
                    val,
                },
            );
            self.modified = true;
        }
        Ok(())
    }

    /// Find the `DT_SONAME` entry in the dynamic section.
    pub fn elf_soname(&self) -> Option<&[u8]> {
        let id = self.builder.dynamic_section()?;
        let section = self.builder.sections.get(id);
        let build::elf::SectionData::Dynamic(dynamic) = &section.data else {
            return None;
        };
        for entry in dynamic.iter() {
            let build::elf::Dynamic::String { tag, val } = entry else {
                continue;
            };
            if *tag != elf::DT_SONAME {
                continue;
            }

            return Some(val);
        }
        None
    }

    /// Set the `DT_SONAME` entry in the dynamic section.
    pub fn elf_set_soname(&mut self, soname: Vec<u8>) -> Result<()> {
        let dynamic = self
            .builder
            .dynamic_data_mut()
            .ok_or_else(|| Error::modify("No dynamic section found; can't set soname"))?;
        let mut found = false;
        for entry in dynamic.iter_mut() {
            let build::elf::Dynamic::String { tag, val } = entry else {
                continue;
            };
            if *tag != elf::DT_SONAME {
                continue;
            }

            *val = soname.clone().into();
            #[cfg(feature = "logging")]
            info!("Setting DT_SONAME entry to {}", val);
            found = true;
        }
        if !found {
            let val = soname.into();
            #[cfg(feature = "logging")]
            info!("Adding DT_SONAME entry {}", val);
            dynamic.push(build::elf::Dynamic::String {
                tag: elf::DT_SONAME,
                val,
            });
        }
        self.modified = true;
        Ok(())
    }

    /// Find the interpreter path in the `PT_INTERP` segment.
    pub fn elf_interpreter(&self) -> Option<&[u8]> {
        self.builder.interp_data()
    }

    /// Set the interpreter path in the `PT_INTERP` segment.
    ///
    /// The null terminator is automatically added if needed.
    pub fn elf_set_interpreter(&mut self, mut interpreter: Vec<u8>) -> Result<()> {
        let data = self
            .builder
            .interp_data_mut()
            .ok_or_else(|| Error::modify("No interp section found; can't set interpreter"))?;
        #[cfg(feature = "logging")]
        info!(
            "Setting interpreter to {}",
            build::ByteString::from(interpreter.as_slice())
        );
        if !interpreter.is_empty() && interpreter.last() != Some(&0) {
            interpreter.push(0);
        }
        *data = interpreter.into();
        self.modified = true;
        Ok(())
    }

    pub(crate) fn elf_finalize(&mut self) -> Result<()> {
        if self.modified {
            move_sections(&mut self.builder)?;
        }
        Ok(())
    }
}

enum BlockKind {
    FileHeader,
    ProgramHeaders,
    Segment,
    Section(build::elf::SectionId),
}

struct Block<'a> {
    #[allow(dead_code)]
    name: build::ByteString<'a>,
    kind: BlockKind,
    address: u64,
    size: u64,
    // Higher means better to move. 0 means never move.
    move_priority: u8,
}

/// Move sections between segments if needed, and assign file offsets to segments and sections.
///
/// Does not change the size of existing `PT_LOAD` segments, but may add new segments.
// TODO: allow changing size of existing `PT_LOAD` segments
fn move_sections(builder: &mut build::elf::Builder) -> Result<()> {
    builder.delete_orphans();
    builder.delete_unused_versions();
    builder.set_section_sizes();

    let mut added_p_flags = Vec::new();
    let mut added_segments = 0;

    // Loop until we reach a fixed point for the number of additional segments needed.
    loop {
        let mut move_sections = find_move_sections(builder, added_segments)?;
        if move_sections.is_empty() {
            return Ok(());
        }

        // Calculate the number of additional PT_LOAD segments needed.
        added_p_flags.clear();
        for id in &move_sections {
            let section = builder.sections.get_mut(*id);
            // Flag the section as needing to move.
            section.sh_offset = 0;
            // We need one PT_LOAD segment for each unique combination of p_flags.
            let p_flags = section.p_flags();
            if !added_p_flags.contains(&p_flags) {
                added_p_flags.push(p_flags);
            }
        }

        // If moving a section that is part of a non-PT_LOAD segment, then we may need to
        // split the segment, which will require an additional segment.
        let mut split_segments = 0;
        for segment in &mut builder.segments {
            if segment.p_type == elf::PT_LOAD {
                continue;
            }
            let mut any = false;
            let mut all = true;
            for id in &segment.sections {
                if move_sections.contains(id) {
                    any = true;
                } else {
                    all = false;
                }
            }
            if !any || all {
                continue;
            }
            split_segments += 1;
        }

        // Check if we have reached a fixed point for the number of additional segments needed.
        if added_segments < split_segments + added_p_flags.len() {
            added_segments = split_segments + added_p_flags.len();
            continue;
        }

        #[cfg(feature = "logging")]
        info!(
            "Moving {} sections, adding {} PT_LOAD segments, splitting {} segments",
            move_sections.len(),
            added_p_flags.len(),
            split_segments,
        );

        // Add the PT_LOAD segments and append sections to them.
        // Try to keep the same order of sections in the new segments.
        move_sections.sort_by_key(|id| {
            let section = builder.sections.get(*id);
            (section.sh_addr, section.sh_size)
        });
        for p_flags in added_p_flags {
            // TODO: reuse segments that only contain movable sections
            let segment = builder
                .segments
                .add_load_segment(p_flags, builder.load_align);
            for id in &move_sections {
                let section = builder.sections.get_mut(*id);
                if p_flags == section.p_flags() {
                    segment.append_section(section);
                    #[cfg(feature = "logging")]
                    info!(
                        "Moved {} to offset {:x}, addr {:x}",
                        section.name, section.sh_offset, section.sh_addr
                    );
                }
            }
            #[cfg(feature = "logging")]
            info!(
                "Added PT_LOAD segment with p_flags {:x}, offset {:x}, addr {:x}, size {:x}",
                p_flags, segment.p_offset, segment.p_vaddr, segment.p_memsz,
            );
        }

        // Split or move non-PT_LOAD segments that contain sections that have been moved.
        let sections = &builder.sections;
        let mut split_segments = Vec::new();
        for segment in &mut builder.segments {
            if segment.p_type == elf::PT_LOAD {
                continue;
            }

            let mut any = false;
            let mut all = true;
            for id in &segment.sections {
                if move_sections.contains(id) {
                    any = true;
                } else {
                    all = false;
                }
            }
            if !any {
                continue;
            }
            if !all {
                // Segment needs splitting.
                // Remove all the sections that have been moved, and store them so
                // that we can add the new segment later.
                let mut split_sections = Vec::new();
                segment.sections.retain(|id| {
                    if move_sections.contains(id) {
                        split_sections.push(*id);
                        false
                    } else {
                        true
                    }
                });
                split_segments.push((segment.id(), split_sections));
            }

            // The remaining sections have already been assigned an address.
            // Recalcuate the file and address ranges for the segment.
            // TODO: verify that the sections are contiguous. If not, try to slide the sections
            // down in memory.
            segment.recalculate_ranges(sections);
        }

        // Add new segments due to splitting.
        for (segment_id, split_sections) in split_segments {
            let segment = builder.segments.copy(segment_id);
            for id in split_sections {
                let section = builder.sections.get_mut(id);
                segment.append_section(section);
            }
            #[cfg(feature = "logging")]
            info!(
                "Split segment with type {:x}, offset {:x}, addr {:x}, size {:x}",
                segment.p_type, segment.p_offset, segment.p_vaddr, segment.p_memsz,
            );
        }

        // Update the PT_PHDR segment to include the new program headers.
        let size = builder.program_headers_size() as u64;
        for segment in &mut builder.segments {
            if segment.p_type != elf::PT_PHDR {
                continue;
            }
            segment.p_filesz = size;
            segment.p_memsz = size;
        }
        return Ok(());
    }
}

fn find_move_sections(
    builder: &build::elf::Builder,
    added_segments: usize,
) -> Result<Vec<build::elf::SectionId>> {
    use build::elf::SectionData;

    let mut move_sections = Vec::new();
    let mut blocks = Vec::new();
    let file_header_size = builder.file_header_size() as u64;
    let program_headers_size = (builder.program_headers_size()
        + added_segments * builder.class().program_header_size())
        as u64;
    let interp = builder.interp_section();

    if let Some(segment) = builder.segments.find_load_segment_from_offset(0) {
        let address = segment.address_from_offset(0);
        blocks.push(Block {
            name: "file header".into(),
            kind: BlockKind::FileHeader,
            address,
            size: file_header_size,
            move_priority: 0,
        });
    }
    if let Some(segment) = builder
        .segments
        .find_load_segment_from_offset(builder.header.e_phoff)
    {
        let address = segment.address_from_offset(builder.header.e_phoff);
        blocks.push(Block {
            name: "program headers".into(),
            kind: BlockKind::ProgramHeaders,
            address,
            size: program_headers_size,
            move_priority: 0,
        });
    }
    for segment in &builder.segments {
        if segment.p_type != elf::PT_LOAD {
            continue;
        }
        // Add zero-sized blocks at the start and end of the segment
        // to prevent changing the segment address or size.
        blocks.push(Block {
            name: "segment start".into(),
            kind: BlockKind::Segment,
            address: segment.p_vaddr,
            size: 0,
            move_priority: 0,
        });
        blocks.push(Block {
            name: "segment end".into(),
            kind: BlockKind::Segment,
            address: segment.p_vaddr + segment.p_memsz,
            size: 0,
            move_priority: 0,
        });
    }
    for section in &builder.sections {
        if !section.is_alloc() {
            continue;
        }
        if section.sh_offset == 0 {
            // Newly added section that needs to be assigned to a segment,
            // or a section that has already been flagged for moving.
            move_sections.push(section.id());
            continue;
        }
        if section.sh_type == elf::SHT_NOBITS && section.sh_flags & u64::from(elf::SHF_TLS) != 0 {
            // Uninitialized TLS sections are not part of the address space.
            continue;
        }
        let move_priority = match &section.data {
            // Can't move sections whose address may referenced from
            // a section that we can't rewrite.
            SectionData::Data(_) => {
                if Some(section.id()) == interp {
                    1
                } else {
                    0
                }
            }
            SectionData::UninitializedData(_) | SectionData::Dynamic(_) => 0,
            // TODO: Can be referenced by dynamic entries, but we don't support that yet.
            SectionData::DynamicRelocation(_) => 0,
            // None of these can be referenced by address that I am aware of.
            SectionData::Relocation(_)
            | SectionData::Note(_)
            | SectionData::Attributes(_)
            | SectionData::SectionString
            | SectionData::Symbol
            | SectionData::SymbolSectionIndex
            | SectionData::String
            | SectionData::DynamicSymbol
            | SectionData::DynamicString
            | SectionData::Hash
            | SectionData::GnuHash
            | SectionData::GnuVersym
            | SectionData::GnuVerdef
            | SectionData::GnuVerneed => 2,
        };
        blocks.push(Block {
            name: (*section.name).into(),
            kind: BlockKind::Section(section.id()),
            address: section.sh_addr,
            size: section.sh_size,
            move_priority,
        });
    }
    blocks.sort_by_key(|block| (block.address, block.size));

    // For each pair of overlapping blocks, decide which one to move.
    let mut i = 0;
    while i + 1 < blocks.len() {
        let end_address = blocks[i].address + blocks[i].size;
        if end_address <= blocks[i + 1].address {
            i += 1;
            continue;
        }
        // Prefer moving the earlier block, since it is the reason for the overlap.
        if blocks[i].move_priority >= blocks[i + 1].move_priority {
            if blocks[i].move_priority == 0 {
                #[cfg(feature = "logging")]
                info!(
                    "Immovable {} (end address {:x}) overlaps immovable {} (start address {:x})",
                    blocks[i].name,
                    end_address,
                    blocks[i + 1].name,
                    blocks[i + 1].address,
                );
                return Err(Error::modify("Overlapping immovable sections"));
            }
            #[cfg(feature = "logging")]
            info!(
                "Need to move {} (end address {:x}) because of {} (start address {:x})",
                blocks[i].name,
                end_address,
                blocks[i + 1].name,
                blocks[i + 1].address,
            );
            if let BlockKind::Section(section) = blocks[i].kind {
                move_sections.push(section);
                blocks.remove(i);
            } else {
                // Only sections can be moved.
                unreachable!();
            }
        } else {
            #[cfg(feature = "logging")]
            info!(
                "Need to move {} (start address {:x}) because of {} (end address {:x})",
                blocks[i + 1].name,
                blocks[i + 1].address,
                blocks[i].name,
                end_address,
            );
            if let BlockKind::Section(section) = blocks[i + 1].kind {
                move_sections.push(section);
                blocks.remove(i + 1);
            } else {
                // Only sections can be moved.
                unreachable!();
            }
        }
    }
    Ok(move_sections)
}
