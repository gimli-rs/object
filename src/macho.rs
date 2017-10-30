use std::cmp::Ordering;

use goblin::mach;

use {SectionKind, Symbol, SymbolKind};

pub(crate) fn get_section<'a>(macho: &mach::MachO<'a>, section_name: &str) -> Option<&'a [u8]> {
    let segment_name = if section_name == ".eh_frame" {
        "__TEXT"
    } else {
        "__DWARF"
    };
    let section_name = translate_section_name(section_name);

    for segment in &macho.segments {
        if let Ok(name) = segment.name() {
            if name == segment_name {
                for section in segment {
                    if let Ok((section, data)) = section {
                        if let Ok(name) = section.name() {
                            if name.as_bytes() == &*section_name {
                                return Some(data);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

// Translate the "." prefix to the "__" prefix used by OSX/Mach-O, eg
// ".debug_info" to "__debug_info".
fn translate_section_name(section_name: &str) -> Vec<u8> {
    let mut name = Vec::with_capacity(section_name.len() + 1);
    name.push(b'_');
    name.push(b'_');
    for ch in &section_name.as_bytes()[1..] {
        name.push(*ch);
    }
    name
}

pub(crate) fn get_symbols<'a>(macho: &mach::MachO<'a>) -> Vec<Symbol<'a>> {
    // Determine section kinds and end addresses.
    // The section kinds are inherited by symbols in those sections.
    // The section end addresses are needed for calculating symbol sizes.
    let mut section_kinds = Vec::new();
    let mut section_ends = Vec::new();
    for segment in &macho.segments {
        for section in segment {
            if let Ok((section, _)) = section {
                let sectname = section
                    .name()
                    .map(str::as_bytes)
                    .unwrap_or(&section.sectname[..]);
                let segname = section
                    .segname()
                    .map(str::as_bytes)
                    .unwrap_or(&section.segname[..]);
                let (section_kind, symbol_kind) = if segname == b"__TEXT" && sectname == b"__text" {
                    (SectionKind::Text, SymbolKind::Text)
                } else if segname == b"__DATA" && sectname == b"__data" {
                    (SectionKind::Data, SymbolKind::Data)
                } else if segname == b"__DATA" && sectname == b"__bss" {
                    (SectionKind::UninitializedData, SymbolKind::Data)
                } else {
                    (SectionKind::Other, SymbolKind::Unknown)
                };
                let section_index = section_kinds.len();
                section_kinds.push((section_kind, symbol_kind));
                section_ends.push(Symbol {
                    kind: SymbolKind::Section,
                    section: section_index + 1,
                    section_kind: Some(section_kind),
                    global: false,
                    name: &[],
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
    for sym in macho.symbols() {
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
                name: name.as_bytes(),
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
