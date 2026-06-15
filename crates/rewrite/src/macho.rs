use std::collections::{HashMap, HashSet};

#[cfg(feature = "logging")]
use log::info;
#[cfg(feature = "logging")]
use object::build::ByteString;

use super::{Error, Result, Rewriter};
use crate::rewriter::Builder;

/// Options for modifying a Mach-O file.
///
/// This struct contains options for modifying a Mach-O file. It is
/// contained in the [`Options`](super::Options) struct.
///
/// Options are listed in the order they are processed.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct MachOOptions {}

impl Rewriter<'_> {
    pub(crate) fn macho_delete_symbols(&mut self, names: &HashSet<Vec<u8>>) {
        let Builder::MachO(builder) = &mut self.builder else {
            return;
        };
        for symbol in &mut builder.symbols {
            if names.contains(&*symbol.name) {
                #[cfg(feature = "logging")]
                info!("Deleting symbol {}", symbol.name);
                symbol.delete = true;
                self.modified = true;
            }
        }
    }

    pub(crate) fn macho_rename_symbols(&mut self, names: &HashMap<Vec<u8>, Vec<u8>>) {
        let Builder::MachO(builder) = &mut self.builder else {
            return;
        };
        for symbol in &mut builder.symbols {
            if let Some(name) = names.get(&*symbol.name) {
                let name = name.clone().into();
                #[cfg(feature = "logging")]
                info!("Renaming symbol {} to {}", symbol.name, name);
                symbol.name = name;
                self.modified = true;
            }
        }
    }

    pub(crate) fn macho_delete_sections(&mut self, names: &HashSet<Vec<u8>>) {
        let Builder::MachO(builder) = &mut self.builder else {
            return;
        };
        for section in &mut builder.sections {
            if names.contains(section.sectname()) {
                #[cfg(feature = "logging")]
                info!("Deleting section {}", ByteString::from(section.sectname()));
                section.delete = true;
                self.modified = true;
            }
        }
    }

    pub(crate) fn macho_rename_sections(
        &mut self,
        names: &HashMap<Vec<u8>, Vec<u8>>,
    ) -> Result<()> {
        let Builder::MachO(builder) = &mut self.builder else {
            return Ok(());
        };
        for section in &mut builder.sections {
            if let Some(name) = names.get(section.sectname()) {
                #[cfg(feature = "logging")]
                info!(
                    "Renaming section {} to {}",
                    ByteString::from(section.sectname()),
                    ByteString::from(&name[..]),
                );
                let len = name.len();
                if len > section.sectname.len() {
                    return Err(Error::modify("Name too long; can't rename section"));
                }
                section.sectname = [0; 16];
                section.sectname[..len].copy_from_slice(name);
                self.modified = true;
            }
        }
        Ok(())
    }

    pub(crate) fn macho_modify(&mut self, _options: MachOOptions) -> Result<()> {
        Ok(())
    }

    pub(crate) fn macho_finalize(&mut self) -> Result<()> {
        Ok(())
    }
}
