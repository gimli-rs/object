use alloc::vec::Vec;
use core::convert::TryInto;
use core::fmt::Debug;

use crate::read::ReadError;
use crate::read::Result;
use crate::{pe, Bytes, LittleEndian as LE, U16Bytes, U32Bytes};

/// Possible exports from a PE file
#[derive(Clone)]
pub enum Export<'data> {
    /// A named exported symbol from this PE file
    Regular {
        /// The ordinal of this export
        ordinal: u32,
        /// The name of this export
        name: &'data [u8],
        /// The virtual address pointed to by this export
        address: u64,
    },

    /// An export that only has an ordinal, but no name
    ByOrdinal {
        /// The ordinal of this export
        ordinal: u32,
        /// The virtual address pointed to by this export
        address: u64,
    },

    /// A forwarded export (i.e. a symbol that is contained in some other DLL).
    /// This concept is [PE-specific](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#export-address-table)
    Forwarded {
        /// The ordinal of this export
        ordinal: u32,
        /// The name of this export
        name: &'data [u8],
        /// The name of the actual symbol, in some other lib.
        /// for example, "MYDLL.expfunc" or "MYDLL.#27"
        forwarded_to: &'data [u8],
    },

    /// A forwarded export (i.e. a symbol that is contained in some other DLL) that has no name.
    /// This concept is [PE-specific](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#export-address-table)
    ForwardedByOrdinal {
        /// The ordinal of this export
        ordinal: u32,
        /// The name of the actual symbol, in some other lib.
        /// for example, "MYDLL.expfunc" or "MYDLL.#27"
        forwarded_to: &'data [u8],
    },
}

impl<'a> Export<'a> {
    /// Returns the ordinal of this export
    pub fn ordinal(&self) -> u32 {
        match &self {
            &Export::Regular { ordinal, .. }
            | &Export::Forwarded { ordinal, .. }
            | &Export::ByOrdinal { ordinal, .. }
            | &Export::ForwardedByOrdinal { ordinal, .. } => *ordinal,
        }
    }

    /// Whether this export has a name
    pub fn has_name(&self) -> bool {
        match &self {
            &Export::Regular { .. } | &Export::Forwarded { .. } => true,
            &Export::ByOrdinal { .. } | &Export::ForwardedByOrdinal { .. } => false,
        }
    }
}

impl<'a> Debug for Export<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::result::Result<(), core::fmt::Error> {
        match &self {
            Export::Regular {
                ordinal,
                name,
                address,
            } => f
                .debug_struct("Regular")
                .field("ordinal", &ordinal)
                .field(
                    "data",
                    &core::str::from_utf8(name).unwrap_or("<invalid name>"),
                )
                .field("address", &address)
                .finish(),
            Export::ByOrdinal { ordinal, address } => f
                .debug_struct("ByOrdinal")
                .field("ordinal", &ordinal)
                .field("address", &address)
                .finish(),
            Export::Forwarded {
                ordinal,
                name,
                forwarded_to,
            } => f
                .debug_struct("Forwarded")
                .field("ordinal", &ordinal)
                .field(
                    "name",
                    &core::str::from_utf8(name).unwrap_or("<invalid name>"),
                )
                .field(
                    "forwarded_to",
                    &core::str::from_utf8(forwarded_to).unwrap_or("<invalid forward name>"),
                )
                .finish(),
            Export::ForwardedByOrdinal {
                ordinal,
                forwarded_to,
            } => f
                .debug_struct("ForwardedByOrdinal")
                .field("ordinal", &ordinal)
                .field(
                    "forwarded_to",
                    &core::str::from_utf8(forwarded_to).unwrap_or("<invalid forward name>"),
                )
                .finish(),
        }
    }
}

impl<'data, Pe, R> super::PeFile<'data, Pe, R>
where
    Pe: super::ImageNtHeaders,
    R: crate::ReadRef<'data>,
{
    /// Returns the exports of this PE file
    ///
    /// See also the [`PeFile::exports`] function, which only returns a subset of these exports.
    pub fn export_table(&self) -> Result<Vec<Export<'data>>> {
        let data_dir = match self.data_directory(pe::IMAGE_DIRECTORY_ENTRY_EXPORT) {
            Some(data_dir) => data_dir,
            None => return Ok(Vec::new()),
        };
        let export_va = data_dir.virtual_address.get(LE);
        let export_size = data_dir.size.get(LE);
        let export_data = data_dir.data(self.data, &self.common.sections).map(Bytes)?;
        let export_dir = export_data
            .read_at::<pe::ImageExportDirectory>(0)
            .read_error("Invalid PE export dir size")?;
        let addresses = export_data
            .read_slice_at::<U32Bytes<_>>(
                export_dir
                    .address_of_functions
                    .get(LE)
                    .wrapping_sub(export_va) as usize,
                export_dir.number_of_functions.get(LE) as usize,
            )
            .read_error("Invalid PE export address table")?;
        let number = export_dir.number_of_names.get(LE) as usize;
        let names = export_data
            .read_slice_at::<U32Bytes<_>>(
                export_dir.address_of_names.get(LE).wrapping_sub(export_va) as usize,
                number,
            )
            .read_error("Invalid PE export name table")?;
        let base_ordinal = export_dir.base.get(LE);
        let ordinals = export_data
            .read_slice_at::<U16Bytes<_>>(
                export_dir
                    .address_of_name_ordinals
                    .get(LE)
                    .wrapping_sub(export_va) as usize,
                number,
            )
            .read_error("Invalid PE export ordinal table")?;

        // First, let's list all exports...
        let mut exports = Vec::new();
        for (i, address) in addresses.iter().enumerate() {
            // Convert from an array index to an ordinal
            // The MSDN documentation is wrong here, see https://stackoverflow.com/a/40001778/721832
            let ordinal: u32 = match i.try_into() {
                Err(_err) => continue,
                Ok(index) => index,
            };
            let ordinal = ordinal + base_ordinal;
            let address = address.get(LE);

            // is it a regular or forwarded export?
            if address < export_va || (address - export_va) >= export_size {
                exports.push(Export::ByOrdinal {
                    ordinal: ordinal,
                    address: self.common.image_base.wrapping_add(address as u64),
                });
            } else {
                let forwarded_to = export_data
                    .read_string_at(address.wrapping_sub(export_va) as usize)
                    .read_error("Invalid target for PE forwarded export")?;
                exports.push(Export::ForwardedByOrdinal {
                    ordinal: ordinal,
                    forwarded_to: forwarded_to,
                });
            }
        }

        // Now, check whether some (or all) of them have an associated name
        for (name_ptr, ordinal_index) in names.iter().zip(ordinals.iter()) {
            // Items in the ordinal array are biased.
            // The MSDN documentation is wrong regarding this bias, see https://stackoverflow.com/a/40001778/721832
            let ordinal_index = ordinal_index.get(LE) as u32;

            let name = export_data
                .read_string_at(name_ptr.get(LE).wrapping_sub(export_va) as usize)
                .read_error("Invalid PE export name entry")?;

            let unnamed_equivalent = exports.get(ordinal_index as usize).cloned();
            match unnamed_equivalent {
                Some(Export::ByOrdinal { ordinal, address }) => {
                    let _ = core::mem::replace(
                        &mut exports[ordinal_index as usize],
                        Export::Regular {
                            name,
                            address,
                            ordinal,
                        },
                    );
                }

                Some(Export::ForwardedByOrdinal {
                    ordinal,
                    forwarded_to,
                }) => {
                    let _ = core::mem::replace(
                        &mut exports[ordinal_index as usize],
                        Export::Forwarded {
                            name,
                            ordinal,
                            forwarded_to,
                        },
                    );
                }

                _ => continue, // unless ordinals are not unique in the ordinals array, this should not happen
            }
        }

        Ok(exports)
    }
}
