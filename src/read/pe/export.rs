use alloc::vec::Vec;
use core::convert::TryInto;
use core::fmt::Debug;

use crate::read::ReadError;
use crate::read::Result;
use crate::ByteString;
use crate::{pe, Bytes, LittleEndian as LE, U16Bytes, U32Bytes};

/// Where an export is pointing to
#[derive(Clone)]
pub enum ExportTarget<'data> {
    /// The export points at a RVA in the file
    Local(u64),
    /// The export is "forwarded" to another DLL
    ///
    /// for example, "MYDLL.expfunc" or "MYDLL.#27"
    Forwarded(&'data [u8]),
}

/// An export from a PE file
///
/// There are multiple kinds of PE exports (with or without a name, and local or exported)
#[derive(Clone)]
pub struct Export<'data> {
    /// The ordinal of the export
    pub ordinal: u32,
    /// The name of the export, if ever the PE file has named it
    pub name: Option<&'data [u8]>,
    /// The target of this export
    pub target: ExportTarget<'data>,
}

impl<'a> Debug for Export<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::result::Result<(), core::fmt::Error> {
        f.debug_struct("Export")
            .field("ordinal", &self.ordinal)
            .field("name", &self.name.map(ByteString))
            .field("target", &self.target)
            .finish()
    }
}

impl<'a> Debug for ExportTarget<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::result::Result<(), core::fmt::Error> {
        match self {
            ExportTarget::Local(addr) => f.write_fmt(format_args!("Local({:#x})", addr)),
            ExportTarget::Forwarded(forward) => {
                f.write_fmt(format_args!("Forwarded({:?})", ByteString(forward)))
            }
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
                exports.push(Export {
                    ordinal: ordinal,
                    target: ExportTarget::Local(
                        self.common.image_base.wrapping_add(address as u64),
                    ),
                    name: None, // might be populated later
                });
            } else {
                let forwarded_to = export_data
                    .read_string_at(address.wrapping_sub(export_va) as usize)
                    .read_error("Invalid target for PE forwarded export")?;
                exports.push(Export {
                    ordinal: ordinal,
                    target: ExportTarget::Forwarded(forwarded_to),
                    name: None, // might be populated later
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

            exports
                .get_mut(ordinal_index as usize)
                .ok_or_else(|| crate::read::Error("Invalid PE export ordinal"))?
                .name = Some(name);
        }

        Ok(exports)
    }
}
