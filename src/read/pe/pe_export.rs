use core::fmt::Debug;

/// Possible exports from a PE file
pub enum PeExport<'data> {
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

impl<'a> Debug for PeExport<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match &self {
            PeExport::Regular {
                ordinal,
                name,
                address,
            } => f
                .debug_struct("Regular")
                .field("ordinal", &ordinal)
                .field(
                    "data",
                    &std::str::from_utf8(name).unwrap_or("<invalid name>"),
                )
                .field("address", &address)
                .finish(),
            PeExport::ByOrdinal { ordinal, address } => f
                .debug_struct("ByOrdinal")
                .field("ordinal", &ordinal)
                .field("address", &address)
                .finish(),
            PeExport::Forwarded {
                ordinal,
                name,
                forwarded_to,
            } => f
                .debug_struct("Forwarded")
                .field("ordinal", &ordinal)
                .field(
                    "name",
                    &std::str::from_utf8(name).unwrap_or("<invalid name>"),
                )
                .field(
                    "forwarded_to",
                    &std::str::from_utf8(forwarded_to).unwrap_or("<invalid forward name>"),
                )
                .finish(),
            PeExport::ForwardedByOrdinal {
                ordinal,
                forwarded_to,
            } => f
                .debug_struct("ForwardedByOrdinal")
                .field("ordinal", &ordinal)
                .field(
                    "forwarded_to",
                    &std::str::from_utf8(forwarded_to).unwrap_or("<invalid forward name>"),
                )
                .finish(),
        }
    }
}
