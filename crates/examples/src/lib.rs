#[cfg(all(feature = "read", feature = "write"))]
pub mod objcopy;

#[cfg(feature = "read")]
pub mod objdump;

#[cfg(all(feature = "read", feature = "names"))]
pub mod readobj;

#[cfg(all(feature = "read", feature = "write"))]
mod elfcopy;
#[cfg(all(feature = "read", feature = "write"))]
pub use elfcopy::*;

#[cfg(all(feature = "read", feature = "write"))]
mod elfstub;
#[cfg(all(feature = "read", feature = "write"))]
pub use elfstub::*;
