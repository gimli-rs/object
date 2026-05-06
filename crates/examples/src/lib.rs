#[cfg(all(feature = "read", feature = "write"))]
pub mod objcopy;

#[cfg(feature = "read")]
pub mod objdump;

#[cfg(all(feature = "read", feature = "names"))]
pub mod readobj;
