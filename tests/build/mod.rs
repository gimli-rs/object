#![cfg(feature = "build")]

mod elf;
#[cfg(all(feature = "macho", feature = "std"))]
mod macho;
