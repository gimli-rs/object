#![cfg(feature = "read")]

mod coff;
mod elf;
mod goff;
mod macho;

#[cfg(feature = "compression")]
mod compression;
