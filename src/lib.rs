mod object_trait;
pub use object_trait::Object;

// The elf crate will work on all platforms, even if that platform doesn't use
// elf files.
mod obj_linux;
pub use obj_linux::*;

// The mach_o crate uses the OSX mach-o system library, so will only build on
// OSX.
#[cfg(target_os="macos")]
mod obj_macos;
#[cfg(target_os="macos")]
pub use obj_macos::*;

#[cfg(target_os="linux")]
pub type File<'a> = Elf<'a>;
#[cfg(target_os="macos")]
pub type File<'a> = MachO<'a>;
