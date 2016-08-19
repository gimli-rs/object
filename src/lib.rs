#[cfg(target_os="linux")]
mod obj_linux;
#[cfg(target_os="linux")]
pub use obj_linux::*;

#[cfg(target_os="macos")]
mod obj_macos;
#[cfg(target_os="macos")]
pub use obj_macos::*;
