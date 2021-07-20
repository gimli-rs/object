# `object`

The `object` crate provides a unified interface to working with object files
across platforms. It supports reading object files and executable files,
and writing object files.

For reading files, it provides multiple levels of support:

* raw struct definitions suitable for zero copy access
* low level APIs for accessing the raw structs
* a higher level unified API for accessing common features of object files, such
  as sections and symbols

Supported file formats: ELF, Mach-O, Windows PE/COFF, Wasm, and Unix archive.

## Example for unified read API
```rust
use object::{Object, ObjectSection};
use std::error::Error;
use std::fs;

/// Reads a file and displays the content of the ".boot" section.
fn main() -> Result<(), Box<dyn Error>> {
  let bin_data = fs::read("./multiboot2-binary.elf")?;
  let obj_file = object::File::parse(&*bin_data)?;
  if let Some(section) = obj_file.section_by_name(".boot") {
    println!("{:#x?}", section.data()?);
  } else {
    eprintln!("section not available");
  }
  Ok(())
}
```

## License

Licensed under either of

  * Apache License, Version 2.0 ([`LICENSE-APACHE`](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
  * MIT license ([`LICENSE-MIT`](./LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
