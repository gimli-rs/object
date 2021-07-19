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

## Example
```rust
use std::fs::File;
use std::io::Read;
use object::{Object, ObjectSection, File as ObjectFile};

/// Reads an ELF-file and displays the content of the ".boot" section.
fn main() {
    let mut file = File::open("./multiboot2-binary.elf").unwrap();
    let mut data = vec![];
    file.read_to_end(&mut data).unwrap();
    let data = data.into_boxed_slice();
    let obj_file = ObjectFile::parse(&*data).unwrap();
    let section = obj_file.section_by_name(".boot").unwrap();
    let data = section.data().unwrap();
    println!("{:#x?}", data)
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
