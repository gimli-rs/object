/// This example demonstrates how to create an object file with a simple main function that
/// calls puts("Hello, world!").
///
/// The resulting object file can be linked with a C runtime to create a complete executable:
/// ```sh
/// $ cargo run --features write --bin simple_write
/// $ gcc -o hello hello.o
/// $ ./hello
/// Hello, world!
/// ```
use object::write::{Object, Relocation, StandardSection, Symbol, SymbolScope, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationEncoding, RelocationFlags, RelocationKind,
    SymbolFlags, SymbolKind,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut obj = Object::new(
        BinaryFormat::native_object(),
        Architecture::X86_64,
        Endianness::Little,
    );

    // Add a file symbol (STT_FILE or equivalent).
    obj.add_file_symbol(b"hello.c".into());

    // Generate code for the equivalent of this C function:
    //     int main() {
    //         puts("Hello, world!");
    //         return 0;
    //     }
    let mut main_data = Vec::new();
    // sub $0x28, %rsp
    main_data.extend_from_slice(&[0x48, 0x83, 0xec, 0x28]);
    // Handle different calling convention on Windows.
    if cfg!(target_os = "windows") {
        // lea 0x0(%rip), %rcx
        main_data.extend_from_slice(&[0x48, 0x8d, 0x0d, 0x00, 0x00, 0x00, 0x00]);
    } else {
        // lea 0x0(%rip), %rdi
        main_data.extend_from_slice(&[0x48, 0x8d, 0x3d, 0x00, 0x00, 0x00, 0x00]);
    }
    // R_X86_64_PC32 .rodata-0x4
    let s_reloc_offset = main_data.len() - 4;
    let s_reloc_addend = -4;
    let s_reloc_flags = RelocationFlags::Generic {
        kind: RelocationKind::Relative,
        encoding: RelocationEncoding::Generic,
        size: 32,
    };
    // call 14 <main+0x14>
    main_data.extend_from_slice(&[0xe8, 0x00, 0x00, 0x00, 0x00]);
    // R_X86_64_PLT32 puts-0x4
    let puts_reloc_offset = main_data.len() - 4;
    let puts_reloc_addend = -4;
    let puts_reloc_flags = RelocationFlags::Generic {
        kind: RelocationKind::PltRelative,
        encoding: RelocationEncoding::X86Branch,
        size: 32,
    };
    // xor %eax, %eax
    main_data.extend_from_slice(&[0x31, 0xc0]);
    // add $0x28, %rsp
    main_data.extend_from_slice(&[0x48, 0x83, 0xc4, 0x28]);
    // ret
    main_data.extend_from_slice(&[0xc3]);

    // Add a globally visible symbol for the main function.
    let main_symbol = obj.add_symbol(Symbol {
        name: b"main".into(),
        value: 0,
        size: 0,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });
    // Add the main function in its own subsection (equivalent to -ffunction-sections).
    let main_section = obj.add_subsection(StandardSection::Text, b"main");
    let main_offset = obj.add_symbol_data(main_symbol, main_section, &main_data, 1);

    // Add a read only string constant for the puts argument.
    // We don't create a symbol for the constant, but instead refer to it by
    // the section symbol and section offset.
    let rodata_section = obj.section_id(StandardSection::ReadOnlyData);
    let rodata_symbol = obj.section_symbol(rodata_section);
    let s_offset = obj.append_section_data(rodata_section, b"Hello, world!\0", 1);

    // Relocation for the string constant.
    obj.add_relocation(
        main_section,
        Relocation {
            offset: main_offset + s_reloc_offset as u64,
            symbol: rodata_symbol,
            addend: s_offset as i64 + s_reloc_addend,
            flags: s_reloc_flags,
        },
    )?;

    // External symbol for puts.
    let puts_symbol = obj.add_symbol(Symbol {
        name: b"puts".into(),
        value: 0,
        size: 0,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });

    // Relocation for the call to puts.
    obj.add_relocation(
        main_section,
        Relocation {
            offset: puts_reloc_offset as u64,
            symbol: puts_symbol,
            addend: puts_reloc_addend,
            flags: puts_reloc_flags,
        },
    )?;

    // Finally, write the object file.
    let file = std::fs::File::create("hello.o")?;
    obj.write_stream(file)?;
    Ok(())
}
