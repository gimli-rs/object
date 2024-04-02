use object::write::{Object, Relocation, StandardSection, Symbol, SymbolScope, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationEncoding, RelocationFlags, RelocationKind,
    SymbolFlags, SymbolKind,
};

// needs feature `write`

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut obj = Object::new(BinaryFormat::Host, Architecture::X86_64, Endianness::Little);
    obj.add_file_symbol(b"test.c".into());

    // External definitions.
    let deadbeef_data = obj.add_symbol(Symbol {
        name: b"DEADBEEF".into(),
        value: 0,
        size: 0,
        kind: SymbolKind::Data,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });
    let printf = obj.add_symbol(Symbol {
        name: b"printf".into(),
        value: 0,
        size: 0,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });

    // 0000000000000000 <deadbeef>:
    //    0:	55                   	push   %rbp
    //    1:	48 89 e5             	mov    %rsp,%rbp
    //    4:	48 8b 05 00 00 00 00 	mov    0x0(%rip),%rax        # b <deadbeef+0xb>
    // 			7: R_X86_64_GOTPCREL	DEADBEEF-0x4
    //    b:	8b 08                	mov    (%rax),%ecx
    //    d:	83 c1 01             	add    $0x1,%ecx
    //   10:	89 c8                	mov    %ecx,%eax
    //   12:	5d                   	pop    %rbp
    //   13:	c3                   	retq
    let name = b"deadbeef";
    #[rustfmt::skip]
    let deadbeef = [
        0x55,
        0x48, 0x89, 0xe5,
        0x48, 0x8b, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x8b, 0x08,
        0x83, 0xc1, 0x01,
        0x89, 0xc8,
        0x5d,
        0xc3,
    ];
    let (deadbeef_section, deadbeef_offset) =
        obj.add_subsection(StandardSection::Text, name, &deadbeef, 16);
    let deadbeef = obj.add_symbol(Symbol {
        name: name.into(),
        value: deadbeef_offset,
        size: deadbeef.len() as u64,
        kind: SymbolKind::Text,
        scope: SymbolScope::Compilation,
        weak: false,
        section: SymbolSection::Section(deadbeef_section),
        flags: SymbolFlags::None,
    });

    // main:
    // 55	push   %rbp
    // 48 89 e5	mov    %rsp,%rbp
    // b8 00 00 00 00	mov    $0x0,%eax
    // e8 00 00 00 00   callq  0x0 <deadbeef>
    // 89 c6	mov    %eax,%esi
    // 48 8d 3d 00 00 00 00 lea    0x0(%rip),%rdi # will be: deadbeef: 0x%x\n
    // b8 00 00 00 00	mov    $0x0,%eax
    // e8 00 00 00 00	callq  0x3f <main+33>  # printf
    // b8 00 00 00 00	mov    $0x0,%eax
    // 5d	pop    %rbp
    // c3	retq
    let name = b"main";
    #[rustfmt::skip]
    let main = [
        0x55,
        0x48, 0x89, 0xe5,
        0xb8, 0x00, 0x00, 0x00, 0x00,
        0xe8, 0x00, 0x00, 0x00, 0x00,
        0x89, 0xc6,
        0x48, 0x8d, 0x3d, 0x00, 0x00, 0x00, 0x00,
        0xb8, 0x00, 0x00, 0x00, 0x00,
        0xe8, 0x00, 0x00, 0x00, 0x00,
        0xb8, 0x00, 0x00, 0x00, 0x00,
        0x5d,
        0xc3,
    ];
    let (main_section, main_offset) = obj.add_subsection(StandardSection::Text, name, &main, 16);
    obj.add_symbol(Symbol {
        name: name.into(),
        value: main_offset,
        size: main.len() as u64,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(main_section),
        flags: SymbolFlags::None,
    });

    // String constant for the format string
    let name = b"str.1";
    let str1 = b"deadbeef: 0x%x\n\0";
    let (str1_section, str1_offset) =
        obj.add_subsection(StandardSection::ReadOnlyData, name, str1, 1);
    let str1 = obj.add_symbol(Symbol {
        name: name.into(),
        value: str1_offset,
        size: str1.len() as u64,
        kind: SymbolKind::Data,
        scope: SymbolScope::Compilation,
        weak: false,
        section: SymbolSection::Section(str1_section),
        flags: SymbolFlags::None,
    });

    // Next, we add our relocations,
    obj.add_relocation(
        main_section,
        Relocation {
            offset: main_offset + 19,
            symbol: str1,
            addend: -4,
            flags: RelocationFlags::Generic {
                kind: RelocationKind::Relative,
                encoding: RelocationEncoding::Generic,
                size: 32,
            },
        },
    )?;
    obj.add_relocation(
        main_section,
        Relocation {
            offset: main_offset + 29,
            symbol: printf,
            addend: -4,
            flags: RelocationFlags::Generic {
                kind: RelocationKind::PltRelative,
                encoding: RelocationEncoding::X86Branch,
                size: 32,
            },
        },
    )?;
    obj.add_relocation(
        main_section,
        Relocation {
            offset: main_offset + 10,
            symbol: deadbeef,
            addend: -4,
            flags: RelocationFlags::Generic {
                kind: RelocationKind::Relative,
                encoding: RelocationEncoding::X86Branch,
                size: 32,
            },
        },
    )?;
    obj.add_relocation(
        deadbeef_section,
        Relocation {
            offset: deadbeef_offset + 7,
            symbol: deadbeef_data,
            addend: -4,
            flags: RelocationFlags::Generic {
                kind: RelocationKind::GotRelative,
                encoding: RelocationEncoding::X86RipRelativeMovq,
                size: 32,
            },
        },
    )?;

    // Finally, we write the object file
    let name = "test.o";
    let file = std::fs::File::create(std::path::Path::new(name))?;
    obj.write_stream(file)?;
    Ok(())
}