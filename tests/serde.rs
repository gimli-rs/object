#[cfg(feature = "enable_serde")]
mod serde {
    use std::u8;

    use object::{
        AddressSize, Architecture, BinaryFormat, ComdatKind, FileFlags, RelocationEncoding,
        RelocationFlags, RelocationKind, SectionFlags, SectionKind, SegmentFlags, SubArchitecture,
        SymbolFlags, SymbolKind, SymbolScope,
    };
    use serde_test::{assert_tokens, Token};

    #[test]
    fn architecture() {
        let mut got = Architecture::Unknown;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Unknown",
            }],
        );

        got = Architecture::Aarch64;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Aarch64",
            }],
        );
        got = Architecture::Aarch64_Ilp32;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Aarch64_Ilp32",
            }],
        );
        got = Architecture::Arm;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Arm",
            }],
        );
        got = Architecture::Avr;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Avr",
            }],
        );
        got = Architecture::Bpf;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Bpf",
            }],
        );
        got = Architecture::Csky;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Csky",
            }],
        );
        got = Architecture::E2K32;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "E2K32",
            }],
        );
        got = Architecture::E2K64;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "E2K64",
            }],
        );
        got = Architecture::I386;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "I386",
            }],
        );
        got = Architecture::X86_64;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "X86_64",
            }],
        );
        got = Architecture::X86_64_X32;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "X86_64_X32",
            }],
        );
        got = Architecture::Hexagon;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Hexagon",
            }],
        );
        got = Architecture::LoongArch64;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "LoongArch64",
            }],
        );
        got = Architecture::Mips;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Mips",
            }],
        );
        got = Architecture::Mips64;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Mips64",
            }],
        );
        got = Architecture::Msp430;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Msp430",
            }],
        );
        got = Architecture::PowerPc;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "PowerPc",
            }],
        );
        got = Architecture::PowerPc64;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "PowerPc64",
            }],
        );
        got = Architecture::Riscv32;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Riscv32",
            }],
        );
        got = Architecture::Riscv64;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Riscv64",
            }],
        );
        got = Architecture::S390x;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "S390x",
            }],
        );
        got = Architecture::Sbf;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Sbf",
            }],
        );
        got = Architecture::Sharc;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Sharc",
            }],
        );
        got = Architecture::Sparc;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Sparc",
            }],
        );
        got = Architecture::Sparc32Plus;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Sparc32Plus",
            }],
        );
        got = Architecture::Sparc64;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Sparc64",
            }],
        );
        got = Architecture::Wasm32;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Wasm32",
            }],
        );
        got = Architecture::Wasm64;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Wasm64",
            }],
        );
        got = Architecture::Xtensa;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "Architecture",
                variant: "Xtensa",
            }],
        );
    }

    #[test]
    fn subarchitecture() {
        let mut got = SubArchitecture::Arm64E;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SubArchitecture",
                variant: "Arm64E",
            }],
        );
        got = SubArchitecture::Arm64EC;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SubArchitecture",
                variant: "Arm64EC",
            }],
        );
    }

    #[test]
    fn address_size() {
        let mut got = AddressSize::U8;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "AddressSize",
                variant: "U8",
            }],
        );
        got = AddressSize::U16;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "AddressSize",
                variant: "U16",
            }],
        );
        got = AddressSize::U32;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "AddressSize",
                variant: "U32",
            }],
        );

        got = AddressSize::U64;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "AddressSize",
                variant: "U64",
            }],
        );
    }

    #[test]
    fn binary_format() {
        let mut got = BinaryFormat::Coff;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "BinaryFormat",
                variant: "Coff",
            }],
        );
        got = BinaryFormat::Elf;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "BinaryFormat",
                variant: "Elf",
            }],
        );
        got = BinaryFormat::MachO;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "BinaryFormat",
                variant: "MachO",
            }],
        );
        got = BinaryFormat::Pe;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "BinaryFormat",
                variant: "Pe",
            }],
        );
        got = BinaryFormat::Wasm;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "BinaryFormat",
                variant: "Wasm",
            }],
        );
        got = BinaryFormat::Xcoff;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "BinaryFormat",
                variant: "Xcoff",
            }],
        );
    }
    #[test]
    fn section_kind() {
        let mut got = SectionKind::Unknown;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SectionKind",
                variant: "Unknown",
            }],
        );
        got = SectionKind::Text;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SectionKind",
                variant: "Text",
            }],
        );
        got = SectionKind::Data;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SectionKind",
                variant: "Data",
            }],
        );
        got = SectionKind::ReadOnlyData;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SectionKind",
                variant: "ReadOnlyData",
            }],
        );
        got = SectionKind::ReadOnlyDataWithRel;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SectionKind",
                variant: "ReadOnlyDataWithRel",
            }],
        );
        got = SectionKind::ReadOnlyString;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SectionKind",
                variant: "ReadOnlyString",
            }],
        );
        got = SectionKind::UninitializedData;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SectionKind",
                variant: "UninitializedData",
            }],
        );
        got = SectionKind::Common;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SectionKind",
                variant: "Common",
            }],
        );
        got = SectionKind::Tls;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SectionKind",
                variant: "Tls",
            }],
        );
        got = SectionKind::UninitializedTls;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SectionKind",
                variant: "UninitializedTls",
            }],
        );
        got = SectionKind::TlsVariables;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SectionKind",
                variant: "TlsVariables",
            }],
        );
        got = SectionKind::OtherString;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SectionKind",
                variant: "OtherString",
            }],
        );
        got = SectionKind::Other;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SectionKind",
                variant: "Other",
            }],
        );
        got = SectionKind::Debug;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SectionKind",
                variant: "Debug",
            }],
        );
        got = SectionKind::DebugString;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SectionKind",
                variant: "DebugString",
            }],
        );
        got = SectionKind::Linker;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SectionKind",
                variant: "Linker",
            }],
        );
        got = SectionKind::Note;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SectionKind",
                variant: "Note",
            }],
        );
        got = SectionKind::Metadata;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SectionKind",
                variant: "Metadata",
            }],
        );
        for i in 0..1_000_000 {
            got = SectionKind::Elf(i);
            assert_tokens(
                &got,
                &[
                    Token::NewtypeVariant {
                        name: "SectionKind",
                        variant: "Elf",
                    },
                    Token::U32(i),
                ],
            );
        }
    }

    #[test]
    fn comdat_kind() {
        let mut got = ComdatKind::Unknown;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "ComdatKind",
                variant: "Unknown",
            }],
        );
        got = ComdatKind::Any;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "ComdatKind",
                variant: "Any",
            }],
        );
        got = ComdatKind::NoDuplicates;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "ComdatKind",
                variant: "NoDuplicates",
            }],
        );
        got = ComdatKind::SameSize;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "ComdatKind",
                variant: "SameSize",
            }],
        );
        got = ComdatKind::ExactMatch;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "ComdatKind",
                variant: "ExactMatch",
            }],
        );
        got = ComdatKind::Largest;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "ComdatKind",
                variant: "Largest",
            }],
        );
        got = ComdatKind::Newest;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "ComdatKind",
                variant: "Newest",
            }],
        );
    }
    #[test]
    fn symbol_kind() {
        let mut got = SymbolKind::Unknown;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SymbolKind",
                variant: "Unknown",
            }],
        );
        got = SymbolKind::Text;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SymbolKind",
                variant: "Text",
            }],
        );
        got = SymbolKind::Data;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SymbolKind",
                variant: "Data",
            }],
        );
        got = SymbolKind::Section;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SymbolKind",
                variant: "Section",
            }],
        );
        got = SymbolKind::File;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SymbolKind",
                variant: "File",
            }],
        );
        got = SymbolKind::Label;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SymbolKind",
                variant: "Label",
            }],
        );
        got = SymbolKind::Tls;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SymbolKind",
                variant: "Tls",
            }],
        );
    }

    #[test]
    fn symbol_scope() {
        let mut got = SymbolScope::Unknown;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SymbolScope",
                variant: "Unknown",
            }],
        );
        got = SymbolScope::Compilation;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SymbolScope",
                variant: "Compilation",
            }],
        );
        got = SymbolScope::Linkage;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SymbolScope",
                variant: "Linkage",
            }],
        );
        got = SymbolScope::Dynamic;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SymbolScope",
                variant: "Dynamic",
            }],
        );
    }

    #[test]
    fn relocation_kind() {
        let mut got = RelocationKind::Unknown;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationKind",
                variant: "Unknown",
            }],
        );
        got = RelocationKind::Absolute;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationKind",
                variant: "Absolute",
            }],
        );
        got = RelocationKind::Relative;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationKind",
                variant: "Relative",
            }],
        );
        got = RelocationKind::Got;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationKind",
                variant: "Got",
            }],
        );
        got = RelocationKind::GotRelative;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationKind",
                variant: "GotRelative",
            }],
        );
        got = RelocationKind::GotBaseRelative;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationKind",
                variant: "GotBaseRelative",
            }],
        );
        got = RelocationKind::GotBaseOffset;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationKind",
                variant: "GotBaseOffset",
            }],
        );
        got = RelocationKind::PltRelative;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationKind",
                variant: "PltRelative",
            }],
        );
        got = RelocationKind::ImageOffset;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationKind",
                variant: "ImageOffset",
            }],
        );
        got = RelocationKind::SectionOffset;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationKind",
                variant: "SectionOffset",
            }],
        );
        got = RelocationKind::SectionIndex;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationKind",
                variant: "SectionIndex",
            }],
        );
    }

    #[test]
    pub fn relocation_encoding() {
        let mut got = RelocationEncoding::Unknown;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationEncoding",
                variant: "Unknown",
            }],
        );
        got = RelocationEncoding::Generic;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationEncoding",
                variant: "Generic",
            }],
        );
        got = RelocationEncoding::X86Signed;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationEncoding",
                variant: "X86Signed",
            }],
        );
        got = RelocationEncoding::X86RipRelative;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationEncoding",
                variant: "X86RipRelative",
            }],
        );
        got = RelocationEncoding::X86RipRelativeMovq;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationEncoding",
                variant: "X86RipRelativeMovq",
            }],
        );
        got = RelocationEncoding::X86Branch;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationEncoding",
                variant: "X86Branch",
            }],
        );
        got = RelocationEncoding::S390xDbl;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationEncoding",
                variant: "S390xDbl",
            }],
        );
        got = RelocationEncoding::AArch64Call;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationEncoding",
                variant: "AArch64Call",
            }],
        );
        got = RelocationEncoding::LoongArchBranch;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationEncoding",
                variant: "LoongArchBranch",
            }],
        );
        got = RelocationEncoding::SharcTypeA;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationEncoding",
                variant: "SharcTypeA",
            }],
        );
        got = RelocationEncoding::SharcTypeB;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationEncoding",
                variant: "SharcTypeB",
            }],
        );
        got = RelocationEncoding::E2KLit;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationEncoding",
                variant: "E2KLit",
            }],
        );
        got = RelocationEncoding::E2KDisp;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "RelocationEncoding",
                variant: "E2KDisp",
            }],
        );
    }

    #[test]
    fn file_flags() {
        let mut got = FileFlags::None;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "FileFlags",
                variant: "None",
            }],
        );

        for os_abi in 0..=50 {
            for abi_version in 0..=50 {
                for e_flags in 0..=50 {
                    got = FileFlags::Elf {
                        os_abi,
                        abi_version,
                        e_flags,
                    };
                    assert_tokens(
                        &got,
                        &[
                            Token::StructVariant {
                                name: "FileFlags",
                                variant: "Elf",
                                len: 3,
                            },
                            Token::Str("os_abi"),
                            Token::U8(os_abi),
                            Token::Str("abi_version"),
                            Token::U8(abi_version),
                            Token::Str("e_flags"),
                            Token::U32(e_flags),
                            Token::StructVariantEnd,
                        ],
                    );
                }
            }
        }

        for flags in 0..=1_000_000 {
            got = FileFlags::MachO { flags };
            assert_tokens(
                &got,
                &[
                    Token::StructVariant {
                        name: "FileFlags",
                        variant: "MachO",
                        len: 1,
                    },
                    Token::Str("flags"),
                    Token::U32(flags),
                    Token::StructVariantEnd,
                ],
            );
        }

        for characteristics in 0..(u16::MAX as _) {
            got = FileFlags::Coff { characteristics };
            assert_tokens(
                &got,
                &[
                    Token::StructVariant {
                        name: "FileFlags",
                        variant: "Coff",
                        len: 1,
                    },
                    Token::Str("characteristics"),
                    Token::U16(characteristics),
                    Token::StructVariantEnd,
                ],
            );
        }

        for f_flags in 0..=(u16::MAX as _) {
            got = FileFlags::Xcoff { f_flags };
            assert_tokens(
                &got,
                &[
                    Token::StructVariant {
                        name: "FileFlags",
                        variant: "Xcoff",
                        len: 1,
                    },
                    Token::Str("f_flags"),
                    Token::U16(f_flags),
                    Token::StructVariantEnd,
                ],
            );
        }
    }

    #[test]
    fn segment_flags() {
        let mut got = SegmentFlags::None;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SegmentFlags",
                variant: "None",
            }],
        );

        for p_flags in 0..=1_000_000 {
            got = SegmentFlags::Elf { p_flags };
            assert_tokens(
                &got,
                &[
                    Token::StructVariant {
                        name: "SegmentFlags",
                        variant: "Elf",
                        len: 1,
                    },
                    Token::Str("p_flags"),
                    Token::U32(p_flags),
                    Token::StructVariantEnd,
                ],
            );
        }

        for flags in 0..=50 {
            for maxprot in 0..=50 {
                for initprot in 0..=50 {
                    got = SegmentFlags::MachO {
                        flags,
                        maxprot,
                        initprot,
                    };
                    assert_tokens(
                        &got,
                        &[
                            Token::StructVariant {
                                name: "SegmentFlags",
                                variant: "MachO",
                                len: 3,
                            },
                            Token::Str("flags"),
                            Token::U32(flags),
                            Token::Str("maxprot"),
                            Token::U32(maxprot),
                            Token::Str("initprot"),
                            Token::U32(initprot),
                            Token::StructVariantEnd,
                        ],
                    );
                }
            }
        }

        for characteristics in 0..(u16::MAX as _) {
            got = SegmentFlags::Coff { characteristics };
            assert_tokens(
                &got,
                &[
                    Token::StructVariant {
                        name: "SegmentFlags",
                        variant: "Coff",
                        len: 1,
                    },
                    Token::Str("characteristics"),
                    Token::U32(characteristics),
                    Token::StructVariantEnd,
                ],
            );
        }
    }

    #[test]
    fn section_flags() {
        let mut got = SectionFlags::None;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SectionFlags",
                variant: "None",
            }],
        );

        for sh_flags in 0..=1_000_000 {
            got = SectionFlags::Elf { sh_flags };
            assert_tokens(
                &got,
                &[
                    Token::StructVariant {
                        name: "SectionFlags",
                        variant: "Elf",
                        len: 1,
                    },
                    Token::Str("sh_flags"),
                    Token::U64(sh_flags),
                    Token::StructVariantEnd,
                ],
            );
        }

        for flags in 0..=1_000_000 {
            got = SectionFlags::MachO { flags };
            assert_tokens(
                &got,
                &[
                    Token::StructVariant {
                        name: "SectionFlags",
                        variant: "MachO",
                        len: 1,
                    },
                    Token::Str("flags"),
                    Token::U32(flags),
                    Token::StructVariantEnd,
                ],
            );
        }

        for characteristics in 0..(u16::MAX as _) {
            got = SectionFlags::Coff { characteristics };
            assert_tokens(
                &got,
                &[
                    Token::StructVariant {
                        name: "SectionFlags",
                        variant: "Coff",
                        len: 1,
                    },
                    Token::Str("characteristics"),
                    Token::U32(characteristics),
                    Token::StructVariantEnd,
                ],
            );
        }

        for s_flags in 0..=(u16::MAX as _) {
            got = SectionFlags::Xcoff { s_flags };
            assert_tokens(
                &got,
                &[
                    Token::StructVariant {
                        name: "SectionFlags",
                        variant: "Xcoff",
                        len: 1,
                    },
                    Token::Str("s_flags"),
                    Token::U32(s_flags),
                    Token::StructVariantEnd,
                ],
            );
        }
    }

    #[test]
    fn symbol_flags() {
        let mut got = SymbolFlags::None;
        assert_tokens(
            &got,
            &[Token::UnitVariant {
                name: "SymbolFlags",
                variant: "None",
            }],
        );

        for st_info in 0..=u8::MAX {
            for st_other in 0..=u8::MAX {
                got = SymbolFlags::Elf { st_info, st_other };
                assert_tokens(
                    &got,
                    &[
                        Token::StructVariant {
                            name: "SymbolFlags",
                            variant: "Elf",
                            len: 2,
                        },
                        Token::Str("st_info"),
                        Token::U8(st_info),
                        Token::Str("st_other"),
                        Token::U8(st_other),
                        Token::StructVariantEnd,
                    ],
                );
            }
        }

        for n_desc in 0..=u16::MAX {
            got = SymbolFlags::MachO { n_desc };
            assert_tokens(
                &got,
                &[
                    Token::StructVariant {
                        name: "SymbolFlags",
                        variant: "MachO",
                        len: 1,
                    },
                    Token::Str("n_desc"),
                    Token::U16(n_desc),
                    Token::StructVariantEnd,
                ],
            );
        }

        for selection in 0..=u8::MAX {
            for associative_section in 0..=(u8::MAX as _) {
                got = SymbolFlags::<u16, u16>::CoffSection {
                    selection,
                    associative_section: Some(associative_section),
                };
                assert_tokens(
                    &got,
                    &[
                        Token::StructVariant {
                            name: "SymbolFlags",
                            variant: "CoffSection",
                            len: 2,
                        },
                        Token::Str("selection"),
                        Token::U8(selection),
                        Token::Str("associative_section"),
                        Token::Some,
                        Token::U16(associative_section),
                        Token::StructVariantEnd,
                    ],
                );

                got = SymbolFlags::<u16, u16>::CoffSection {
                    selection,
                    associative_section: None,
                };
                assert_tokens(
                    &got,
                    &[
                        Token::StructVariant {
                            name: "SymbolFlags",
                            variant: "CoffSection",
                            len: 2,
                        },
                        Token::Str("selection"),
                        Token::U8(selection),
                        Token::Str("associative_section"),
                        Token::None,
                        Token::StructVariantEnd,
                    ],
                );
            }
        }

        for n_sclass in 0..=50 {
            for x_smtyp in 0..=50 {
                for x_smclas in 0..=50 {
                    let containing_csect = (n_sclass + x_smclas) as _;
                    got = SymbolFlags::<u16, u16>::Xcoff {
                        n_sclass,
                        x_smtyp,
                        x_smclas,
                        containing_csect: Some(containing_csect),
                    };
                    assert_tokens(
                        &got,
                        &[
                            Token::StructVariant {
                                name: "SymbolFlags",
                                variant: "Xcoff",
                                len: 4,
                            },
                            Token::Str("n_sclass"),
                            Token::U8(n_sclass),
                            Token::Str("x_smtyp"),
                            Token::U8(x_smtyp),
                            Token::Str("x_smclas"),
                            Token::U8(x_smclas),
                            Token::Str("containing_csect"),
                            Token::Some,
                            Token::U16(containing_csect),
                            Token::StructVariantEnd,
                        ],
                    );
                    got = SymbolFlags::<u16, u16>::Xcoff {
                        n_sclass,
                        x_smtyp,
                        x_smclas,
                        containing_csect: None,
                    };
                    assert_tokens(
                        &got,
                        &[
                            Token::StructVariant {
                                name: "SymbolFlags",
                                variant: "Xcoff",
                                len: 4,
                            },
                            Token::Str("n_sclass"),
                            Token::U8(n_sclass),
                            Token::Str("x_smtyp"),
                            Token::U8(x_smtyp),
                            Token::Str("x_smclas"),
                            Token::U8(x_smclas),
                            Token::Str("containing_csect"),
                            Token::None,
                            Token::StructVariantEnd,
                        ],
                    );
                }
            }
        }
    }

    #[test]
    fn relocation_flags() {
        let mut got;
        let kinds = [
            (RelocationKind::Unknown, "Unknown"),
            (RelocationKind::Absolute, "Absolute"),
            (RelocationKind::Relative, "Relative"),
            (RelocationKind::Got, "Got"),
            (RelocationKind::GotRelative, "GotRelative"),
            (RelocationKind::GotBaseRelative, "GotBaseRelative"),
            (RelocationKind::GotBaseOffset, "GotBaseOffset"),
            (RelocationKind::PltRelative, "PltRelative"),
            (RelocationKind::ImageOffset, "ImageOffset"),
            (RelocationKind::SectionOffset, "SectionOffset"),
            (RelocationKind::SectionIndex, "SectionIndex"),
        ];

        let encodings = [
            (RelocationEncoding::Unknown, "Unknown"),
            (RelocationEncoding::Generic, "Generic"),
            (RelocationEncoding::X86Signed, "X86Signed"),
            (RelocationEncoding::X86RipRelative, "X86RipRelative"),
            (RelocationEncoding::X86RipRelativeMovq, "X86RipRelativeMovq"),
            (RelocationEncoding::X86Branch, "X86Branch"),
            (RelocationEncoding::S390xDbl, "S390xDbl"),
            (RelocationEncoding::AArch64Call, "AArch64Call"),
            (RelocationEncoding::LoongArchBranch, "LoongArchBranch"),
            (RelocationEncoding::SharcTypeA, "SharcTypeA"),
            (RelocationEncoding::SharcTypeB, "SharcTypeB"),
            (RelocationEncoding::E2KLit, "E2KLit"),
            (RelocationEncoding::E2KDisp, "E2KDisp"),
        ];

        for (kind, kind_variant) in kinds {
            for (encoding, encoding_variant) in encodings {
                for size in 0..=u8::MAX {
                    got = RelocationFlags::Generic {
                        kind,
                        encoding,
                        size,
                    };
                    assert_tokens(
                        &got,
                        &[
                            Token::StructVariant {
                                name: "RelocationFlags",
                                variant: "Generic",
                                len: 3,
                            },
                            Token::Str("kind"),
                            Token::UnitVariant {
                                name: "RelocationKind",
                                variant: kind_variant,
                            },
                            Token::Str("encoding"),
                            Token::UnitVariant {
                                name: "RelocationEncoding",
                                variant: encoding_variant,
                            },
                            Token::Str("size"),
                            Token::U8(size),
                            Token::StructVariantEnd,
                        ],
                    );
                }
            }
        }

        for r_type in 0..=1_000_000 {
            got = RelocationFlags::Elf { r_type };
            assert_tokens(
                &got,
                &[
                    Token::StructVariant {
                        name: "RelocationFlags",
                        variant: "Elf",
                        len: 1,
                    },
                    Token::Str("r_type"),
                    Token::U32(r_type),
                    Token::StructVariantEnd,
                ],
            );
        }

        for r_type in 0..=u8::MAX {
            for r_length in 0..=u8::MAX {
                got = RelocationFlags::MachO {
                    r_type,
                    r_pcrel: true,
                    r_length,
                };
                assert_tokens(
                    &got,
                    &[
                        Token::StructVariant {
                            name: "RelocationFlags",
                            variant: "MachO",
                            len: 3,
                        },
                        Token::Str("r_type"),
                        Token::U8(r_type),
                        Token::Str("r_pcrel"),
                        Token::Bool(true),
                        Token::Str("r_length"),
                        Token::U8(r_length),
                        Token::StructVariantEnd,
                    ],
                );
                got = RelocationFlags::MachO {
                    r_type,
                    r_pcrel: false,
                    r_length,
                };
                assert_tokens(
                    &got,
                    &[
                        Token::StructVariant {
                            name: "RelocationFlags",
                            variant: "MachO",
                            len: 3,
                        },
                        Token::Str("r_type"),
                        Token::U8(r_type),
                        Token::Str("r_pcrel"),
                        Token::Bool(false),
                        Token::Str("r_length"),
                        Token::U8(r_length),
                        Token::StructVariantEnd,
                    ],
                );
            }
        }

        for typ in 0..=u16::MAX {
            got = RelocationFlags::Coff { typ };
            assert_tokens(
                &got,
                &[
                    Token::StructVariant {
                        name: "RelocationFlags",
                        variant: "Coff",
                        len: 1,
                    },
                    Token::Str("typ"),
                    Token::U16(typ),
                    Token::StructVariantEnd,
                ],
            );
        }

        for r_rtype in 0..=50 {
            for r_rsize in 0..=50 {
                got = RelocationFlags::Xcoff { r_rtype, r_rsize };
                assert_tokens(
                    &got,
                    &[
                        Token::StructVariant {
                            name: "RelocationFlags",
                            variant: "Xcoff",
                            len: 2,
                        },
                        Token::Str("r_rtype"),
                        Token::U8(r_rtype),
                        Token::Str("r_rsize"),
                        Token::U8(r_rsize),
                        Token::StructVariantEnd,
                    ],
                );
            }
        }
    }
}
