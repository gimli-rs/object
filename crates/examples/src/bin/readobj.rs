//! Example that uses the lower level read API.

use clap::{Arg, ArgAction, Command};
use object_examples::readobj;
use std::path::PathBuf;
use std::{fs, io};

fn main() {
    let matches = Command::new("readobj")
        .arg(
            Arg::new("file")
                .action(ArgAction::Append)
                .required(true)
                .value_parser(clap::value_parser!(PathBuf))
                .help("The file to read"),
        )
        .arg(
            Arg::new("file-header")
                .long("file-header")
                .action(ArgAction::SetTrue)
                .help("Print the file header"),
        )
        .arg(
            Arg::new("segments")
                .long("segments")
                .action(ArgAction::SetTrue)
                .help("Print the segments"),
        )
        .arg(
            Arg::new("sections")
                .long("sections")
                .action(ArgAction::SetTrue)
                .help("Print the sections"),
        )
        .arg(
            Arg::new("symbols")
                .long("symbols")
                .action(ArgAction::SetTrue)
                .help("Print the symbols"),
        )
        .arg(
            Arg::new("relocations")
                .long("relocations")
                .action(ArgAction::SetTrue)
                .help("Print the relocations"),
        )
        .arg(
            Arg::new("elf-dynamic")
                .long("elf-dynamic")
                .action(ArgAction::SetTrue)
                .help("Print the ELF dynamic section"),
        )
        .arg(
            Arg::new("elf-dynamic-symbols")
                .long("elf-dynamic-symbols")
                .action(ArgAction::SetTrue)
                .help("Print the dynamic symbols"),
        )
        .arg(
            Arg::new("elf-notes")
                .long("elf-notes")
                .action(ArgAction::SetTrue)
                .help("Print the ELF notes"),
        )
        .arg(
            Arg::new("elf-version-info")
                .long("elf-version-info")
                .action(ArgAction::SetTrue)
                .help("Print the ELF version info sections"),
        )
        .arg(
            Arg::new("elf-attributes")
                .long("elf-attributes")
                .action(ArgAction::SetTrue)
                .help("Print the ELF attribute sections"),
        )
        .arg(
            Arg::new("macho-load-commands")
                .long("macho-load-commands")
                .action(ArgAction::SetTrue)
                .help("Print the Mach-O load commands"),
        )
        .arg(
            Arg::new("pe-rich")
                .long("pe-rich")
                .action(ArgAction::SetTrue)
                .help("Print the PE rich header"),
        )
        .arg(
            Arg::new("pe-base-relocs")
                .long("pe-base-relocs")
                .action(ArgAction::SetTrue)
                .help("Print the PE base relocations"),
        )
        .arg(
            Arg::new("pe-imports")
                .long("pe-imports")
                .action(ArgAction::SetTrue)
                .help("Print the PE imports"),
        )
        .arg(
            Arg::new("pe-exports")
                .long("pe-exports")
                .action(ArgAction::SetTrue)
                .help("Print the PE exports"),
        )
        .arg(
            Arg::new("pe-resources")
                .long("pe-resources")
                .action(ArgAction::SetTrue)
                .help("Print the PE resource directory"),
        )
        .arg(
            Arg::new("no-string-indices")
                .long("no-string-indices")
                .action(ArgAction::SetTrue)
                .help("Don't print string table indices"),
        )
        .get_matches();
    let mut options = readobj::PrintOptions {
        file: matches.get_flag("file-header"),
        segments: matches.get_flag("segments"),
        sections: matches.get_flag("sections"),
        symbols: matches.get_flag("symbols"),
        relocations: matches.get_flag("relocations"),
        elf_dynamic: matches.get_flag("elf-dynamic"),
        elf_dynamic_symbols: matches.get_flag("elf-dynamic-symbols"),
        elf_notes: matches.get_flag("elf-notes"),
        elf_versions: matches.get_flag("elf-version-info"),
        elf_attributes: matches.get_flag("elf-attributes"),
        macho_load_commands: matches.get_flag("macho-load-commands"),
        pe_rich: matches.get_flag("pe-rich"),
        pe_base_relocs: matches.get_flag("pe-base-relocs"),
        pe_imports: matches.get_flag("pe-imports"),
        pe_exports: matches.get_flag("pe-exports"),
        pe_resources: matches.get_flag("pe-resources"),
        ..readobj::PrintOptions::none()
    };
    if options == readobj::PrintOptions::none() {
        options = readobj::PrintOptions::all();
    }
    options.string_indices = !matches.get_flag("no-string-indices");

    let file_paths = matches.get_many::<PathBuf>("file").unwrap();
    let file_count = file_paths.len();
    for file_path in file_paths {
        if file_count > 1 {
            println!();
            println!("{}:", file_path.display());
        }

        let file = match fs::File::open(file_path) {
            Ok(file) => file,
            Err(err) => {
                println!("Failed to open file '{}': {}", file_path.display(), err);
                continue;
            }
        };
        let file = match unsafe { memmap2::Mmap::map(&file) } {
            Ok(mmap) => mmap,
            Err(err) => {
                println!("Failed to map file '{}': {}", file_path.display(), err);
                continue;
            }
        };

        let stdout = io::stdout();
        let stderr = io::stderr();
        readobj::print(&mut stdout.lock(), &mut stderr.lock(), &file, &options);
    }
}
