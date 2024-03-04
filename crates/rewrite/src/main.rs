use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{command, Arg, ArgAction, ArgGroup};
use object_rewrite as rewrite;

fn main() -> Result<()> {
    let matches = command!()
        .max_term_width(100)
        .args(&[
            Arg::new("input")
                .required(true)
                .value_parser(clap::value_parser!(PathBuf))
                .help("The input file"),
            // TODO: make output optional, and overwrite input file by default
            Arg::new("output")
                .required(false)
                .value_parser(clap::value_parser!(PathBuf))
                .help("The output file. Required if any modification is requested"),
            Arg::new("delete-symbol")
                .long("delete-symbol")
                .value_name("symbol")
                .value_parser(clap::value_parser!(String))
                .action(ArgAction::Append)
                .help("Delete the named symbol"),
            Arg::new("rename-symbol")
                .long("rename-symbol")
                .value_name("old=new")
                .value_parser(clap::value_parser!(String))
                .action(ArgAction::Append)
                .help("Change the name of a symbol from <old> to <new>"),
            Arg::new("rename-symbols")
                .long("rename-symbols")
                .value_name("file")
                .value_parser(clap::value_parser!(PathBuf))
                .action(ArgAction::Append)
                .help(
                    "Read a list of symbol names from <file> and apply --rename-symbol for each. \
                    Each line contains two symbols separated by whitespace.",
                ),
            Arg::new("delete-section")
                .long("delete-section")
                .value_name("section")
                .value_parser(clap::value_parser!(String))
                .action(ArgAction::Append)
                .help("Delete the named section"),
            Arg::new("rename-section")
                .long("rename-section")
                .value_name("old=new")
                .value_parser(clap::value_parser!(String))
                .action(ArgAction::Append)
                .help("Change the name of a section from <old> to <new>"),
            Arg::new("elf-add-dynamic-debug")
                .long("elf-add-dynamic-debug")
                .action(ArgAction::SetTrue)
                .help("Add a DT_DEBUG entry to the dynamic section"),
            Arg::new("elf-print-runpath")
                .long("elf-print-runpath")
                .action(ArgAction::SetTrue)
                .help("Print any DT_RPATH or DT_RUNPATH entries in the dynamic section"),
            Arg::new("elf-delete-runpath")
                .long("elf-delete-runpath")
                .action(ArgAction::SetTrue)
                .help("Delete any DT_RPATH and DT_RUNPATH entries in the dynamic section"),
            Arg::new("elf-set-runpath")
                .long("elf-set-runpath")
                .value_name("path")
                .value_parser(clap::value_parser!(String))
                .help("Set the path for any DT_RPATH or DT_RUNPATH entry in the dynamic section"),
            Arg::new("elf-add-runpath")
                .long("elf-add-runpath")
                .value_name("path")
                .value_parser(clap::value_parser!(String))
                .action(ArgAction::Append)
                .help("Add a path to any DT_RPATH or DT_RUNPATH entry in the dynamic section"),
            Arg::new("elf-use-rpath")
                .long("elf-use-rpath")
                .action(ArgAction::SetTrue)
                .help("Change any DT_RUNPATH entry in the dynamic section to DT_RPATH"),
            Arg::new("elf-use-runpath")
                .long("elf-use-runpath")
                .action(ArgAction::SetTrue)
                .help("Change any DT_RPATH entry in the dynamic section to DT_RUNPATH"),
            Arg::new("elf-print-needed")
                .long("elf-print-needed")
                .action(ArgAction::SetTrue)
                .help("Print the DT_NEEDED entries in the dynamic section"),
            Arg::new("elf-delete-needed")
                .long("elf-delete-needed")
                .value_name("name")
                .value_parser(clap::value_parser!(String))
                .action(ArgAction::Append)
                .help("Delete the named DT_NEEDED entry in the dynamic section"),
            Arg::new("elf-replace-needed")
                .long("elf-replace-needed")
                .value_name("old=new")
                .value_parser(clap::value_parser!(String))
                .action(ArgAction::Append)
                .help("Change the value of a DT_NEEDED entry from <old> to <new>"),
            Arg::new("elf-add-needed")
                .long("elf-add-needed")
                .value_name("name")
                .value_parser(clap::value_parser!(String))
                .action(ArgAction::Append)
                .help("Add a DT_NEEDED entry to the start of the dynamic section"),
            Arg::new("elf-print-soname")
                .long("elf-print-soname")
                .action(ArgAction::SetTrue)
                .help("Print the DT_SONAME entry in the dynamic section"),
            Arg::new("elf-set-soname")
                .long("elf-set-soname")
                .value_name("name")
                .value_parser(clap::value_parser!(String))
                .help("Set the DT_SONAME entry in the dynamic section"),
            Arg::new("elf-print-interpreter")
                .long("elf-print-interpreter")
                .action(ArgAction::SetTrue)
                .help("Print the interpreter path in the PT_INTERP segment"),
            Arg::new("elf-set-interpreter")
                .long("elf-set-interpreter")
                .value_name("path")
                .value_parser(clap::value_parser!(String))
                .help("Set the interpreter path in the PT_INTERP segment"),
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue)
                .help("Enable verbose output"),
        ])
        .group(
            ArgGroup::new("output-flags")
                .args([
                    "delete-symbol",
                    "rename-symbol",
                    "rename-symbols",
                    "delete-section",
                    "rename-section",
                    "elf-add-dynamic-debug",
                    "elf-delete-runpath",
                    "elf-set-runpath",
                    "elf-add-runpath",
                    "elf-use-rpath",
                    "elf-use-runpath",
                    "elf-delete-needed",
                    "elf-replace-needed",
                    "elf-add-needed",
                    "elf-set-soname",
                    "elf-set-interpreter",
                ])
                .multiple(true)
                .required(false)
                .requires("output"),
        )
        .get_matches();

    if matches.get_flag("verbose") {
        env_logger::builder()
            .format_level(false)
            .format_target(false)
            .filter_module("object_rewrite", log::LevelFilter::Debug)
            .init();
    }

    // TODO: allow - for stdin
    let in_path = matches.get_one::<PathBuf>("input").unwrap();

    let in_file = fs::File::open(in_path)
        .with_context(|| format!("Failed to open input file '{}'", in_path.display()))?;
    let in_data = unsafe { memmap2::Mmap::map(&in_file) }
        .with_context(|| format!("Failed to map input file '{}'", in_path.display()))?;
    let in_data = &*in_data;
    let mut rewriter = rewrite::Rewriter::read(in_data)
        .with_context(|| format!("Failed to parse input file '{}'", in_path.display()))?;

    if matches.get_flag("elf-print-runpath") {
        if let Some(runpath) = rewriter.elf_runpath() {
            println!("{}", String::from_utf8_lossy(runpath));
        }
    }
    if matches.get_flag("elf-print-needed") {
        for needed in rewriter.elf_needed() {
            println!("{}", String::from_utf8_lossy(needed));
        }
    }
    if matches.get_flag("elf-print-soname") {
        if let Some(soname) = rewriter.elf_soname() {
            println!("{}", String::from_utf8_lossy(soname));
        }
    }
    if matches.get_flag("elf-print-interpreter") {
        if let Some(interp) = rewriter.elf_interpreter() {
            println!("{}", String::from_utf8_lossy(interp));
        }
    }

    // TODO: allow replacing input file
    let Some(out_path) = matches.get_one::<PathBuf>("output") else {
        return Ok(());
    };

    let mut options = rewrite::Options::default();

    options.delete_symbols = matches
        .get_many::<String>("delete-symbol")
        .unwrap_or_default()
        .map(|arg| arg.clone().into_bytes())
        .collect();
    for arg in matches
        .get_many::<String>("rename-symbol")
        .unwrap_or_default()
    {
        let names: Vec<&[u8]> = arg.as_bytes().splitn(2, |byte| *byte == b'=').collect();
        if names.len() != 2 {
            return Err(
                anyhow!("Invalid rename symbol: `{}`. --rename-symbol expects argument of the form: <old>=<new>", arg)
            );
        }
        options
            .rename_symbols
            .insert(names[0].to_vec(), names[1].to_vec());
    }
    for filename in matches
        .get_many::<PathBuf>("rename-symbols")
        .unwrap_or_default()
    {
        let file = fs::File::open(filename).with_context(|| {
            format!("Failed to open rename symbol file '{}'", filename.display())
        })?;
        let mut buf = io::BufReader::new(file);
        let mut line = Vec::new();
        while buf.read_until(b'\n', &mut line)? != 0 {
            if line.ends_with(&[b'\n']) {
                line.pop();
                if line.ends_with(&[b'\r']) {
                    line.pop();
                }
            }
            let names: Vec<&[u8]> = line.splitn(2, |byte| *byte == b' ').collect();
            if names.len() != 2 {
                return Err(
                    anyhow!(
                    "Invalid rename symbol file entry: `{}`. --rename-symbols expects lines  of the form: <old> <new>", String::from_utf8_lossy(&line))
                );
            }
            options
                .rename_symbols
                .insert(names[0].to_vec(), names[1].to_vec());
            line.clear();
        }
    }
    options.delete_sections = matches
        .get_many::<String>("delete-section")
        .unwrap_or_default()
        .map(|arg| arg.clone().into_bytes())
        .collect();
    for arg in matches
        .get_many::<String>("rename-section")
        .unwrap_or_default()
    {
        let names: Vec<&[u8]> = arg.as_bytes().splitn(2, |byte| *byte == b'=').collect();
        if names.len() != 2 {
            return Err(
                anyhow!(
                "Invalid rename section: `{}`. --rename-section expects argument  of the form: <old>=<new>", arg)
            );
        }
        options
            .rename_sections
            .insert(names[0].to_vec(), names[1].to_vec());
    }
    options.elf.add_dynamic_debug = matches.get_flag("elf-add-dynamic-debug");
    options.elf.delete_runpath = matches.get_flag("elf-delete-runpath");
    options.elf.set_runpath = matches
        .get_one::<String>("elf-set-runpath")
        .map(|arg| arg.clone().into_bytes());
    options.elf.add_runpath = matches
        .get_many::<String>("elf-add-runpath")
        .unwrap_or_default()
        .map(|arg| arg.clone().into_bytes())
        .collect();
    options.elf.use_rpath = matches.get_flag("elf-use-rpath");
    options.elf.use_runpath = matches.get_flag("elf-use-runpath");
    options.elf.delete_needed = matches
        .get_many::<String>("elf-delete-needed")
        .unwrap_or_default()
        .map(|arg| arg.clone().into_bytes())
        .collect();
    for arg in matches
        .get_many::<String>("elf-replace-needed")
        .unwrap_or_default()
    {
        let names: Vec<&[u8]> = arg.as_bytes().splitn(2, |byte| *byte == b'=').collect();
        if names.len() != 2 {
            return Err(
                anyhow!(
                "Invalid replace needed: `{}`. --elf-replace-needed expects argument of the form: <old>=<new>", arg)
            );
        }
        options
            .elf
            .replace_needed
            .insert(names[0].to_vec(), names[1].to_vec());
    }
    options.elf.add_needed = matches
        .get_many::<String>("elf-add-needed")
        .unwrap_or_default()
        .map(|arg| arg.clone().into_bytes())
        .collect();
    options.elf.set_soname = matches
        .get_one::<String>("elf-set-soname")
        .map(|arg| arg.clone().into_bytes());
    options.elf.set_interpreter = matches
        .get_one::<String>("elf-set-interpreter")
        .map(|arg| arg.clone().into_bytes());

    rewriter.modify(options)?;

    if out_path == Path::new("-") {
        rewriter
            .write(io::stdout().lock())
            .with_context(|| "Failed to write output to stdout")?;
        return Ok(());
    }

    let mut open_options = fs::OpenOptions::new();
    open_options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::OpenOptionsExt;
        let in_metadata = in_file.metadata().with_context(|| {
            format!(
                "Failed to read metadata of input file '{}'",
                in_path.display()
            )
        })?;
        open_options.mode(in_metadata.mode());
    }
    let out_file = open_options
        .open(out_path)
        .with_context(|| format!("Failed to create output file '{}'", out_path.display()))?;
    let out_metadata = out_file.metadata();
    rewriter.write(out_file).with_context(|| {
        if let Ok(out_metadata) = out_metadata {
            if out_metadata.is_file() {
                // This is a regular file that we either created or truncated,
                // so we can safely remove it.
                fs::remove_file(out_path).ok();
            }
        }
        format!("Failed to write output file '{}'", out_path.display())
    })?;
    Ok(())
}
