#![cfg(feature = "read")]

#[cfg(feature = "write")]
use object_examples::objcopy;
use object_examples::{objdump, readobj};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::{env, fs};

const DISABLED_TEST_DIRS: &[&str] = &[
    #[cfg(not(feature = "wasm"))]
    "wasm",
    #[cfg(not(feature = "xcoff"))]
    "xcoff",
];

fn test_dir_enabled(path: &Path) -> bool {
    match path.file_name().and_then(OsStr::to_str) {
        Some(dir) => !DISABLED_TEST_DIRS.contains(&dir),
        None => true,
    }
}

#[test]
fn testfiles() {
    let in_testfiles = PathBuf::from("../..");
    let out_testfiles = PathBuf::from("testfiles");

    let mut fail = false;
    let mut dirs = vec![out_testfiles];
    while let Some(dir) = dirs.pop() {
        for entry in dir.read_dir().unwrap() {
            let entry = entry.unwrap();
            let out_path = entry.path();
            let file_type = entry.file_type().unwrap();
            if file_type.is_dir() {
                if test_dir_enabled(&out_path) {
                    dirs.push(out_path);
                }
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let extension = out_path.extension().unwrap().to_str().unwrap();

            let mut in_path = in_testfiles.join(&out_path);
            in_path.set_extension("");

            if extension == "err" {
                continue;
            }
            // TODO: use err_path.as_mut_os_string().push(".err") when MSRV is >= 1.70.
            let mut err_path = out_path.clone().into_os_string();
            err_path.push(".err");
            let err_path = PathBuf::from(err_path);
            let err_path = if err_path.is_file() {
                Some(&*err_path)
            } else {
                None
            };

            if extension == "objdump" {
                fail |= testfile(&in_path, &out_path, err_path, |out, err, data| {
                    objdump::print(out, err, data, &[], vec![]).unwrap();
                });
            } else if extension == "objdump-shndx" {
                // Special case for the large symtab shndx test.
                fail |= testfile(&in_path, &out_path, err_path, |out, err, data| {
                    objdump::print(out, err, data, &[], vec![]).unwrap();
                    *out = filter_lines(&*out, |line| {
                        line.starts_with("6553") && line[5..].starts_with(": Symbol {")
                    });
                });
            } else if extension == "objdump-comdat" {
                fail |= testfile(&in_path, &out_path, err_path, |out, err, data| {
                    objdump::print(out, err, data, &[], vec![]).unwrap();
                    *out = filter_lines(&*out, |line| line.starts_with("Comdat "));
                });
            } else if extension.starts_with("readobj") {
                let options = match extension {
                    "readobj" => readobj::PrintOptions {
                        pe_base_relocs: false, // Too many
                        ..readobj::PrintOptions::all()
                    },
                    "readobj-section" => readobj::PrintOptions {
                        sections: true,
                        ..readobj::PrintOptions::none()
                    },
                    "readobj-elf-note" => readobj::PrintOptions {
                        elf_notes: true,
                        ..readobj::PrintOptions::none()
                    },
                    "readobj-pe-base-reloc" => readobj::PrintOptions {
                        pe_base_relocs: true,
                        ..readobj::PrintOptions::none()
                    },
                    "readobj-pe-resource" => readobj::PrintOptions {
                        pe_resources: true,
                        ..readobj::PrintOptions::none()
                    },
                    _ => {
                        println!("Unknown test {}", out_path.display());
                        fail = true;
                        continue;
                    }
                };
                fail |= testfile(&in_path, &out_path, err_path, |out, err, data| {
                    readobj::print(out, err, data, &options);
                });
            } else if extension == "objcopy" {
                #[cfg(feature = "write")]
                {
                    fail |= testfile(&in_path, &out_path, err_path, |out, err, in_data| {
                        let copy_data = objcopy::copy(in_data);
                        readobj::print(out, err, &copy_data, &readobj::PrintOptions::all());
                    });
                }
            } else {
                println!("Unknown test {}", out_path.display());
                fail = true;
            }
        }
    }
    if fail {
        panic!("Tests failed; rerun with OBJECT_TESTFILES_UPDATE=1 to update tests");
    }
}

fn testfile<F>(in_path: &Path, out_path: &Path, err_path: Option<&Path>, f: F) -> bool
where
    F: FnOnce(&mut Vec<u8>, &mut Vec<u8>, &[u8]),
{
    println!("Test {}", out_path.display());
    let in_data = match fs::read(in_path) {
        Ok(in_data) => in_data,
        Err(err) => {
            println!("FAIL Couldn't read {}: {}", in_path.display(), err);
            return true;
        }
    };

    let mut out_data = Vec::new();
    let mut err_data = Vec::new();
    f(&mut out_data, &mut err_data, &in_data);

    let update = env::var_os("OBJECT_TESTFILES_UPDATE").is_some();
    let mut fail = false;

    // Check exact match of output.
    if update {
        fs::write(out_path, &out_data).unwrap();
    } else {
        let expect_out_data = fs::read(out_path).unwrap();
        if out_data != expect_out_data {
            println!("FAIL mismatch");
            fail = true;
        }
    }

    // Check exact match of errors.
    if let Some(err_path) = err_path {
        if update {
            fs::write(err_path, &err_data).unwrap();
        } else {
            let expect_err_data = fs::read(err_path).unwrap();
            if err_data != expect_err_data {
                println!("FAIL mismatch");
                fail = true;
            }
        }
    } else if !err_data.is_empty() {
        println!("FAIL unexpected stderr");
        fail = true;
    }

    fail
}

fn filter_lines<F>(data: &[u8], mut f: F) -> Vec<u8>
where
    F: FnMut(&str) -> bool,
{
    let mut result = Vec::new();
    for line in data.split(|&b| b == b'\n') {
        if f(std::str::from_utf8(line).unwrap()) {
            result.extend_from_slice(line);
            result.push(b'\n');
        }
    }
    result
}
