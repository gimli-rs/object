#![cfg(feature = "read")]

use object_examples::{objdump, readobj};
use std::ffi::OsStr;
use std::io::Write;
use std::path::PathBuf;
use std::{env, fs};

const DISABLED_TEST_DIRS: &[&'static str] = &[
    #[cfg(not(feature = "wasm"))]
    "wasm",
    #[cfg(not(feature = "xcoff"))]
    "xcoff",
];

fn test_dir_filter(path: &PathBuf) -> bool {
    match path.file_name().and_then(OsStr::to_str) {
        Some(dir) => !DISABLED_TEST_DIRS.contains(&dir),
        None => true,
    }
}

#[test]
fn testfiles() {
    // Move from crates/examples to the workspace root.
    env::set_current_dir("../..").unwrap();

    let mut fail = false;
    for dir in glob::glob("testfiles/*")
        .unwrap()
        .filter_map(Result::ok)
        .filter(test_dir_filter)
    {
        let dir = dir.to_str().unwrap();
        for path in glob::glob(&format!("{}/*", dir))
            .unwrap()
            .filter_map(Result::ok)
        {
            let path = path.to_str().unwrap();
            if glob::glob(&format!("crates/examples/{}.*", path))
                .unwrap()
                .find_map(Result::ok)
                .is_none()
            {
                continue;
            }

            println!("File {}", path);
            let data = fs::read(&path).unwrap();
            fail |= testfile(path, &data, "objdump", |mut out, mut err, data| {
                objdump::print(&mut out, &mut err, data, &[], vec![]).unwrap()
            });
            fail |= testfile(path, &data, "readobj", readobj::print);
            println!();
        }
    }
    assert!(!fail);
}

fn testfile<F>(path: &str, data: &[u8], ext: &str, f: F) -> bool
where
    F: FnOnce(&mut dyn Write, &mut dyn Write, &[u8]),
{
    if glob::glob(&format!("crates/examples/{}.{}*", path, ext))
        .unwrap()
        .find_map(Result::ok)
        .is_none()
    {
        return false;
    }

    // TODO: print diffs for mismatches
    let mut fail = false;
    let mut out = Vec::new();
    let mut err = Vec::new();
    f(&mut out, &mut err, data);

    // Check exact match of output.
    let out_path = &format!("crates/examples/{}.{}", path, ext);
    if let Ok(expect_out) = fs::read(out_path) {
        println!("Test {}", out_path);
        if out != expect_out {
            println!("FAIL mismatch");
            fail = true;
        }
    }

    // Check partial match of output.
    for out_path in glob::glob(&format!("crates/examples/{}.{}.*", path, ext))
        .unwrap()
        .filter_map(Result::ok)
    {
        println!("Test {}", out_path.to_str().unwrap());
        let expect_out = fs::read(&out_path).unwrap();
        if !find_subslice(&out, &expect_out) {
            println!("FAIL not found");
            fail = true;
        }
    }

    // Check exact match of errors.
    let err_path = &format!("{}.err", out_path);
    if let Ok(expect_err) = fs::read(err_path) {
        println!("Test {}", err_path);
        if err != expect_err {
            println!("FAIL mismatch");
            fail = true;
        }
    } else if !err.is_empty() {
        println!("FAIL unexpected stderr");
        fail = true;
    }

    fail
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
