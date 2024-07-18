use object_examples::readobj;
use std::path::Path;
use std::{env, fs};

fn fail_message(fail: bool) {
    if fail {
        panic!("Tests failed; run `cargo xtask test-update` and check the diff");
    }
}

#[test]
fn rewrite_base() {
    let print_options = readobj::PrintOptions {
        string_indices: false,
        ..readobj::PrintOptions::all()
    };
    let mut fail = false;

    let options = object_rewrite::Options::default();
    fail |= testfile("elf/base", "elf/base.noop", options, &print_options);

    fail_message(fail);
}

#[test]
fn rewrite_base_version() {
    let print_options = readobj::PrintOptions {
        string_indices: false,
        ..readobj::PrintOptions::all()
    };
    let mut fail = false;

    let options = object_rewrite::Options::default();
    fail |= testfile(
        "elf/libbase.so",
        "elf/libbase.so.noop",
        options,
        &print_options,
    );

    fail_message(fail);
}

#[test]
fn rewrite_symbols() {
    let print_options = readobj::PrintOptions {
        string_indices: false,
        segments: true,
        sections: true,
        symbols: true,
        elf_dynamic_symbols: true,
        ..readobj::PrintOptions::none()
    };
    let mut fail = false;

    let mut options = object_rewrite::Options::default();
    options.delete_symbols.insert(b"printf".to_vec());
    fail |= testfile(
        "elf/base",
        "elf/base.delete-symbol",
        options,
        &print_options,
    );

    let mut options = object_rewrite::Options::default();
    options
        .rename_symbols
        .insert(b"printf".to_vec(), b"printf_renamed".to_vec());
    fail |= testfile(
        "elf/base",
        "elf/base.rename-symbol",
        options,
        &print_options,
    );

    fail_message(fail);
}

#[test]
fn rewrite_sections() {
    let print_options = readobj::PrintOptions {
        string_indices: false,
        segments: true,
        sections: true,
        elf_dynamic: true,
        ..readobj::PrintOptions::none()
    };
    let mut fail = false;

    let mut options = object_rewrite::Options::default();
    // Tests that we delete the corresponding dynamic entry.
    options.delete_sections.insert(b".gnu.hash".to_vec());
    // Tests that we delete the resulting empty segment.
    options.delete_sections.insert(b".eh_frame_hdr".to_vec());
    options.delete_sections.insert(b".eh_frame".to_vec());
    fail |= testfile(
        "elf/base",
        "elf/base.delete-section",
        options,
        &print_options,
    );

    let mut options = object_rewrite::Options::default();
    options
        .rename_sections
        .insert(b".comment".to_vec(), b".comment_renamed".to_vec());
    fail |= testfile(
        "elf/base",
        "elf/base.rename-section",
        options,
        &print_options,
    );

    fail_message(fail);
}

#[test]
fn rewrite_runpath() {
    let print_options = readobj::PrintOptions {
        string_indices: false,
        segments: true,
        sections: true,
        elf_dynamic: true,
        ..readobj::PrintOptions::none()
    };
    let mut fail = false;

    // Needed a file that has a runpath to test this.
    //let mut options = object_rewrite::Options::default();
    //options.elf.delete_runpath = true;
    //fail |= testfile("elf/base", "elf/base.delete-runpath", options, &print_options);

    let mut options = object_rewrite::Options::default();
    options.elf.set_runpath = Some(b"/foo:/bar".to_vec());
    fail |= testfile("elf/base", "elf/base.set-runpath", options, &print_options);

    let mut options = object_rewrite::Options::default();
    options.elf.add_runpath = vec![b"/foo".to_vec(), b"/bar".to_vec()];
    fail |= testfile("elf/base", "elf/base.add-runpath", options, &print_options);

    let mut options = object_rewrite::Options::default();
    options.elf.add_runpath = vec![b"/foo".to_vec(), b"/bar".to_vec()];
    options.elf.use_rpath = true;
    fail |= testfile("elf/base", "elf/base.add-rpath", options, &print_options);

    fail_message(fail);
}

#[test]
fn rewrite_needed() {
    let print_options = readobj::PrintOptions {
        string_indices: false,
        segments: true,
        sections: true,
        elf_dynamic: true,
        ..readobj::PrintOptions::none()
    };
    let mut fail = false;

    let mut options = object_rewrite::Options::default();
    options.elf.delete_needed.insert(b"libc.so.6".to_vec());
    fail |= testfile(
        "elf/base",
        "elf/base.delete-needed",
        options,
        &print_options,
    );

    let mut options = object_rewrite::Options::default();
    options
        .elf
        .replace_needed
        .insert(b"libc.so.6".to_vec(), b"libc_renamed.so.6".to_vec());
    fail |= testfile(
        "elf/base",
        "elf/base.replace-needed",
        options,
        &print_options,
    );

    let mut options = object_rewrite::Options::default();
    options.elf.add_needed = vec![b"libfoo.so.1".to_vec(), b"libbar.so.2".to_vec()];
    fail |= testfile("elf/base", "elf/base.add-needed", options, &print_options);

    fail_message(fail);
}

#[test]
fn rewrite_interpreter() {
    let print_options = readobj::PrintOptions {
        string_indices: false,
        segments: true,
        sections: true,
        elf_dynamic: true,
        ..readobj::PrintOptions::none()
    };
    let mut fail = false;

    let mut options = object_rewrite::Options::default();
    options.elf.set_interpreter = Some(b"/foo/ld.so".to_vec());
    fail |= testfile(
        "elf/base",
        "elf/base.set-interpreter",
        options,
        &print_options,
    );

    fail_message(fail);
}

fn testfile(
    in_path: &str,
    out_path: &str,
    options: object_rewrite::Options,
    print_options: &readobj::PrintOptions,
) -> bool {
    let in_path = Path::new("../../testfiles").join(in_path);
    let out_path = Path::new("testfiles").join(out_path);

    println!("Test {}", out_path.display());
    let in_data = match fs::read(&in_path) {
        Ok(in_data) => in_data,
        Err(err) => {
            println!("FAIL Couldn't read {}: {}", in_path.display(), err);
            return true;
        }
    };

    let mut rewriter = object_rewrite::Rewriter::read(&in_data).unwrap();
    rewriter.modify(options).unwrap();
    let mut rewrite_data = Vec::new();
    rewriter.write(&mut rewrite_data).unwrap();

    let mut out_data = Vec::new();
    let mut err_data = Vec::new();
    readobj::print(&mut out_data, &mut err_data, &rewrite_data, print_options);

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

    if !err_data.is_empty() {
        println!("FAIL unexpected stderr");
        fail = true;
    }

    fail
}
