use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

type DynError = Box<dyn std::error::Error>;

fn main() {
    if let Err(e) = try_main() {
        eprintln!("{}", e);
        std::process::exit(-1);
    }
}

fn try_main() -> Result<(), DynError> {
    if let Some(name) = env::args().nth(1) {
        if let Some(task) = TASKS.iter().find(|task| name == task.0) {
            (task.1)()?;
            return Ok(());
        }
    }
    print_help();
    Ok(())
}

fn print_help() {
    eprintln!("Tasks:");
    for task in TASKS {
        eprintln!("  {:20}{}", task.0, task.2);
    }
}

type Task = (&'static str, fn() -> Result<(), DynError>, &'static str);

const TASKS: &[Task] = &[
    ("ci", cmd_ci, "runs everything in CI"),
    ("check", cmd_check, "checks everything"),
    ("build", cmd_build, "builds everything"),
    ("test", cmd_test, "tests everything"),
    (
        "test-update",
        cmd_test_update,
        "regenerates the expected test output",
    ),
    (
        "features",
        cmd_features,
        "tests with various feature combinations",
    ),
    ("cross", cmd_cross, "tests for other platforms"),
    ("msrv", cmd_msrv, "tests minimum supported Rust version"),
    ("fmt", cmd_fmt, "checks formatting"),
    ("doc", cmd_doc, "generates documentation for everything"),
    (
        "coverage",
        cmd_coverage,
        "generates HTML test coverage with tarpaulin and pycobertura, and opens it",
    ),
    (
        "coverage_lcov",
        cmd_coverage_lcov,
        "generates Lcov test coverage with tarpaulin",
    ),
    ("clippy", cmd_clippy, "run clippy for everything"),
    ("semver", cmd_semver, "run semver checks"),
];

fn cmd_ci() -> Result<(), DynError> {
    cmd_check()?;
    cmd_test()?;
    cmd_features()?;
    cmd_cross()?;
    cmd_msrv()?;
    cmd_fmt()?;
    cmd_doc()?;
    Ok(())
}

fn cmd_check() -> Result<(), DynError> {
    cargo(&["check", "--workspace", "--features", "all"])
}

fn cmd_build() -> Result<(), DynError> {
    cargo(&["build", "--workspace", "--features", "all"])
}

fn cmd_test() -> Result<(), DynError> {
    cargo(&["test", "--workspace", "--features", "all"])
}

fn cmd_test_update() -> Result<(), DynError> {
    cargo_with(&["test", "--workspace", "--features", "all"], |cmd| {
        cmd.env("OBJECT_TESTFILES_UPDATE", "1");
    })
}

fn cmd_features() -> Result<(), DynError> {
    // Test the default features for everything.
    cargo(&["test", "--workspace"])?;

    // Test no default features for everything.
    cargo(&["test", "-p", "object", "--no-default-features"])?;
    cargo(&["test", "-p", "object-examples", "--no-default-features"])?;
    cargo(&["test", "-p", "object-rewrite", "--no-default-features"])?;

    // Feature combinations for the `object` and `object-examples` packages.
    for features in [
        // Test the main submodules.
        "read",
        "write",
        "build",
        // Test each file format individually.
        "read_core,write_core,coff",
        "read_core,write_core,build_core,elf",
        "read_core,write_core,macho",
        "read_core,write_core,pe",
        "read_core,write_core,xcoff",
        "read_core,wasm",
        // Test miscellaneous features individually.
        "std",
        "compression",
        "unaligned",
    ] {
        cargo(&[
            "test",
            "-p",
            "object",
            "-p",
            "object-examples",
            "--no-default-features",
            "--features",
            features,
        ])?;
    }

    // Feature combinations for the `object-rewrite` package.
    cargo(&[
        "test",
        "-p",
        "object-rewrite",
        "--no-default-features",
        "--features",
        "logging",
    ])?;
    Ok(())
}

fn cmd_cross() -> Result<(), DynError> {
    for target in [
        // 32-bit target
        "i686-unknown-linux-gnu",
        // big-endian target
        "powerpc64-unknown-linux-gnu",
    ] {
        cmd(
            "cross",
            &[
                "test",
                "--workspace",
                "--features",
                "all",
                "--target",
                target,
            ],
        )?;
    }
    Ok(())
}

fn cmd_msrv() -> Result<(), DynError> {
    // Test MSRV for object read feature.
    cargo(&["update", "-p", "memchr", "--precise", "2.6.2"])?;
    cmd_with(
        "cargo",
        &[
            "+1.60.0",
            "test",
            "-p",
            "object",
            "--no-default-features",
            "--features",
            "read,std",
        ],
        |cmd| {
            cmd.env("CARGO_NET_GIT_FETCH_WITH_CLI", "true");
        },
    )?;
    cargo(&["update", "-p", "memchr"])?;
    // Test MSRV for object all features.
    cargo(&["update", "-p", "ahash", "--precise", "0.8.6"])?;
    cmd_with(
        "cargo",
        &["+1.65.0", "test", "-p", "object", "--features", "all"],
        |cmd| {
            cmd.env("CARGO_NET_GIT_FETCH_WITH_CLI", "true");
        },
    )?;

    cargo(&["update", "-p", "ahash"])?;
    Ok(())
}

fn cmd_fmt() -> Result<(), DynError> {
    cargo(&["fmt", "--", "--check"])
}

fn cmd_doc() -> Result<(), DynError> {
    cargo_with(
        &[
            "doc",
            "--workspace",
            "--lib",
            "--no-default-features",
            "--features",
            "doc",
        ],
        |cmd| {
            cmd.env("RUSTDOCFLAGS", "-D warnings");
        },
    )
}

fn cmd_coverage() -> Result<(), DynError> {
    cargo(&[
        "tarpaulin",
        "--features",
        "all",
        "--ignore-tests",
        "--out",
        "xml",
    ])?;
    cmd(
        "pycobertura",
        &[
            "show",
            "--format",
            "html",
            "cobertura.xml",
            "--output",
            "cobertura.html",
        ],
    )?;
    cmd("open", &["cobertura.html"])?;
    Ok(())
}

fn cmd_coverage_lcov() -> Result<(), DynError> {
    cargo(&[
        "tarpaulin",
        "--features",
        "all",
        "--ignore-tests",
        "--out",
        "Lcov",
    ])
}

fn cmd_clippy() -> Result<(), DynError> {
    cargo(&[
        "clippy",
        "--workspace",
        "--features",
        "all",
        "--all-targets",
    ])
}

fn cmd_semver() -> Result<(), DynError> {
    cargo(&[
        "semver-checks",
        "--only-explicit-features",
        "--features",
        "all",
        "-p",
        "object",
    ])
}

fn cargo(args: &[&str]) -> Result<(), DynError> {
    cargo_with(args, |_| ())
}

fn cargo_with(args: &[&str], f: impl FnOnce(&mut Command)) -> Result<(), DynError> {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    cmd_with(&cargo, args, f)
}

fn cmd(cmd: &str, args: &[&str]) -> Result<(), DynError> {
    cmd_with(cmd, args, |_| ())
}

fn cmd_with<F>(program: &str, args: &[&str], f: F) -> Result<(), DynError>
where
    F: FnOnce(&mut Command),
{
    println!("Running '{} {}'", program, args.join(" "));
    let mut command = Command::new(program);
    command.current_dir(project_root()).args(args);
    f(&mut command);
    let status = command.status()?;
    if !status.success() {
        Err(format!("'{} {}' failed", program, args.join(" ")))?;
    }
    Ok(())
}

fn project_root() -> PathBuf {
    Path::new(&env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .unwrap()
        .to_path_buf()
}
