use std::{env, fs, process};

fn main() {
    let mut args = env::args_os().skip(1);
    let (input_path, output_path) = match (args.next(), args.next(), args.next()) {
        (Some(i), Some(o), None) => (i, o),
        _ => {
            eprintln!("Usage: elfstub <input.so> <output.so>");
            process::exit(1);
        }
    };

    let data = match fs::read(&input_path) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("Failed to read file '{}': {}", input_path.display(), err,);
            process::exit(1);
        }
    };

    let stub = match object_examples::elfstub(&data) {
        Ok(stub) => stub,
        Err(err) => {
            eprintln!("Failed to create stub: {}", err);
            process::exit(1);
        }
    };

    if let Err(err) = fs::write(&output_path, stub) {
        eprintln!("Failed to write file '{}': {}", output_path.display(), err);
        process::exit(1);
    }
}
