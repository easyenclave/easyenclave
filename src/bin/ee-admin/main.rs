mod password_hash;

use std::env;

fn usage() {
    eprintln!(
        "Usage: cargo run --bin ee-admin -- <command> [args...]\n\nCommands:\n  hash-admin-password"
    );
}

fn main() {
    let mut args = env::args().skip(1);
    let Some(command_name) = args.next() else {
        usage();
        std::process::exit(2);
    };

    let tail_args: Vec<String> = args.collect();
    match command_name.as_str() {
        "hash-admin-password" | "hash_admin_password" => {
            std::process::exit(password_hash::run(&tail_args))
        }
        _ => {
            eprintln!("Unknown ee-admin command: {command_name}");
            usage();
            std::process::exit(2);
        }
    }
}
