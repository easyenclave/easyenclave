use std::io::{self, Read};

use bcrypt::{hash, DEFAULT_COST};

fn usage() {
    eprintln!(
        "Usage: cargo run --bin ee-admin -- hash-admin-password [--password <value> | --stdin]\n\nWithout flags, prompts interactively."
    );
}

fn parse_args(args: &[String]) -> Result<(Option<String>, bool), String> {
    let mut password: Option<String> = None;
    let mut use_stdin = false;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--password" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("--password requires a value".to_string());
                };
                password = Some(val.to_string());
            }
            "--stdin" => {
                use_stdin = true;
            }
            "-h" | "--help" => {
                usage();
                return Err("help_requested".to_string());
            }
            other => {
                return Err(format!("unknown argument: {other}"));
            }
        }
        i += 1;
    }

    if password.is_some() && use_stdin {
        return Err("use either --password or --stdin, not both".to_string());
    }

    Ok((password, use_stdin))
}

fn read_password_stdin() -> Result<String, String> {
    let mut raw = String::new();
    io::stdin()
        .read_to_string(&mut raw)
        .map_err(|e| format!("failed to read stdin: {e}"))?;
    Ok(raw.trim().to_string())
}

fn prompt_passwords() -> Result<String, String> {
    println!("=== EasyEnclave Admin Password Hasher ===\n");
    println!("This command will generate a bcrypt hash for your admin password.");
    println!("The hash should be set as the ADMIN_PASSWORD_HASH environment variable.\n");

    let password =
        rpassword::prompt_password("Enter admin password: ").map_err(|e| format!("{e}"))?;
    let password_confirm =
        rpassword::prompt_password("Confirm admin password: ").map_err(|e| format!("{e}"))?;

    if password != password_confirm {
        return Err("Passwords do not match".to_string());
    }
    Ok(password)
}

fn emit_output(password_hash: &str) {
    println!("\n{}", "=".repeat(70));
    println!("SUCCESS! Add this to your environment variables:");
    println!("{}", "=".repeat(70));
    println!("\nexport ADMIN_PASSWORD_HASH='{}'", password_hash);
    println!("\nOr add to your .env file:");
    println!("\nADMIN_PASSWORD_HASH={}", password_hash);
    println!("\n{}", "=".repeat(70));
    println!("\nIMPORTANT: Store this securely. The plaintext password cannot be recovered.");
    println!("{}", "=".repeat(70));
}

pub fn run(args: &[String]) -> i32 {
    let (arg_password, use_stdin) = match parse_args(args) {
        Ok(v) => v,
        Err(err) if err == "help_requested" => return 0,
        Err(err) => {
            eprintln!("error: {err}");
            usage();
            return 2;
        }
    };

    let password = if let Some(v) = arg_password {
        v
    } else if use_stdin {
        match read_password_stdin() {
            Ok(v) => v,
            Err(err) => {
                eprintln!("error: {err}");
                return 1;
            }
        }
    } else {
        match prompt_passwords() {
            Ok(v) => v,
            Err(err) => {
                eprintln!("\nError: {err}");
                return 1;
            }
        }
    };

    if password.len() < 8 {
        eprintln!("\nError: Password must be at least 8 characters long!");
        return 1;
    }

    let password_hash = match hash(password, DEFAULT_COST) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("\nError: failed to hash password: {err}");
            return 1;
        }
    };

    emit_output(&password_hash);
    0
}
