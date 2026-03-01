mod password_hash;

use std::env;
use std::path::PathBuf;
use std::process::Command;

enum Op {
    Script {
        program: &'static str,
        script_rel: &'static str,
    },
    Native(fn(&[String]) -> i32),
}

fn usage() {
    eprintln!(
        "Usage: cargo run -p ee-ops -- <command> [args...]\n\nCommands:\n  lint\n  ci-build-measure\n  ci-reproducibility-check\n  ci-deploy\n  gcp-bake-image\n  hash-admin-password"
    );
}

fn resolve_op(name: &str) -> Option<Op> {
    match name {
        "lint" => Some(Op::Script {
            program: "bash",
            script_rel: "crates/ee-ops/assets/lint.sh",
        }),
        "ci-build-measure" | "ci_build_measure" => Some(Op::Script {
            program: "bash",
            script_rel: "crates/ee-ops/assets/ci-build-measure.sh",
        }),
        "ci-reproducibility-check" | "ci_reproducibility_check" => Some(Op::Script {
            program: "bash",
            script_rel: "crates/ee-ops/assets/ci-reproducibility-check.sh",
        }),
        "ci-deploy" | "ci_deploy" => Some(Op::Script {
            program: "bash",
            script_rel: "crates/ee-ops/assets/ci-deploy.sh",
        }),
        "gcp-bake-image" | "gcp_bake_image" => Some(Op::Script {
            program: "bash",
            script_rel: "crates/ee-ops/assets/gcp-bake-image.sh",
        }),
        "hash-admin-password" | "hash_admin_password" => Some(Op::Native(password_hash::run)),
        _ => None,
    }
}

fn repo_root() -> Result<PathBuf, String> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest
        .join("../..")
        .canonicalize()
        .map_err(|e| format!("failed to resolve repo root: {e}"))?;
    Ok(root)
}

fn main() {
    let mut args = env::args().skip(1);
    let Some(command_name) = args.next() else {
        usage();
        std::process::exit(2);
    };

    let Some(op) = resolve_op(&command_name) else {
        eprintln!("Unknown ee-ops command: {command_name}");
        usage();
        std::process::exit(2);
    };

    let repo_root = match repo_root() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };

    let tail_args: Vec<String> = args.collect();
    match op {
        Op::Native(run_fn) => std::process::exit(run_fn(&tail_args)),
        Op::Script {
            program,
            script_rel,
        } => {
            let script_path = repo_root.join(script_rel);
            if !script_path.exists() {
                eprintln!("ee-ops asset not found: {}", script_path.display());
                std::process::exit(1);
            }

            let status = match Command::new(program)
                .arg(script_path)
                .args(&tail_args)
                .current_dir(&repo_root)
                .status()
            {
                Ok(status) => status,
                Err(err) => {
                    eprintln!("failed to run ee-ops command '{command_name}': {err}");
                    std::process::exit(1);
                }
            };

            std::process::exit(status.code().unwrap_or(1));
        }
    }
}
