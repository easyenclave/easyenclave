//! Process manager -- run workloads as plain processes on the VM.

use std::path::PathBuf;
use tokio::process::{Child, Command};

const DEFAULT_DATA_DIR: &str = "/var/lib/easyenclave";

fn workload_logs_dir() -> PathBuf {
    let data_dir = std::env::var("EE_DATA_DIR").unwrap_or_else(|_| DEFAULT_DATA_DIR.to_string());
    PathBuf::from(data_dir).join("workloads/logs")
}

fn shell_escape(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "'\"'\"'"))
}

fn build_tty_command(program: &str, args: &[&str]) -> String {
    std::iter::once(program)
        .chain(args.iter().copied())
        .map(shell_escape)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Spawn a command directly on the VM.
pub async fn spawn_command(program: &str, args: &[&str], tty: bool) -> Result<Child, String> {
    let _ = tokio::fs::create_dir_all(workload_logs_dir()).await;

    let mut cmd = if tty {
        let mut c = Command::new("script");
        c.arg("-qfc");
        c.arg(build_tty_command(program, args));
        c.arg("/dev/null");
        c.env("TERM", "xterm-256color");
        c
    } else {
        let mut c = Command::new(program);
        c.args(args);
        c
    };

    cmd.stdin(if tty {
        std::process::Stdio::piped()
    } else {
        std::process::Stdio::null()
    });
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let child = cmd.spawn().map_err(|e| format!("spawn {program}: {e}"))?;
    eprintln!(
        "easyenclave: spawned {program} (pid={})",
        child.id().unwrap_or(0)
    );
    Ok(child)
}

/// Spawn a command with explicit environment variables.
pub async fn spawn_command_with_env(
    program: &str,
    args: &[&str],
    tty: bool,
    env: &std::collections::HashMap<String, String>,
) -> Result<Child, String> {
    let _ = tokio::fs::create_dir_all(workload_logs_dir()).await;

    let mut cmd = Command::new(program);
    cmd.args(args);
    // Inherit host env, then overlay workload env
    cmd.envs(env);
    if tty {
        cmd.env("TERM", "xterm-256color");
    }

    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let child = cmd.spawn().map_err(|e| format!("spawn {program}: {e}"))?;
    eprintln!(
        "easyenclave: spawned {program} (pid={})",
        child.id().unwrap_or(0)
    );
    Ok(child)
}

/// Kill a process by PID (SIGTERM then SIGKILL).
pub async fn kill_process(pid: u32) -> Result<(), String> {
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .output()
        .await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let _ = Command::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .output()
        .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::build_tty_command;

    #[test]
    fn build_tty_command_shell_escapes_arguments() {
        let cmd = build_tty_command("echo", &["hello world", "quote's"]);
        assert_eq!(cmd, "'echo' 'hello world' 'quote'\"'\"'s'");
    }
}
