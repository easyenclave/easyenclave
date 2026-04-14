//! Process manager -- run workloads as plain processes on the VM.

use std::path::PathBuf;
use tokio::process::{Child, Command};

const LOG_DIR: &str = "/var/lib/easyenclave/workloads/logs";

fn log_path(app_name: &str) -> PathBuf {
    PathBuf::from(format!("{LOG_DIR}/{app_name}.log"))
}

/// Open the per-app log file for writing. Truncates on each deploy —
/// old workloads for the same app are stopped first, so their logs are
/// in the previous deploy's copy (not preserved across deploys).
fn open_log_file(app_name: &str) -> Result<std::fs::File, String> {
    std::fs::create_dir_all(LOG_DIR).map_err(|e| format!("create log dir: {e}"))?;
    std::fs::File::create(log_path(app_name)).map_err(|e| format!("open log for {app_name}: {e}"))
}

/// Spawn a command directly on the VM. stdout+stderr are redirected to
/// a log file under LOG_DIR so the `logs` socket method works and so
/// long-running children don't deadlock on a full pipe buffer.
pub async fn spawn_command(
    program: &str,
    args: &[&str],
    tty: bool,
    app_name: &str,
) -> Result<Child, String> {
    let stdout = open_log_file(app_name)?;
    let stderr = stdout
        .try_clone()
        .map_err(|e| format!("clone log fd: {e}"))?;

    let mut cmd = if tty {
        let mut c = Command::new("script");
        c.arg("-qfc");
        let full_cmd = std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        c.arg(full_cmd);
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
    cmd.stdout(stdout);
    cmd.stderr(stderr);

    let child = cmd.spawn().map_err(|e| format!("spawn {program}: {e}"))?;
    eprintln!(
        "easyenclave: spawned {program} (pid={}, app={app_name})",
        child.id().unwrap_or(0)
    );
    Ok(child)
}

/// Spawn a command with an explicit environment map on top of the
/// inherited parent env.
pub async fn spawn_command_with_env(
    program: &str,
    args: &[&str],
    tty: bool,
    env: &std::collections::HashMap<String, String>,
    app_name: &str,
) -> Result<Child, String> {
    let stdout = open_log_file(app_name)?;
    let stderr = stdout
        .try_clone()
        .map_err(|e| format!("clone log fd: {e}"))?;

    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.envs(env);
    if tty {
        cmd.env("TERM", "xterm-256color");
    }

    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(stdout);
    cmd.stderr(stderr);

    let child = cmd.spawn().map_err(|e| format!("spawn {program}: {e}"))?;
    eprintln!(
        "easyenclave: spawned {program} (pid={}, app={app_name})",
        child.id().unwrap_or(0)
    );
    Ok(child)
}

/// Read the last `tail` lines from a workload's log file.
pub async fn read_logs(app_name: &str, tail: usize) -> Result<Vec<String>, String> {
    let path = log_path(app_name);
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => {
            let lines: Vec<String> = content.lines().map(String::from).collect();
            let start = lines.len().saturating_sub(tail);
            Ok(lines[start..].to_vec())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("read log: {e}")),
    }
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
