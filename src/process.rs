//! Process manager -- run workloads as plain processes on the VM.

use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

const LOG_DIR: &str = "/var/lib/easyenclave/workloads/logs";

fn log_path(app_name: &str) -> PathBuf {
    PathBuf::from(format!("{LOG_DIR}/{app_name}.log"))
}

/// Tee a child stream to both a log file and easyenclave's stderr
/// (which goes to the serial console at boot). Drains the pipe so it
/// never blocks the child on a full buffer.
fn spawn_tee(
    stream: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    log_file: std::fs::File,
    prefix: String,
) {
    use std::io::Write;
    use std::sync::Mutex;
    let log_file = std::sync::Arc::new(Mutex::new(log_file));
    tokio::spawn(async move {
        let mut reader = BufReader::new(stream).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            eprintln!("[{prefix}] {line}");
            if let Ok(mut f) = log_file.lock() {
                let _ = writeln!(f, "{line}");
                let _ = f.flush();
            }
        }
    });
}

/// Spawn a command directly on the VM. stdout+stderr are piped, drained
/// by background tasks, and tee'd to both a per-app log file (for the
/// `logs` socket method) and easyenclave's own stderr (so output is
/// visible on the serial console during boot).
pub async fn spawn_command(
    program: &str,
    args: &[&str],
    tty: bool,
    app_name: &str,
) -> Result<Child, String> {
    spawn_inner(program, args, tty, None, app_name).await
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
    spawn_inner(program, args, tty, Some(env), app_name).await
}

async fn spawn_inner(
    program: &str,
    args: &[&str],
    tty: bool,
    env: Option<&std::collections::HashMap<String, String>>,
    app_name: &str,
) -> Result<Child, String> {
    std::fs::create_dir_all(LOG_DIR).map_err(|e| format!("create log dir: {e}"))?;
    let log_file =
        std::fs::File::create(log_path(app_name)).map_err(|e| format!("open log: {e}"))?;
    let log_clone = log_file
        .try_clone()
        .map_err(|e| format!("clone log: {e}"))?;

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

    if let Some(e) = env {
        cmd.envs(e);
    }
    if tty {
        cmd.env("TERM", "xterm-256color");
    }

    cmd.stdin(if tty { Stdio::piped() } else { Stdio::null() });
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| format!("spawn {program}: {e}"))?;
    let pid = child.id().unwrap_or(0);
    eprintln!("easyenclave: spawned {program} (pid={pid}, app={app_name})");

    if let Some(stdout) = child.stdout.take() {
        spawn_tee(stdout, log_file, app_name.to_string());
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_tee(stderr, log_clone, app_name.to_string());
    }

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
