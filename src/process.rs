//! Process manager -- run workloads as plain processes on the VM.

use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;

use crate::capture::CaptureSink;

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
    capture: Option<CaptureSink>,
    stream_name: &'static str,
) -> JoinHandle<()> {
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
            if let Some(c) = capture.as_ref() {
                c.out(stream_name, &line).await;
            }
        }
    })
}

/// Spawn a command directly on the VM. stdout+stderr are piped, drained
/// by background tasks, and tee'd to both a per-app log file (for the
/// `logs` socket method) and easyenclave's own stderr (so output is
/// visible on the serial console during boot).
/// Handle to a spawned workload. `tee_handles` are the background tasks
/// draining stdout/stderr into the log file (and the capture socket, if
/// configured). Await them before emitting a final `exit` record so the
/// child's last lines aren't lost to the race between `child.wait()` and
/// pipe drain.
pub struct SpawnedChild {
    pub child: Child,
    pub tee_handles: Vec<JoinHandle<()>>,
}

pub async fn spawn_command(
    program: &str,
    args: &[&str],
    tty: bool,
    app_name: &str,
    capture: Option<CaptureSink>,
) -> Result<SpawnedChild, String> {
    spawn_inner(program, args, tty, None, app_name, capture).await
}

/// Spawn a command with an explicit environment map on top of the
/// inherited parent env.
pub async fn spawn_command_with_env(
    program: &str,
    args: &[&str],
    tty: bool,
    env: &std::collections::HashMap<String, String>,
    app_name: &str,
    capture: Option<CaptureSink>,
) -> Result<SpawnedChild, String> {
    spawn_inner(program, args, tty, Some(env), app_name, capture).await
}

async fn spawn_inner(
    program: &str,
    args: &[&str],
    tty: bool,
    env: Option<&std::collections::HashMap<String, String>>,
    app_name: &str,
    capture: Option<CaptureSink>,
) -> Result<SpawnedChild, String> {
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

    let mut tee_handles = Vec::with_capacity(2);
    if let Some(stdout) = child.stdout.take() {
        tee_handles.push(spawn_tee(
            stdout,
            log_file,
            app_name.to_string(),
            capture.clone(),
            "stdout",
        ));
    }
    if let Some(stderr) = child.stderr.take() {
        tee_handles.push(spawn_tee(
            stderr,
            log_clone,
            app_name.to_string(),
            capture,
            "stderr",
        ));
    }

    Ok(SpawnedChild { child, tee_handles })
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
