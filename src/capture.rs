//! Workload stdio capture — optionally tee every spawned workload's
//! stdout/stderr to a unix-domain socket as line-delimited JSON
//! records.
//!
//! When a [`workload::DeployRequest`](crate::workload::DeployRequest)
//! sets `capture_socket`, easyenclave connects to that socket once per
//! spawned workload and sends:
//!
//! - `{"type":"spawn","id":"<app>-<ms>","argv":[..],"cwd":"/"}` — first
//! - `{"type":"out","id":"<app>-<ms>","s":"stdout"|"stderr","b":"<line>"}`
//!   — per line, in order of arrival. `b` is the UTF-8 string (no base64).
//! - `{"type":"exit","id":"<app>-<ms>","code":<i32>}` — last, before
//!   closing the connection.
//!
//! The consumer on the other end of the socket (today:
//! `devopsdefender/dd`'s bastion workload) can reconstruct each
//! workload's lifetime into a searchable block. If the socket isn't
//! there or the connection drops mid-stream, easyenclave keeps the
//! workload running — capture is best-effort tee, not a hard
//! dependency.

use std::path::Path;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::Mutex;

/// A live connection to the capture socket for a single workload.
///
/// Clone cheaply for each tee task (stdout + stderr share one
/// connection under a mutex); consume the last handle via
/// [`CaptureSink::exit`] to emit the final record and drop the socket.
#[derive(Clone)]
pub struct CaptureSink {
    stream: Arc<Mutex<UnixStream>>,
    id: Arc<str>,
}

impl CaptureSink {
    /// Connect to `path`, send the initial `spawn` record, and return
    /// a handle usable for `out` and `exit` calls.
    ///
    /// Returns `None` on any I/O error so callers can fall back to
    /// running the workload without capture rather than failing it.
    pub async fn connect(
        path: impl AsRef<Path>,
        id: String,
        argv: &[String],
        cwd: Option<&str>,
    ) -> Option<Self> {
        let stream = match UnixStream::connect(path.as_ref()).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "easyenclave: capture socket {}: {e} — skipping capture for {id}",
                    path.as_ref().display()
                );
                return None;
            }
        };
        let sink = Self {
            stream: Arc::new(Mutex::new(stream)),
            id: Arc::from(id),
        };
        let record = serde_json::json!({
            "type": "spawn",
            "id": &*sink.id,
            "argv": argv,
            "cwd": cwd,
        });
        if sink.send(record).await.is_err() {
            return None;
        }
        Some(sink)
    }

    /// Send an `out` record for one line of stdout/stderr.
    pub async fn out(&self, stream_name: &str, line: &str) {
        let record = serde_json::json!({
            "type": "out",
            "id": &*self.id,
            "s": stream_name,
            "b": line,
        });
        let _ = self.send(record).await;
    }

    /// Send the final `exit` record and close. Takes `self` so callers
    /// can't keep using the sink after exit.
    pub async fn exit(self, code: i32) {
        let record = serde_json::json!({
            "type": "exit",
            "id": &*self.id,
            "code": code,
        });
        let _ = self.send(record).await;
        // UnixStream closes on drop.
    }

    async fn send(&self, record: serde_json::Value) -> std::io::Result<()> {
        let mut line = serde_json::to_string(&record).unwrap_or_default();
        line.push('\n');
        let mut g = self.stream.lock().await;
        g.write_all(line.as_bytes()).await?;
        g.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn emits_spawn_out_exit_records() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("capture.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let accept = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut lines = BufReader::new(stream).lines();
            let mut out = Vec::new();
            while let Ok(Some(line)) = lines.next_line().await {
                out.push(line);
            }
            out
        });

        let sink = CaptureSink::connect(
            &sock,
            "myapp-42".into(),
            &["myapp".into(), "--flag".into()],
            None,
        )
        .await
        .expect("connect");
        sink.out("stdout", "hello").await;
        sink.out("stderr", "boom").await;
        sink.exit(7).await;

        let lines = accept.await.unwrap();
        assert_eq!(lines.len(), 4);
        let spawn: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(spawn["type"], "spawn");
        assert_eq!(spawn["id"], "myapp-42");
        assert_eq!(spawn["argv"], serde_json::json!(["myapp", "--flag"]));
        let out1: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!(out1["type"], "out");
        assert_eq!(out1["s"], "stdout");
        assert_eq!(out1["b"], "hello");
        let out2: serde_json::Value = serde_json::from_str(&lines[2]).unwrap();
        assert_eq!(out2["s"], "stderr");
        let exit: serde_json::Value = serde_json::from_str(&lines[3]).unwrap();
        assert_eq!(exit["type"], "exit");
        assert_eq!(exit["code"], 7);
    }
}
