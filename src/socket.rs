//! Unix socket server -- newline-delimited JSON protocol.
//!
//! Most methods are one-shot request/response. The `attach` method is
//! special: after the JSON handshake the connection switches to a raw
//! byte stream bridging a PTY-backed shell.

use serde_json::{json, Value};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::process::Command;

use crate::attestation::AttestationBackend;
use crate::workload::{DeployRequest, Deployments};

pub struct SocketServer {
    pub socket_path: String,
    pub deployments: Deployments,
    pub attestation: Arc<Box<dyn AttestationBackend>>,
    pub start_time: std::time::Instant,
}

impl SocketServer {
    /// Run the socket server. Blocks until the listener is dropped.
    pub async fn run(&self) -> Result<(), String> {
        // Remove stale socket file
        let _ = std::fs::remove_file(&self.socket_path);

        // Ensure parent directory exists
        if let Some(parent) = std::path::Path::new(&self.socket_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = UnixListener::bind(&self.socket_path)
            .map_err(|e| format!("bind {}: {e}", self.socket_path))?;

        eprintln!("easyenclave: listening on {}", self.socket_path);

        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|e| format!("accept: {e}"))?;

            let deployments = self.deployments.clone();
            let attestation = self.attestation.clone();
            let start_time = self.start_time;

            tokio::spawn(async move {
                let (reader, mut writer) = stream.into_split();
                let mut buf_reader = BufReader::new(reader);
                let mut line = String::new();

                loop {
                    line.clear();
                    match buf_reader.read_line(&mut line).await {
                        Ok(0) => break, // EOF
                        Ok(_) => {}
                        Err(_) => break,
                    }

                    // Sniff for `attach` before dispatching — it switches
                    // the connection from JSON line mode to raw bytes.
                    if let Ok(req) = serde_json::from_str::<Value>(line.trim()) {
                        if req.get("method").and_then(|m| m.as_str()) == Some("attach") {
                            if writer
                                .write_all(b"{\"ok\":true,\"attached\":true}\n")
                                .await
                                .is_err()
                            {
                                return;
                            }
                            bridge_attach(buf_reader, writer, &req).await;
                            return;
                        }
                    }

                    let response =
                        handle_request(&line, &deployments, &attestation, start_time).await;
                    let mut out = serde_json::to_string(&response).unwrap_or_else(|_| {
                        r#"{"ok":false,"error":"serialize error"}"#.to_string()
                    });
                    out.push('\n');
                    if writer.write_all(out.as_bytes()).await.is_err() {
                        break;
                    }
                }
            });
        }
    }
}

async fn handle_request(
    line: &str,
    deployments: &Deployments,
    attestation: &Arc<Box<dyn AttestationBackend>>,
    start_time: std::time::Instant,
) -> Value {
    let req: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => return json!({"ok": false, "error": format!("invalid json: {e}")}),
    };

    let method = match req.get("method").and_then(|m| m.as_str()) {
        Some(m) => m,
        None => return json!({"ok": false, "error": "missing method"}),
    };

    match method {
        "health" => handle_health(deployments, attestation, start_time).await,
        "attest" => handle_attest(&req, attestation),
        "deploy" => handle_deploy(&req, deployments).await,
        "list" => handle_list(deployments).await,
        "stop" => handle_stop(&req, deployments).await,
        "exec" => handle_exec(&req).await,
        "logs" => handle_logs(&req, deployments).await,
        _ => json!({"ok": false, "error": format!("unknown method: {method}")}),
    }
}

async fn handle_health(
    deployments: &Deployments,
    attestation: &Arc<Box<dyn AttestationBackend>>,
    start_time: std::time::Instant,
) -> Value {
    let count = deployments.lock().await.len();
    json!({
        "ok": true,
        "attestation_type": attestation.attestation_type(),
        "workloads": count,
        "uptime_secs": start_time.elapsed().as_secs(),
    })
}

fn handle_attest(req: &Value, attestation: &Arc<Box<dyn AttestationBackend>>) -> Value {
    let report_data = match attestation_report_data(req) {
        Ok(report_data) => report_data,
        Err(e) => return json!({"ok": false, "error": e}),
    };

    let quote = if report_data.is_empty() {
        attestation.generate_quote_b64()
    } else {
        attestation.generate_quote_with_report_data(&report_data)
    };

    match quote {
        Ok(q) => {
            use base64::Engine;
            json!({
                "ok": true,
                "attestation_type": attestation.attestation_type(),
                "quote_format": "tdx",
                "quote_b64": q,
                "report_data_b64": base64::engine::general_purpose::STANDARD.encode(&report_data),
                "report_data_len": report_data.len(),
            })
        }
        Err(e) => json!({
            "ok": false,
            "attestation_type": attestation.attestation_type(),
            "error": e,
        }),
    }
}

fn attestation_report_data(req: &Value) -> Result<Vec<u8>, String> {
    let report_data =
        if let Some(report_data_b64) = req.get("report_data_b64").and_then(|n| n.as_str()) {
            decode_base64_field("report_data_b64", report_data_b64)?
        } else if let Some(nonce) = req.get("nonce").and_then(|n| n.as_str()) {
            decode_legacy_nonce(nonce)?
        } else {
            Vec::new()
        };

    if report_data.len() > 64 {
        return Err(format!(
            "TDX report data is {} bytes; maximum is 64",
            report_data.len()
        ));
    }

    Ok(report_data)
}

fn decode_base64_field(field: &str, value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() {
        return Ok(Vec::new());
    }

    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| format!("invalid {field} base64: {e}"))
}

fn decode_legacy_nonce(value: &str) -> Result<Vec<u8>, String> {
    if is_hex(value) {
        decode_hex(value).map_err(|e| format!("invalid nonce hex: {e}"))
    } else {
        decode_base64_field("nonce", value)
    }
}

fn is_hex(value: &str) -> bool {
    !value.is_empty()
        && value.len().is_multiple_of(2)
        && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("odd number of digits".into());
    }

    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_value(pair[0])?;
            let low = hex_value(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("non-hex digit '{}'", byte as char)),
    }
}

async fn handle_deploy(req: &Value, deployments: &Deployments) -> Value {
    let deploy_req: DeployRequest = match serde_json::from_value(req.clone()) {
        Ok(r) => r,
        Err(e) => return json!({"ok": false, "error": format!("invalid deploy request: {e}")}),
    };

    let (id, status) = crate::workload::execute_deploy(deployments, deploy_req).await;
    json!({"ok": true, "id": id, "status": status})
}

async fn handle_list(deployments: &Deployments) -> Value {
    let deps = deployments.lock().await;
    let list: Vec<_> = deps.values().collect();
    json!({"ok": true, "deployments": list})
}

async fn handle_stop(req: &Value, deployments: &Deployments) -> Value {
    let id = match req.get("id").and_then(|i| i.as_str()) {
        Some(id) => id,
        None => return json!({"ok": false, "error": "missing id"}),
    };
    match crate::workload::execute_stop(deployments, id).await {
        Ok(()) => json!({"ok": true}),
        Err(e) => json!({"ok": false, "error": e}),
    }
}

async fn handle_exec(req: &Value) -> Value {
    let cmd = match req.get("cmd").and_then(|c| c.as_array()) {
        Some(arr) => {
            let strs: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            if strs.is_empty() {
                return json!({"ok": false, "error": "cmd array is empty"});
            }
            strs
        }
        None => return json!({"ok": false, "error": "missing cmd array"}),
    };

    let timeout_secs = req
        .get("timeout_secs")
        .and_then(|t| t.as_u64())
        .unwrap_or(30);
    let timeout = std::time::Duration::from_secs(timeout_secs);

    let program = &cmd[0];
    let args: Vec<&str> = cmd[1..].iter().map(|s| s.as_str()).collect();

    let child = match tokio::process::Command::new(program)
        .args(&args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return json!({"ok": false, "error": format!("spawn failed: {e}")}),
    };

    let pid = child.id();

    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(output)) => {
            json!({
                "ok": true,
                "exit_code": output.status.code().unwrap_or(-1),
                "stdout": String::from_utf8_lossy(&output.stdout),
                "stderr": String::from_utf8_lossy(&output.stderr),
            })
        }
        Ok(Err(e)) => json!({"ok": false, "error": format!("wait failed: {e}")}),
        Err(_) => {
            if let Some(pid) = pid {
                let _ = crate::process::kill_process(pid).await;
            }
            json!({"ok": false, "error": format!("command timed out after {timeout_secs}s")})
        }
    }
}

/// Bridge a unix socket connection to a PTY-backed shell.
///
/// `req` is the original attach request (`{"method":"attach","cmd":[...]}`).
/// `cmd` defaults to `["/bin/sh"]`. Uses `script(1)` to allocate a PTY —
/// the same wrapper `process.rs` uses for tty workloads.
async fn bridge_attach<R, W>(reader: R, mut writer: W, req: &Value)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let cmd: Vec<String> = req
        .get("cmd")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .filter(|v: &Vec<String>| !v.is_empty())
        .unwrap_or_else(|| vec!["/bin/sh".to_string()]);

    let full_cmd = cmd.join(" ");
    eprintln!("easyenclave: attach session: {full_cmd}");

    let mut child = match Command::new("script")
        .arg("-qfc")
        .arg(&full_cmd)
        .arg("/dev/null")
        .env("TERM", "xterm-256color")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("easyenclave: attach: spawn script: {e}");
            let _ = writer
                .write_all(format!("\nattach failed: {e}\n").as_bytes())
                .await;
            return;
        }
    };

    let pid = child.id();
    let mut child_stdin = child.stdin.take().expect("stdin piped");
    let mut child_stdout = child.stdout.take().expect("stdout piped");
    let mut child_stderr = child.stderr.take().expect("stderr piped");

    // Three concurrent copies. Wrap the writer in an Arc<Mutex<>> so
    // stdout and stderr can share it without interleaving partial UTF-8
    // sequences mid-byte. (script(1) usually folds stderr into stdout
    // anyway, but the stderr leg is cheap insurance.)
    let writer = std::sync::Arc::new(tokio::sync::Mutex::new(writer));

    let writer_out = writer.clone();
    let stdout_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match child_stdout.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut w = writer_out.lock().await;
                    if w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let writer_err = writer.clone();
    let stderr_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match child_stderr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut w = writer_err.lock().await;
                    if w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let stdin_task = tokio::spawn(async move {
        let mut reader = reader;
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if child_stdin.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Wait for the child to exit OR the socket-read side to drop.
    // Either condition tears the session down.
    tokio::select! {
        _ = child.wait() => {}
        _ = stdin_task => {}
    }

    // Best-effort: kill the child if it's still around, then drain
    // stdout/stderr so trailing bytes reach the client.
    if let Some(p) = pid {
        let _ = crate::process::kill_process(p).await;
    }
    let _ = stdout_task.await;
    let _ = stderr_task.await;
    eprintln!("easyenclave: attach session ended ({full_cmd})");
}

async fn handle_logs(req: &Value, deployments: &Deployments) -> Value {
    let id = match req.get("id").and_then(|i| i.as_str()) {
        Some(id) => id,
        None => return json!({"ok": false, "error": "missing id"}),
    };
    let tail = req.get("tail").and_then(|t| t.as_u64()).unwrap_or(100) as usize;

    let app_name = {
        let deps = deployments.lock().await;
        match deps.get(id) {
            Some(info) => info.app_name.clone(),
            None => return json!({"ok": false, "error": "deployment not found"}),
        }
    };

    match crate::process::read_logs(&app_name, tail).await {
        Ok(lines) => json!({"ok": true, "lines": lines}),
        Err(e) => json!({"ok": false, "error": e}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serde_json::json;

    #[test]
    fn report_data_b64_is_preferred() {
        let report_data = vec![1u8; 32];
        let req = json!({
            "report_data_b64": base64::engine::general_purpose::STANDARD.encode(&report_data),
            "nonce": "00",
        });

        assert_eq!(attestation_report_data(&req).unwrap(), report_data);
    }

    #[test]
    fn legacy_nonce_accepts_base64() {
        let nonce = b"freshness";
        let req = json!({
            "nonce": base64::engine::general_purpose::STANDARD.encode(nonce),
        });

        assert_eq!(attestation_report_data(&req).unwrap(), nonce);
    }

    #[test]
    fn legacy_nonce_accepts_hex_values() {
        let req = json!({ "nonce": "deadbeef" });

        assert_eq!(
            attestation_report_data(&req).unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn report_data_rejects_oversize_values() {
        let report_data = vec![7u8; 65];
        let req = json!({
            "report_data_b64": base64::engine::general_purpose::STANDARD.encode(report_data),
        });

        let err = attestation_report_data(&req).unwrap_err();
        assert!(err.contains("maximum is 64"));
    }
}
