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

use crate::attestation::{AttestationBackend, GpuEvidenceBackend};
use crate::workload::{DeployRequest, Deployments};

pub type GpuBackend = Arc<Box<dyn GpuEvidenceBackend>>;

pub struct SocketServer {
    pub socket_path: String,
    pub deployments: Deployments,
    pub attestation: Arc<Box<dyn AttestationBackend>>,
    /// Optional auxiliary GPU evidence producer. When `Some`, `attest`
    /// folds an `evidence.nvgpu` (or `evidence.nvgpu_error`) field into
    /// its response. Failures here never fail the TDX path.
    pub gpu_evidence: Option<GpuBackend>,
    pub start_time: std::time::Instant,
    /// If set, every request must include `"token": "<matching-value>"`.
    /// Minted once at boot by `main.rs::mint_boot_token` and handed to
    /// workloads that opt in via `BootWorkload.inherit_token`.
    pub expected_token: Option<String>,
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

        // Belt-and-suspenders: even with the token check in place, only
        // root should be able to open the socket. Workloads running as
        // non-root (future privilege-drop tier) can't bypass the token
        // check by guessing — they can't even connect.
        if let Err(e) = chmod_0600(&self.socket_path) {
            eprintln!("easyenclave: warning: chmod {} 0600: {e}", self.socket_path);
        }

        eprintln!("easyenclave: listening on {}", self.socket_path);

        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|e| format!("accept: {e}"))?;

            let deployments = self.deployments.clone();
            let attestation = self.attestation.clone();
            let gpu_evidence = self.gpu_evidence.clone();
            let start_time = self.start_time;
            let expected_token = self.expected_token.clone();

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
                        if !token_ok(&req, expected_token.as_deref()) {
                            let _ = writer
                                .write_all(b"{\"ok\":false,\"error\":\"unauthenticated\"}\n")
                                .await;
                            continue;
                        }
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

                    let response = handle_request(
                        &line,
                        &deployments,
                        &attestation,
                        gpu_evidence.as_ref(),
                        start_time,
                    )
                    .await;
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
    gpu_evidence: Option<&GpuBackend>,
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
        "health" => handle_health(deployments, attestation, gpu_evidence, start_time).await,
        "attest" => handle_attest(&req, attestation, gpu_evidence),
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
    gpu_evidence: Option<&GpuBackend>,
    start_time: std::time::Instant,
) -> Value {
    let count = deployments.lock().await.len();
    let mut response = json!({
        "ok": true,
        "attestation_type": attestation.attestation_type(),
        "workloads": count,
        "uptime_secs": start_time.elapsed().as_secs(),
    });
    if let Some(g) = gpu_evidence {
        response["gpu_evidence_type"] = json!(g.evidence_type());
    }
    response
}

fn handle_attest(
    req: &Value,
    attestation: &Arc<Box<dyn AttestationBackend>>,
    gpu_evidence: Option<&GpuBackend>,
) -> Value {
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
            let mut response = json!({
                "ok": true,
                "attestation_type": attestation.attestation_type(),
                "quote_format": "tdx",
                "quote_b64": q,
                "report_data_b64": base64::engine::general_purpose::STANDARD.encode(&report_data),
                "report_data_len": report_data.len(),
            });
            // GPU evidence is best-effort: TDX-only clients see no
            // change; failures degrade to a `nvgpu_error` field but
            // never escalate to top-level `ok: false`.
            if let Some(g) = gpu_evidence {
                response["evidence"] = collect_gpu_evidence_value(&***g);
            }
            response
        }
        Err(e) => json!({
            "ok": false,
            "attestation_type": attestation.attestation_type(),
            "error": e,
        }),
    }
}

fn collect_gpu_evidence_value(g: &dyn GpuEvidenceBackend) -> Value {
    use base64::Engine;
    match g.collect() {
        Ok(ev) => {
            let mut nvgpu = json!({
                "gpu_attestation_report_b64":
                    base64::engine::general_purpose::STANDARD.encode(&ev.gpu_report),
                "collected_at": ev.collected_at,
                "helper": g.evidence_type(),
            });
            if let Some(switch) = ev.switch_report {
                nvgpu["switch_attestation_report_b64"] =
                    json!(base64::engine::general_purpose::STANDARD.encode(&switch));
            }
            json!({ "nvgpu": nvgpu })
        }
        Err(e) => json!({ "nvgpu_error": e }),
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
    let app_preview = req
        .get("app_name")
        .and_then(|v| v.as_str())
        .unwrap_or("(none)");
    eprintln!("easyenclave: handle_deploy entered (app={app_preview})");
    let deploy_req: DeployRequest = match serde_json::from_value(req.clone()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("easyenclave: handle_deploy parse error: {e}");
            return json!({"ok": false, "error": format!("invalid deploy request: {e}")});
        }
    };

    let (id, status) = crate::workload::execute_deploy(deployments, deploy_req).await;
    eprintln!("easyenclave: handle_deploy → id={id} status={status}");
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

/// Constant-time-ish equality + `None`-means-unsealed logic. When
/// `expected` is `None` the socket is in "no seal" mode and every
/// request is accepted (matches pre-Tier-1 behaviour — useful for
/// local dev and upstream's existing standalone usage). When
/// `expected` is `Some(t)`, the caller must include a matching
/// `"token": "<t>"` field.
fn token_ok(req: &Value, expected: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    let Some(got) = req.get("token").and_then(|v| v.as_str()) else {
        return false;
    };
    constant_time_eq(got.as_bytes(), expected.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

/// `chmod 0600` on a path. Used right after `UnixListener::bind` so
/// only the owner (EE itself, UID 0) can connect. Combined with the
/// token check this makes local-admin access a two-factor gate.
fn chmod_0600(path: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serde_json::json;

    #[test]
    fn token_ok_accepts_when_no_seal() {
        // expected=None → pre-seal behaviour, every request passes.
        assert!(token_ok(&json!({}), None));
        assert!(token_ok(&json!({"method": "health"}), None));
    }

    #[test]
    fn token_ok_rejects_without_token() {
        assert!(!token_ok(&json!({"method": "health"}), Some("secret")));
    }

    #[test]
    fn token_ok_rejects_wrong_token() {
        assert!(!token_ok(
            &json!({"method": "health", "token": "nope"}),
            Some("secret"),
        ));
    }

    #[test]
    fn token_ok_accepts_matching_token() {
        assert!(token_ok(
            &json!({"method": "health", "token": "secret"}),
            Some("secret"),
        ));
    }

    #[test]
    fn constant_time_eq_matches_std_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"short", b"shorter"));
        assert!(constant_time_eq(b"", b""));
    }

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

    fn mock_attestation() -> Arc<Box<dyn AttestationBackend>> {
        use crate::attestation::testing::MockTdxBackend;
        let backend: Box<dyn AttestationBackend> = Box::new(MockTdxBackend::new());
        Arc::new(backend)
    }

    fn mock_gpu_ok() -> GpuBackend {
        use crate::attestation::testing::MockGpuBackend;
        let backend: Box<dyn GpuEvidenceBackend> = Box::new(MockGpuBackend::ok());
        Arc::new(backend)
    }

    fn mock_gpu_err() -> GpuBackend {
        use crate::attestation::testing::MockGpuBackend;
        let backend: Box<dyn GpuEvidenceBackend> = Box::new(MockGpuBackend::err("collector busy"));
        Arc::new(backend)
    }

    #[test]
    fn attest_without_gpu_backend_omits_evidence_field() {
        // Regression guard: TDX-only clients (e.g. private-claude) must
        // see the exact pre-change response shape.
        let req = json!({"method": "attest"});
        let resp = handle_attest(&req, &mock_attestation(), None);
        assert_eq!(resp["ok"], json!(true));
        assert_eq!(resp["attestation_type"], json!("tdx"));
        assert_eq!(resp["quote_format"], json!("tdx"));
        assert!(resp["quote_b64"].is_string());
        assert!(resp.get("evidence").is_none(), "got: {resp}");
    }

    #[test]
    fn attest_with_gpu_backend_includes_nvgpu_block() {
        let req = json!({"method": "attest"});
        let gpu = mock_gpu_ok();
        let resp = handle_attest(&req, &mock_attestation(), Some(&gpu));
        assert_eq!(resp["ok"], json!(true));
        let nvgpu = &resp["evidence"]["nvgpu"];
        assert!(nvgpu["gpu_attestation_report_b64"].is_string(), "{resp}");
        assert!(nvgpu["switch_attestation_report_b64"].is_string(), "{resp}");
        assert_eq!(nvgpu["helper"], json!("nvidia-cc"));
        assert!(nvgpu["collected_at"].is_number());
    }

    #[test]
    fn attest_gpu_failure_does_not_break_tdx_path() {
        let req = json!({"method": "attest"});
        let gpu = mock_gpu_err();
        let resp = handle_attest(&req, &mock_attestation(), Some(&gpu));
        // TDX path still succeeds.
        assert_eq!(resp["ok"], json!(true));
        assert!(resp["quote_b64"].is_string());
        // GPU failure surfaces as a structured error, not a top-level fail.
        assert_eq!(resp["evidence"]["nvgpu_error"], json!("collector busy"));
        assert!(resp["evidence"].get("nvgpu").is_none());
    }

    #[tokio::test]
    async fn health_surfaces_gpu_evidence_type_when_present() {
        let deployments: Deployments =
            std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
        let attestation = mock_attestation();
        let gpu = mock_gpu_ok();
        let start = std::time::Instant::now();

        let resp_with = handle_health(&deployments, &attestation, Some(&gpu), start).await;
        assert_eq!(resp_with["gpu_evidence_type"], json!("nvidia-cc"));

        let resp_without = handle_health(&deployments, &attestation, None, start).await;
        assert!(
            resp_without.get("gpu_evidence_type").is_none(),
            "{resp_without}"
        );
    }
}
