//! Unix socket server -- newline-delimited JSON protocol.

use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use crate::attestation::AttestationBackend;
use crate::workload::{DeployRequest, Deployments};

pub struct SocketServer {
    pub socket_path: String,
    pub deployments: Deployments,
    pub attestation: Arc<dyn AttestationBackend>,
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

            tokio::spawn(serve_stream(stream, deployments, attestation, start_time));
        }
    }
}

async fn serve_stream(
    stream: tokio::net::UnixStream,
    deployments: Deployments,
    attestation: Arc<dyn AttestationBackend>,
    start_time: std::time::Instant,
) {
    serve_io(stream, deployments, attestation, start_time).await;
}

async fn serve_io<S>(
    stream: S,
    deployments: Deployments,
    attestation: Arc<dyn AttestationBackend>,
    start_time: std::time::Instant,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let response = handle_request(&line, &deployments, &attestation, start_time).await;
        let mut out = serde_json::to_string(&response)
            .unwrap_or_else(|_| r#"{"ok":false,"error":"serialize error"}"#.to_string());
        out.push('\n');
        if writer.write_all(out.as_bytes()).await.is_err() {
            break;
        }
    }
}

async fn handle_request(
    line: &str,
    deployments: &Deployments,
    attestation: &Arc<dyn AttestationBackend>,
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
    attestation: &Arc<dyn AttestationBackend>,
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

fn handle_attest(req: &Value, attestation: &Arc<dyn AttestationBackend>) -> Value {
    let nonce_b64 = req.get("nonce").and_then(|n| n.as_str()).unwrap_or("");
    let nonce_bytes = if nonce_b64.is_empty() {
        Vec::new()
    } else {
        use base64::Engine;
        match base64::engine::general_purpose::STANDARD.decode(nonce_b64) {
            Ok(bytes) => bytes,
            Err(e) => return json!({"ok": false, "error": format!("invalid nonce base64: {e}")}),
        }
    };

    let quote = if nonce_bytes.is_empty() {
        attestation.generate_quote_b64()
    } else {
        attestation.generate_quote_with_nonce(&nonce_bytes)
    };

    match quote {
        Some(q) => json!({"ok": true, "quote_b64": q}),
        None => {
            json!({"ok": true, "quote_b64": null, "attestation_type": attestation.attestation_type()})
        }
    }
}

async fn handle_deploy(req: &Value, deployments: &Deployments) -> Value {
    let deploy_req: DeployRequest = match serde_json::from_value(req.clone()) {
        Ok(r) => r,
        Err(e) => return json!({"ok": false, "error": format!("invalid deploy request: {e}")}),
    };

    match crate::workload::execute_deploy(deployments, deploy_req).await {
        Ok((id, status)) => json!({"ok": true, "id": id, "status": status}),
        Err(e) => json!({"ok": false, "error": e}),
    }
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

async fn handle_logs(req: &Value, deployments: &Deployments) -> Value {
    let id = match req.get("id").and_then(|i| i.as_str()) {
        Some(id) => id,
        None => return json!({"ok": false, "error": "missing id"}),
    };
    let tail = req.get("tail").and_then(|t| t.as_u64()).unwrap_or(100) as usize;

    let container_id = {
        let deps = deployments.lock().await;
        match deps.get(id) {
            Some(info) => info.container_id.clone(),
            None => return json!({"ok": false, "error": "deployment not found"}),
        }
    };

    match container_id {
        Some(cid) => match crate::container::logs(&cid, tail).await {
            Ok(lines) => json!({"ok": true, "lines": lines}),
            Err(e) => json!({"ok": false, "error": e}),
        },
        None => json!({"ok": true, "lines": [], "note": "process workload (no container logs)"}),
    }
}

#[cfg(test)]
mod tests {
    use super::{serve_io, SocketServer};
    use crate::attestation::AttestationBackend;
    use crate::workload::Deployments;
    use serde_json::Value;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::sync::Mutex;

    struct FakeAttestation;

    impl AttestationBackend for FakeAttestation {
        fn attestation_type(&self) -> &str {
            "tdx"
        }

        fn generate_quote_b64(&self) -> Option<String> {
            Some("quote".into())
        }

        fn generate_quote_with_nonce(&self, _nonce: &[u8]) -> Option<String> {
            Some("quote-with-nonce".into())
        }
    }

    async fn send_request(request: &str) -> Value {
        let deployments: Deployments = Arc::new(Mutex::new(HashMap::new()));
        let attestation: Arc<dyn AttestationBackend> = Arc::new(FakeAttestation);
        let (client, server) = tokio::io::duplex(4096);

        tokio::spawn(serve_io(
            server,
            deployments,
            attestation,
            std::time::Instant::now(),
        ));

        let (reader, mut writer) = tokio::io::split(client);
        writer
            .write_all(format!("{request}\n").as_bytes())
            .await
            .unwrap();
        let mut lines = BufReader::new(reader).lines();
        let response = lines.next_line().await.unwrap().unwrap();
        serde_json::from_str(&response).unwrap()
    }

    #[tokio::test]
    async fn health_request_works_over_real_stream_protocol() {
        let response = send_request(r#"{"method":"health"}"#).await;

        assert_eq!(response["ok"], true);
        assert_eq!(response["attestation_type"], "tdx");
        assert_eq!(response["workloads"], 0);
    }

    #[tokio::test]
    async fn deploy_rejects_empty_request_immediately() {
        let response = send_request(r#"{"method":"deploy"}"#).await;

        assert_eq!(response["ok"], false);
        assert_eq!(response["error"], "either image or cmd must be specified");
    }

    #[test]
    fn socket_server_holds_trait_object_without_boxing() {
        let deployments: Deployments = Arc::new(Mutex::new(HashMap::new()));
        let attestation: Arc<dyn AttestationBackend> = Arc::new(FakeAttestation);
        let server = SocketServer {
            socket_path: "/tmp/ignored.sock".into(),
            deployments,
            attestation,
            start_time: std::time::Instant::now(),
        };

        assert_eq!(server.attestation.attestation_type(), "tdx");
    }
}
