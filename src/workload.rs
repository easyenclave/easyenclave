//! Workload deployment and lifecycle management.
//!
//! A workload is either a command to run, or a GitHub release asset to
//! download and then run. No containers, no OCI — the asset is a static
//! binary, treated as a plain process. Fetch-only workloads (github_release
//! present, cmd empty) just prime the bin dir with a tool for other
//! workloads to shell out to (e.g. cloudflared).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::capture::CaptureSink;
use crate::process;
use crate::release::{self, GithubRelease};

const BIN_DIR: &str = "/var/lib/easyenclave/bin";

/// Reads `EE_CAPTURE_SOCKET`; when set, every spawned workload's
/// stdin/stdout is teed to this unix-domain socket as LDJSON records.
/// See [`capture`](crate::capture).
fn capture_socket_path() -> Option<PathBuf> {
    std::env::var_os("EE_CAPTURE_SOCKET").map(PathBuf::from)
}

#[derive(Debug, Clone, Serialize)]
pub struct DeploymentInfo {
    pub id: String,
    pub pid: Option<u32>,
    pub app_name: String,
    /// Human-readable label describing what this deployment is —
    /// "owner/repo@tag" for github_release, or the command line for cmd.
    pub source: String,
    /// "deploying", "running", "completed", "failed", "stopped"
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    pub started_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeployRequest {
    #[serde(default)]
    pub cmd: Vec<String>,
    #[serde(default)]
    pub env: Option<Vec<String>>,
    #[serde(default)]
    pub app_name: Option<String>,
    #[serde(default)]
    pub tty: bool,
    /// Fetch a static binary from a GitHub release before starting.
    #[serde(default)]
    pub github_release: Option<GithubRelease>,
}

pub type Deployments = Arc<Mutex<HashMap<String, DeploymentInfo>>>;

// ── Deploy ───────────────────────────────────────────────────────────────────

pub async fn execute_deploy(deployments: &Deployments, req: DeployRequest) -> (String, String) {
    let dep_id = uuid::Uuid::new_v4().to_string();
    let app_name = req.app_name.clone().unwrap_or_else(|| "unnamed".into());

    let source = if let Some(ref gh) = req.github_release {
        format!("{}@{}", gh.repo, gh.tag.as_deref().unwrap_or("latest"))
    } else {
        req.cmd.join(" ")
    };

    let info = DeploymentInfo {
        id: dep_id.clone(),
        pid: None,
        app_name: app_name.clone(),
        source,
        status: "deploying".into(),
        error_message: None,
        started_at: chrono::Utc::now().to_rfc3339(),
    };
    deployments.lock().await.insert(dep_id.clone(), info);

    let return_id = dep_id.clone();
    let deployments_clone = deployments.clone();
    tokio::spawn(async move {
        run_deploy(deployments_clone, dep_id, app_name, req).await;
    });

    (return_id, "deploying".into())
}

async fn run_deploy(
    deployments: Deployments,
    dep_id: String,
    app_name: String,
    req: DeployRequest,
) {
    // Stop prior deployments for this app.
    stop_old_for_app(&deployments, &app_name, &dep_id).await;

    let has_gh = req.github_release.is_some();
    let has_cmd = !req.cmd.is_empty();

    if has_gh && !has_cmd {
        // Fetch-only: download the binary, mark completed. Its presence
        // on PATH is what other workloads need (e.g. cloudflared).
        match fetch_release(req.github_release.as_ref().unwrap()).await {
            Ok(path) => {
                eprintln!(
                    "easyenclave: fetched {} -> {} (fetch-only)",
                    app_name,
                    path.display()
                );
                let mut deps = deployments.lock().await;
                if let Some(info) = deps.get_mut(&dep_id) {
                    info.status = "completed".into();
                }
            }
            Err(e) => set_deploy_failed(&deployments, &dep_id, &e).await,
        }
    } else if has_gh {
        // Fetch then run. If `cmd` starts with the asset name (or rename),
        // we treat it as "use the fetched binary" and rewrite to the full
        // path. Otherwise we assume cmd[0] is already on PATH.
        let gh = req.github_release.as_ref().unwrap();
        match fetch_release(gh).await {
            Ok(path) => spawn_from_cmd(&deployments, &dep_id, &app_name, &req, Some(&path)).await,
            Err(e) => set_deploy_failed(&deployments, &dep_id, &e).await,
        }
    } else if has_cmd {
        spawn_from_cmd(&deployments, &dep_id, &app_name, &req, None).await;
    } else {
        set_deploy_failed(
            &deployments,
            &dep_id,
            "neither github_release nor cmd specified",
        )
        .await;
    }
}

/// Spawn a command. If `binary_override` is Some, cmd[0] is replaced with it.
async fn spawn_from_cmd(
    deployments: &Deployments,
    dep_id: &str,
    app_name: &str,
    req: &DeployRequest,
    binary_override: Option<&PathBuf>,
) {
    let program_owned: String = if let Some(b) = binary_override {
        b.to_string_lossy().into_owned()
    } else {
        req.cmd[0].clone()
    };
    let args: Vec<&str> = req.cmd.iter().skip(1).map(|s| s.as_str()).collect();

    // If EE_CAPTURE_SOCKET is set, open a per-workload connection to it
    // and emit a `spawn` record before the child starts. The sink is
    // cloned into the tee tasks (so each stdout/stderr line becomes an
    // `out` record) and moved into the wait task (so we emit `exit`
    // when the child terminates). A failed connect falls back to
    // running without capture — best-effort tee, not a hard dependency.
    let capture = if let Some(sock) = capture_socket_path() {
        let id = format!(
            "{}-{}",
            app_name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        );
        let argv: Vec<String> = std::iter::once(program_owned.clone())
            .chain(args.iter().map(|s| s.to_string()))
            .collect();
        CaptureSink::connect(&sock, id, &argv, None).await
    } else {
        None
    };

    let result = if let Some(env_list) = &req.env {
        let env_map = parse_env_list(env_list);
        process::spawn_command_with_env(
            &program_owned,
            &args,
            req.tty,
            &env_map,
            app_name,
            capture.clone(),
        )
        .await
    } else {
        process::spawn_command(&program_owned, &args, req.tty, app_name, capture.clone()).await
    };

    match result {
        Ok(process::SpawnedChild {
            mut child,
            tee_handles,
        }) => {
            let pid = child.id();
            eprintln!("easyenclave: deployment {dep_id} running (pid={pid:?})");
            let mut deps = deployments.lock().await;
            if let Some(info) = deps.get_mut(dep_id) {
                info.pid = pid;
                info.status = "running".into();
            }
            drop(deps);
            tokio::spawn(async move {
                let status = child.wait().await;
                // Wait for the tee tasks to finish draining stdout/stderr
                // before emitting the final `exit` record — otherwise a
                // workload's last lines lose the race and get committed
                // after the block's closing bookmark.
                for h in tee_handles {
                    let _ = h.await;
                }
                if let Some(sink) = capture {
                    let code = status.ok().and_then(|s| s.code()).unwrap_or(-1);
                    sink.exit(code).await;
                }
            });
        }
        Err(e) => set_deploy_failed(deployments, dep_id, &e).await,
    }
}

async fn fetch_release(gh: &GithubRelease) -> Result<PathBuf, String> {
    let gh_clone = gh.clone();
    tokio::task::spawn_blocking(move || release::download(&gh_clone, BIN_DIR))
        .await
        .map_err(|e| format!("fetch task: {e}"))?
}

fn parse_env_list(env_list: &[String]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for e in env_list {
        if let Some((k, v)) = e.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    map
}

async fn stop_old_for_app(deployments: &Deployments, app_name: &str, current_id: &str) {
    let old: Vec<(String, Option<u32>)> = {
        let deps = deployments.lock().await;
        deps.values()
            .filter(|d| d.app_name == app_name && d.id != current_id)
            .map(|d| (d.id.clone(), d.pid))
            .collect()
    };
    for (id, pid) in old {
        if let Some(p) = pid {
            let _ = process::kill_process(p).await;
        }
        deployments.lock().await.remove(&id);
    }
}

async fn set_deploy_failed(deployments: &Deployments, dep_id: &str, error: &str) {
    eprintln!("easyenclave: deployment {dep_id} failed: {error}");
    let mut deps = deployments.lock().await;
    if let Some(info) = deps.get_mut(dep_id) {
        info.status = "failed".into();
        info.error_message = Some(error.to_string());
    }
}

// ── Stop ─────────────────────────────────────────────────────────────────────

pub async fn execute_stop(deployments: &Deployments, id: &str) -> Result<(), String> {
    let pid = {
        let deps = deployments.lock().await;
        let info = deps.get(id).ok_or("deployment not found")?;
        if info.status != "running" && info.status != "deploying" {
            return Err(format!(
                "cannot stop deployment in '{}' status",
                info.status
            ));
        }
        info.pid
    };

    if let Some(p) = pid {
        process::kill_process(p).await?;
    }

    let mut deps = deployments.lock().await;
    if let Some(info) = deps.get_mut(id) {
        info.status = "stopped".into();
    }
    Ok(())
}

pub async fn stop_all(deployments: &Deployments) {
    let ids: Vec<String> = {
        let deps = deployments.lock().await;
        deps.values()
            .filter(|d| d.status == "running" || d.status == "deploying")
            .map(|d| d.id.clone())
            .collect()
    };
    for id in ids {
        if let Err(e) = execute_stop(deployments, &id).await {
            eprintln!("easyenclave: stop {id}: {e}");
        }
    }
}
