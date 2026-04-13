//! Workload deployment and lifecycle management.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::container;
use crate::process;

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct DeploymentInfo {
    pub id: String,
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    pub app_name: String,
    pub image: String,
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
    pub image: Option<String>,
    #[serde(default)]
    pub env: Option<Vec<String>>,
    #[serde(default)]
    pub volumes: Option<Vec<String>>,
    #[serde(default)]
    pub app_name: Option<String>,
    #[serde(default)]
    pub tty: bool,
    /// Commands to exec inside the container after it starts.
    #[serde(default)]
    pub post_deploy: Option<Vec<Vec<String>>>,
    /// Run the OCI image natively (extract binary, exec on host).
    #[serde(default)]
    pub native: bool,
}

pub type Deployments = Arc<Mutex<HashMap<String, DeploymentInfo>>>;

// ── Deploy ───────────────────────────────────────────────────────────────────

/// Start a deployment. Spawns run_deploy on tokio and returns immediately
/// with (deployment_id, "deploying").
pub async fn execute_deploy(deployments: &Deployments, req: DeployRequest) -> (String, String) {
    let dep_id = uuid::Uuid::new_v4().to_string();
    let app_name = req.app_name.clone().unwrap_or_else(|| "unnamed".into());

    let image_label = if let Some(ref img) = req.image {
        img.clone()
    } else {
        req.cmd.join(" ")
    };

    let info = DeploymentInfo {
        id: dep_id.clone(),
        pid: None,
        container_id: None,
        app_name: app_name.clone(),
        image: image_label,
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
    // Stop old workloads for same app
    {
        let deps = deployments.lock().await;
        let old: Vec<(String, Option<u32>, Option<String>)> = deps
            .values()
            .filter(|d| d.app_name == app_name && d.id != dep_id)
            .map(|d| (d.id.clone(), d.pid, d.container_id.clone()))
            .collect();
        drop(deps);
        for (old_id, old_pid, old_cid) in old {
            if let Some(cid) = old_cid {
                let _ = container::stop(&cid).await;
            } else if let Some(pid) = old_pid {
                let _ = process::kill_process(pid).await;
            }
            deployments.lock().await.remove(&old_id);
        }
    }

    if req.native && req.image.is_some() {
        // Native path: pull OCI image, unpack layers, run entrypoint
        // directly on the host. Full access to host filesystem + sockets.
        let image = req.image.as_ref().unwrap();
        match container::pull_native(image, &app_name).await {
            Ok((entrypoint, image_env)) => {
                // Merge env: image defaults + workload overrides
                let mut env_map: HashMap<String, String> = HashMap::new();
                for e in &image_env {
                    if let Some((k, v)) = e.split_once('=') {
                        env_map.insert(k.to_string(), v.to_string());
                    }
                }
                if let Some(extra) = &req.env {
                    for e in extra {
                        if let Some((k, v)) = e.split_once('=') {
                            env_map.insert(k.to_string(), v.to_string());
                        }
                    }
                }

                let program = &entrypoint[0];
                let args: Vec<&str> = entrypoint[1..].iter().map(|s| s.as_str()).collect();
                match process::spawn_command_with_env(program, &args, false, &env_map).await {
                    Ok(mut child) => {
                        let pid = child.id();
                        eprintln!("easyenclave: deployment {dep_id} running native (pid={pid:?})");
                        let mut deps = deployments.lock().await;
                        if let Some(info) = deps.get_mut(&dep_id) {
                            info.pid = pid;
                            info.status = "running".into();
                        }
                        drop(deps);
                        tokio::spawn(async move {
                            let _ = child.wait().await;
                        });
                    }
                    Err(e) => {
                        set_deploy_failed(&deployments, &dep_id, &e).await;
                    }
                }
            }
            Err(e) => {
                set_deploy_failed(&deployments, &dep_id, &e).await;
            }
        }
    } else if let Some(ref image) = req.image {
        // Container path
        match container::pull_and_run(image, &app_name, req.env, req.volumes, true).await {
            Ok(container_id) => {
                eprintln!("easyenclave: deployment {dep_id} running (container={container_id})");
                let mut deps = deployments.lock().await;
                if let Some(info) = deps.get_mut(&dep_id) {
                    info.container_id = Some(container_id.clone());
                    info.status = "running".into();
                }
                drop(deps);

                // Run post-deploy commands inside the container
                if let Some(ref commands) = req.post_deploy {
                    // Wait for container to be ready
                    for _ in 0..60 {
                        if container::is_running(&container_id).await {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }

                    for cmd in commands {
                        if cmd.is_empty() {
                            continue;
                        }
                        eprintln!("easyenclave: post-deploy exec: {}", cmd.join(" "));
                        match container::exec(&app_name, cmd).await {
                            Ok((code, stdout, stderr)) => {
                                if code != 0 {
                                    eprintln!(
                                        "easyenclave: post-deploy cmd failed (exit {}): {}{}",
                                        code,
                                        stdout.trim(),
                                        if stderr.is_empty() {
                                            String::new()
                                        } else {
                                            format!(" stderr: {}", stderr.trim())
                                        }
                                    );
                                    set_deploy_failed(
                                        &deployments,
                                        &dep_id,
                                        &format!(
                                            "post-deploy failed: {} (exit {code})",
                                            cmd.join(" ")
                                        ),
                                    )
                                    .await;
                                    return;
                                }
                                if !stdout.trim().is_empty() {
                                    eprintln!("easyenclave: post-deploy: {}", stdout.trim());
                                }
                            }
                            Err(e) => {
                                set_deploy_failed(
                                    &deployments,
                                    &dep_id,
                                    &format!("post-deploy exec error: {e}"),
                                )
                                .await;
                                return;
                            }
                        }
                    }
                    eprintln!("easyenclave: post-deploy commands complete for {app_name}");
                }
            }
            Err(e) => {
                set_deploy_failed(&deployments, &dep_id, &e).await;
            }
        }
    } else if !req.cmd.is_empty() {
        // Process path
        let program = &req.cmd[0];
        let args: Vec<&str> = req.cmd[1..].iter().map(|s| s.as_str()).collect();
        match process::spawn_command(program, &args, req.tty).await {
            Ok(mut child) => {
                let pid = child.id();
                eprintln!("easyenclave: deployment {dep_id} running (pid={pid:?})");
                let mut deps = deployments.lock().await;
                if let Some(info) = deps.get_mut(&dep_id) {
                    info.pid = pid;
                    info.status = "running".into();
                }
                drop(deps);

                // Wait for process in background
                tokio::spawn(async move {
                    let _ = child.wait().await;
                });
            }
            Err(e) => {
                set_deploy_failed(&deployments, &dep_id, &e).await;
            }
        }
    } else {
        set_deploy_failed(&deployments, &dep_id, "neither image nor cmd specified").await;
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
    let (pid, container_id) = {
        let deps = deployments.lock().await;
        let info = deps.get(id).ok_or("deployment not found")?;
        if info.status != "running" && info.status != "deploying" {
            return Err(format!(
                "cannot stop deployment in '{}' status",
                info.status
            ));
        }
        (info.pid, info.container_id.clone())
    };

    if let Some(cid) = container_id {
        container::stop(&cid).await?;
    } else if let Some(pid) = pid {
        process::kill_process(pid).await?;
    }

    let mut deps = deployments.lock().await;
    if let Some(info) = deps.get_mut(id) {
        info.status = "stopped".into();
    }
    Ok(())
}

/// Stop all running deployments (used during shutdown).
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
