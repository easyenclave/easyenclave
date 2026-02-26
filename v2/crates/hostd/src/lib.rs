use anyhow::Result;
use axum::{extract::State, routing::get, Json, Router};
use ee_common::now_epoch_seconds;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    net::TcpListener,
    sync::{oneshot, RwLock},
    task::JoinHandle,
};
use tracing::error;

#[derive(Clone, Debug)]
pub struct Config {
    pub listen_addr: SocketAddr,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:9090".parse().expect("valid default listen addr"),
        }
    }
}

#[derive(Clone)]
struct AppState {
    inner: Arc<RwLock<HostState>>,
}

#[derive(Default)]
struct HostState {
    vms: Vec<VmInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VmInfo {
    pub vm_id: String,
    pub image: String,
    pub status: String,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateVmRequest {
    pub vm_id: String,
    pub image: String,
}

pub struct HostdHandle {
    local_addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl HostdHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = self.task.await;
    }
}

pub async fn start(config: Config) -> Result<HostdHandle> {
    let state = AppState {
        inner: Arc::new(RwLock::new(HostState::default())),
    };

    let router = Router::new()
        .route("/health", get(health))
        .route("/vms", get(list_vms).post(create_vm))
        .route("/resources", get(resources))
        .with_state(state);

    let listener = TcpListener::bind(config.listen_addr).await?;
    let local_addr = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let task = tokio::spawn(async move {
        let server = axum::serve(listener, router).with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        });
        if let Err(err) = server.await {
            error!("hostd server failed: {err}");
        }
    });

    Ok(HostdHandle {
        local_addr,
        shutdown_tx: Some(shutdown_tx),
        task,
    })
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({"status": "ok", "service": "hostd"}))
}

async fn list_vms(State(state): State<AppState>) -> Json<Vec<VmInfo>> {
    let guard = state.inner.read().await;
    Json(guard.vms.clone())
}

async fn create_vm(
    State(state): State<AppState>,
    Json(req): Json<CreateVmRequest>,
) -> Json<VmInfo> {
    let vm = VmInfo {
        vm_id: req.vm_id,
        image: req.image,
        status: "running".to_string(),
        created_at: now_epoch_seconds(),
    };

    let mut guard = state.inner.write().await;
    guard.vms.push(vm.clone());
    Json(vm)
}

async fn resources() -> Json<serde_json::Value> {
    Json(json!({
        "cpu_cores": 8,
        "memory_mb": 32768,
        "tdx_supported": true,
        "max_agent_vms": 4
    }))
}
