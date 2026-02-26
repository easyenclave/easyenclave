use anyhow::Result;
use axum::{
    extract::{Query, State},
    routing::{get, post},
    Json, Router,
};
use ee_attestation::generate_mock_attestation;
use ee_common::{
    api::{
        AgentHeartbeatRequest, AgentRegistrationRequest, DeployRequest, HealthResponse,
        UndeployRequest,
    },
    now_epoch_seconds,
};
use serde::Deserialize;
use serde_json::json;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{oneshot, watch, RwLock},
    task::JoinHandle,
};
use tracing::{error, warn};

#[derive(Clone, Debug)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub agent_id: String,
    pub datacenter: String,
    pub registration_target: Option<String>,
    pub heartbeat_interval: Duration,
    pub test_mode: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8081".parse().expect("valid default listen addr"),
            agent_id: "agent-local".to_string(),
            datacenter: "dev:local".to_string(),
            registration_target: None,
            heartbeat_interval: Duration::from_secs(10),
            test_mode: true,
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: Config,
    inner: Arc<RwLock<AgentState>>,
    client: reqwest::Client,
    listen_url: String,
}

#[derive(Default)]
struct AgentState {
    deployment: Option<String>,
}

pub struct AgentHandle {
    local_addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    stop_tx: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl AgentHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.local_addr)
    }

    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = self.stop_tx.send(true);
        while let Some(task) = self.tasks.pop() {
            let _ = task.await;
        }
    }
}

pub async fn start(config: Config) -> Result<AgentHandle> {
    let listener = TcpListener::bind(config.listen_addr).await?;
    let local_addr = listener.local_addr()?;

    let state = AppState {
        listen_url: format!("http://{local_addr}"),
        config,
        inner: Arc::new(RwLock::new(AgentState::default())),
        client: reqwest::Client::new(),
    };

    let router = Router::new()
        .route("/api/health", get(get_health))
        .route("/api/deploy", post(deploy))
        .route("/api/undeploy", post(undeploy))
        .with_state(state.clone());

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let (stop_tx, stop_rx) = watch::channel(false);

    let server_task = tokio::spawn(async move {
        let server = axum::serve(listener, router).with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        });
        if let Err(err) = server.await {
            error!("agent server failed: {err}");
        }
    });

    let registration_state = state.clone();
    let registration_task = tokio::spawn(async move {
        run_registration(registration_state, stop_rx).await;
    });

    Ok(AgentHandle {
        local_addr,
        shutdown_tx: Some(shutdown_tx),
        stop_tx,
        tasks: vec![server_task, registration_task],
    })
}

async fn run_registration(state: AppState, mut stop_rx: watch::Receiver<bool>) {
    let Some(target) = state.config.registration_target.clone() else {
        return;
    };

    loop {
        match register_once(&state, &target).await {
            Ok(()) => break,
            Err(err) => {
                warn!("agent registration failed, retrying: {err}");
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                    _ = stop_rx.changed() => {
                        if *stop_rx.borrow() {
                            return;
                        }
                    }
                }
            }
        }
    }

    let mut heartbeat = tokio::time::interval(state.config.heartbeat_interval);
    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                if let Err(err) = send_heartbeat(&state, &target).await {
                    warn!("heartbeat failed: {err}");
                }
            }
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    break;
                }
            }
        }
    }
}

async fn register_once(state: &AppState, target: &str) -> Result<()> {
    let attestation = Some(generate_mock_attestation(&state.config.agent_id));
    let req = AgentRegistrationRequest {
        agent_id: state.config.agent_id.clone(),
        listen_url: state.listen_url.clone(),
        datacenter: state.config.datacenter.clone(),
        attestation,
    };
    let endpoint = format!("{}/api/v1/agents/register", target.trim_end_matches('/'));
    state
        .client
        .post(endpoint)
        .json(&req)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

async fn send_heartbeat(state: &AppState, target: &str) -> Result<()> {
    let deployment = {
        let guard = state.inner.read().await;
        guard.deployment.clone()
    };

    let req = AgentHeartbeatRequest {
        healthy: true,
        deployment,
        attestation: if state.config.test_mode {
            None
        } else {
            Some(generate_mock_attestation(&state.config.agent_id))
        },
        timestamp: now_epoch_seconds(),
    };

    let endpoint = format!(
        "{}/api/v1/agents/{}/heartbeat",
        target.trim_end_matches('/'),
        state.config.agent_id
    );

    state
        .client
        .post(endpoint)
        .json(&req)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

#[derive(Deserialize)]
struct HealthQuery {
    attest: Option<bool>,
}

async fn get_health(
    State(state): State<AppState>,
    Query(query): Query<HealthQuery>,
) -> Json<HealthResponse> {
    let deployment = {
        let guard = state.inner.read().await;
        guard.deployment.clone()
    };

    let attestation = if query.attest.unwrap_or(false) {
        Some(generate_mock_attestation(&state.config.agent_id))
    } else {
        None
    };

    Json(HealthResponse {
        service: "agent".to_string(),
        status: "ok".to_string(),
        timestamp: now_epoch_seconds(),
        agent_id: Some(state.config.agent_id.clone()),
        deployment,
        attestation,
    })
}

async fn deploy(
    State(state): State<AppState>,
    Json(req): Json<DeployRequest>,
) -> Json<serde_json::Value> {
    let mut guard = state.inner.write().await;
    guard.deployment = Some(req.app_name);
    Json(json!({"ok": true}))
}

async fn undeploy(
    State(state): State<AppState>,
    Json(req): Json<UndeployRequest>,
) -> Json<serde_json::Value> {
    let mut guard = state.inner.write().await;
    if req.app_name.is_none() || guard.deployment.as_deref() == req.app_name.as_deref() {
        guard.deployment = None;
    }
    Json(json!({"ok": true}))
}
