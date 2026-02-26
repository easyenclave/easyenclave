use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use ee_attestation::verify_attestation;
use ee_common::{
    api::{
        AgentHeartbeatRequest, AgentListResponse, AgentRegistrationRequest,
        AgentRegistrationResponse, AgentSnapshot, AggregatorListResponse,
        AggregatorRegistrationRequest, AggregatorRegistrationResponse, AggregatorSnapshot,
        AggregatorStateResponse, ErrorResponse, HealthResponse,
    },
    now_epoch_seconds,
};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{oneshot, watch, RwLock},
    task::JoinHandle,
};
use tracing::{error, warn};

#[derive(Clone, Debug)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub scrape_interval: Duration,
    pub trusted_mrtds: HashSet<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:7000".parse().expect("valid default listen addr"),
            scrape_interval: Duration::from_secs(10),
            trusted_mrtds: HashSet::new(),
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: Config,
    inner: Arc<RwLock<ControlPlaneState>>,
    client: reqwest::Client,
}

#[derive(Default)]
struct ControlPlaneState {
    agents: HashMap<String, AgentSnapshot>,
    aggregators: HashMap<String, AggregatorSnapshot>,
}

pub struct ControlPlaneHandle {
    local_addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    stop_tx: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl ControlPlaneHandle {
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

pub async fn start(config: Config) -> Result<ControlPlaneHandle> {
    let state = AppState {
        config,
        inner: Arc::new(RwLock::new(ControlPlaneState::default())),
        client: reqwest::Client::new(),
    };

    let router = Router::new()
        .route("/health", get(get_health))
        .route("/api/v1/agents/register", post(register_agent))
        .route("/api/v1/agents/:agent_id/heartbeat", post(agent_heartbeat))
        .route("/api/v1/agents", get(list_agents))
        .route("/api/v1/aggregators/register", post(register_aggregator))
        .route("/api/v1/aggregators", get(list_aggregators))
        .with_state(state.clone());

    let listener = TcpListener::bind(state.config.listen_addr).await?;
    let local_addr = listener.local_addr()?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let (stop_tx, stop_rx) = watch::channel(false);

    let server_task = tokio::spawn(async move {
        let server = axum::serve(listener, router).with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        });
        if let Err(err) = server.await {
            error!("cp server failed: {err}");
        }
    });

    let scraper_state = state.clone();
    let scraper_task = tokio::spawn(async move {
        run_scraper(scraper_state, stop_rx).await;
    });

    Ok(ControlPlaneHandle {
        local_addr,
        shutdown_tx: Some(shutdown_tx),
        stop_tx,
        tasks: vec![server_task, scraper_task],
    })
}

async fn run_scraper(state: AppState, mut stop_rx: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(state.config.scrape_interval);
    loop {
        tokio::select! {
            _ = interval.tick() => scrape_once(&state).await,
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    break;
                }
            }
        }
    }
}

async fn scrape_once(state: &AppState) {
    let aggregators = {
        let guard = state.inner.read().await;
        guard.aggregators.values().cloned().collect::<Vec<_>>()
    };

    for aggregator in aggregators {
        let endpoint = format!("{}/api/state", aggregator.listen_url.trim_end_matches('/'));
        match state.client.get(endpoint).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<AggregatorStateResponse>().await {
                    Ok(snapshot) => {
                        let mut guard = state.inner.write().await;
                        for agent in snapshot.agents {
                            guard.agents.insert(agent.agent_id.clone(), agent);
                        }
                    }
                    Err(err) => warn!("failed to parse aggregator state: {err}"),
                }
            }
            Ok(resp) => warn!("aggregator scrape failed with status {}", resp.status()),
            Err(err) => warn!("aggregator scrape request failed: {err}"),
        }
    }
}

async fn get_health() -> Json<HealthResponse> {
    Json(HealthResponse {
        service: "cp".to_string(),
        status: "ok".to_string(),
        timestamp: now_epoch_seconds(),
        agent_id: None,
        deployment: None,
        attestation: None,
    })
}

async fn register_agent(
    State(state): State<AppState>,
    Json(req): Json<AgentRegistrationRequest>,
) -> Result<Json<AgentRegistrationResponse>, (StatusCode, Json<ErrorResponse>)> {
    if let Some(attestation) = req.attestation.as_ref() {
        verify_attestation(attestation, &state.config.trusted_mrtds).map_err(invalid_request)?;
    }

    let now = now_epoch_seconds();
    let snapshot = AgentSnapshot {
        agent_id: req.agent_id.clone(),
        listen_url: req.listen_url,
        datacenter: req.datacenter,
        source: "direct".to_string(),
        healthy: true,
        attested: req.attestation.is_some(),
        deployment: None,
        last_seen: now,
    };

    let mut guard = state.inner.write().await;
    guard.agents.insert(req.agent_id.clone(), snapshot);

    Ok(Json(AgentRegistrationResponse {
        accepted: true,
        agent_secret: format!("agent-secret-{}", req.agent_id),
    }))
}

async fn agent_heartbeat(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(req): Json<AgentHeartbeatRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if let Some(attestation) = req.attestation.as_ref() {
        verify_attestation(attestation, &state.config.trusted_mrtds).map_err(invalid_request)?;
    }

    let mut guard = state.inner.write().await;
    let existing = guard.agents.get(&agent_id).cloned();
    let mut snapshot = existing.unwrap_or(AgentSnapshot {
        agent_id: agent_id.clone(),
        listen_url: String::new(),
        datacenter: "unknown".to_string(),
        source: "direct".to_string(),
        healthy: req.healthy,
        attested: req.attestation.is_some(),
        deployment: req.deployment.clone(),
        last_seen: req.timestamp,
    });

    snapshot.healthy = req.healthy;
    snapshot.attested = req.attestation.is_some() || snapshot.attested;
    snapshot.deployment = req.deployment;
    snapshot.last_seen = req.timestamp;

    guard.agents.insert(agent_id, snapshot);
    Ok(Json(serde_json::json!({"ok": true})))
}

async fn list_agents(State(state): State<AppState>) -> Json<AgentListResponse> {
    let guard = state.inner.read().await;
    let agents = guard.agents.values().cloned().collect::<Vec<_>>();
    Json(AgentListResponse {
        total: agents.len(),
        agents,
    })
}

async fn register_aggregator(
    State(state): State<AppState>,
    Json(req): Json<AggregatorRegistrationRequest>,
) -> Json<AggregatorRegistrationResponse> {
    let snapshot = AggregatorSnapshot {
        aggregator_id: req.aggregator_id.clone(),
        listen_url: req.listen_url,
        datacenter: req.datacenter,
        last_seen: now_epoch_seconds(),
    };

    let mut guard = state.inner.write().await;
    guard.aggregators.insert(req.aggregator_id, snapshot);

    Json(AggregatorRegistrationResponse { accepted: true })
}

async fn list_aggregators(State(state): State<AppState>) -> Json<AggregatorListResponse> {
    let guard = state.inner.read().await;
    let aggregators = guard.aggregators.values().cloned().collect::<Vec<_>>();
    Json(AggregatorListResponse {
        total: aggregators.len(),
        aggregators,
    })
}

fn invalid_request(err: anyhow::Error) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: err.to_string(),
        }),
    )
}
