use anyhow::Result;
use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use ee_attestation::verify_attestation;
use ee_common::{
    api::{
        AgentHeartbeatRequest, AgentRegistrationRequest, AgentRegistrationResponse, AgentSnapshot,
        AggregatorRegistrationRequest, AggregatorStateResponse, DeployRequest, DeployResponse,
        HealthResponse, UndeployRequest,
    },
    now_epoch_seconds,
};
use serde_json::json;
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
use tracing::{debug, error, warn};

#[derive(Clone, Debug)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub aggregator_id: String,
    pub datacenter: String,
    pub cp_url: Option<String>,
    pub scrape_token: String,
    pub health_interval: Duration,
    pub attestation_interval: Duration,
    pub trusted_mrtds: HashSet<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:7100".parse().expect("valid default listen addr"),
            aggregator_id: "agg-local".to_string(),
            datacenter: "dev:local".to_string(),
            cp_url: None,
            scrape_token: "dev-scrape-token".to_string(),
            health_interval: Duration::from_secs(15),
            attestation_interval: Duration::from_secs(300),
            trusted_mrtds: HashSet::new(),
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: Config,
    inner: Arc<RwLock<AggregatorState>>,
    client: reqwest::Client,
    listen_url: String,
}

#[derive(Default)]
struct AggregatorState {
    agents: HashMap<String, AgentSnapshot>,
}

pub struct AggregatorHandle {
    local_addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    stop_tx: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl AggregatorHandle {
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

pub async fn start(config: Config) -> Result<AggregatorHandle> {
    let listener = TcpListener::bind(config.listen_addr).await?;
    let local_addr = listener.local_addr()?;

    let state = AppState {
        config,
        inner: Arc::new(RwLock::new(AggregatorState::default())),
        client: reqwest::Client::new(),
        listen_url: format!("http://{local_addr}"),
    };

    let router = Router::new()
        .route("/health", get(get_health))
        .route("/api/v1/agents/register", post(register_agent))
        .route("/api/v1/agents/:agent_id/heartbeat", post(agent_heartbeat))
        .route("/api/state", get(get_state))
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
            error!("aggregator server failed: {err}");
        }
    });

    let control_state = state.clone();
    let mut control_stop_rx = stop_rx.clone();
    let control_task = tokio::spawn(async move {
        if let Some(cp_url) = &control_state.config.cp_url {
            loop {
                if let Err(err) = register_with_cp(&control_state, cp_url).await {
                    warn!("aggregator registration with cp failed: {err}");
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {}
                    _ = control_stop_rx.changed() => {
                        if *control_stop_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        }
    });

    let scraper_state = state.clone();
    let scraper_task = tokio::spawn(async move {
        run_scraper(scraper_state, stop_rx).await;
    });

    Ok(AggregatorHandle {
        local_addr,
        shutdown_tx: Some(shutdown_tx),
        stop_tx,
        tasks: vec![server_task, control_task, scraper_task],
    })
}

async fn register_with_cp(state: &AppState, cp_url: &str) -> Result<()> {
    let req = AggregatorRegistrationRequest {
        aggregator_id: state.config.aggregator_id.clone(),
        listen_url: state.listen_url.clone(),
        datacenter: state.config.datacenter.clone(),
        scrape_token: state.config.scrape_token.clone(),
    };
    let endpoint = format!(
        "{}/api/v1/aggregators/register",
        cp_url.trim_end_matches('/')
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

async fn run_scraper(state: AppState, mut stop_rx: watch::Receiver<bool>) {
    let mut health_interval = tokio::time::interval(state.config.health_interval);
    let mut attestation_interval = tokio::time::interval(state.config.attestation_interval);

    loop {
        tokio::select! {
            _ = health_interval.tick() => {
                scrape_agents(&state, false).await;
            }
            _ = attestation_interval.tick() => {
                scrape_agents(&state, true).await;
            }
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    break;
                }
            }
        }
    }
}

async fn scrape_agents(state: &AppState, with_attestation: bool) {
    let known_agents = {
        let guard = state.inner.read().await;
        guard.agents.values().cloned().collect::<Vec<_>>()
    };

    for mut agent in known_agents {
        let suffix = if with_attestation {
            "/api/health?attest=true"
        } else {
            "/api/health"
        };

        let url = format!("{}{}", agent.listen_url.trim_end_matches('/'), suffix);
        match state.client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.json::<HealthResponse>().await {
                Ok(health) => {
                    if with_attestation {
                        if let Some(attestation) = health.attestation.as_ref() {
                            if let Err(err) =
                                verify_attestation(attestation, &state.config.trusted_mrtds)
                            {
                                warn!("agent {} attestation rejected: {err}", agent.agent_id);
                                agent.attested = false;
                            } else {
                                agent.attested = true;
                            }
                        }
                    }
                    agent.healthy = health.status == "ok";
                    agent.deployment = health.deployment;
                    agent.last_seen = now_epoch_seconds();
                    let mut guard = state.inner.write().await;
                    guard.agents.insert(agent.agent_id.clone(), agent);
                }
                Err(err) => warn!("failed to parse agent health response: {err}"),
            },
            Ok(resp) => {
                debug!("agent health scrape failed with status {}", resp.status());
            }
            Err(err) => {
                debug!("agent health scrape request failed: {err}");
            }
        }
    }
}

async fn get_health() -> Json<HealthResponse> {
    Json(HealthResponse {
        service: "aggregator".to_string(),
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
) -> Json<AgentRegistrationResponse> {
    let now = now_epoch_seconds();
    let snapshot = AgentSnapshot {
        agent_id: req.agent_id.clone(),
        listen_url: req.listen_url,
        datacenter: req.datacenter,
        source: state.config.aggregator_id.clone(),
        healthy: true,
        attested: req.attestation.is_some(),
        deployment: None,
        last_seen: now,
    };

    let mut guard = state.inner.write().await;
    guard.agents.insert(req.agent_id.clone(), snapshot);

    Json(AgentRegistrationResponse {
        accepted: true,
        agent_secret: format!("agent-secret-{}", req.agent_id),
    })
}

async fn agent_heartbeat(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(req): Json<AgentHeartbeatRequest>,
) -> Json<serde_json::Value> {
    let mut guard = state.inner.write().await;
    if let Some(agent) = guard.agents.get_mut(&agent_id) {
        agent.healthy = req.healthy;
        agent.deployment = req.deployment;
        if req.attestation.is_some() {
            agent.attested = true;
        }
        agent.last_seen = req.timestamp;
    }
    Json(json!({"ok": true}))
}

async fn get_state(State(state): State<AppState>) -> Json<AggregatorStateResponse> {
    let guard = state.inner.read().await;
    let agents = guard.agents.values().cloned().collect::<Vec<_>>();
    Json(AggregatorStateResponse {
        aggregator_id: state.config.aggregator_id.clone(),
        collected_at: now_epoch_seconds(),
        agents,
    })
}

async fn deploy(
    State(state): State<AppState>,
    Json(req): Json<DeployRequest>,
) -> Json<DeployResponse> {
    relay_to_agents(
        state,
        req.target_agent_id.clone(),
        "/api/deploy",
        serde_json::to_value(&req).expect("serialize deploy request"),
    )
    .await
}

async fn undeploy(
    State(state): State<AppState>,
    Json(req): Json<UndeployRequest>,
) -> Json<DeployResponse> {
    relay_to_agents(
        state,
        req.target_agent_id.clone(),
        "/api/undeploy",
        serde_json::to_value(&req).expect("serialize undeploy request"),
    )
    .await
}

async fn relay_to_agents(
    state: AppState,
    target_agent_id: Option<String>,
    endpoint: &str,
    body: serde_json::Value,
) -> Json<DeployResponse> {
    let candidates = {
        let guard = state.inner.read().await;
        guard
            .agents
            .values()
            .filter(|agent| {
                target_agent_id
                    .as_ref()
                    .map(|target| target == &agent.agent_id)
                    .unwrap_or(true)
            })
            .cloned()
            .collect::<Vec<_>>()
    };

    let mut dispatched = 0usize;
    let mut failed = 0usize;

    for agent in candidates {
        let url = format!("{}{}", agent.listen_url.trim_end_matches('/'), endpoint);
        match state.client.post(url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => dispatched += 1,
            _ => failed += 1,
        }
    }

    Json(DeployResponse { dispatched, failed })
}
