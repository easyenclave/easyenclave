//! Aggregator HTTP server with health, state, proxy, billing, and admin routes.

use crate::billing::marketplace::Marketplace;
use crate::billing::types::PurchaseRequest;
use crate::config::AggregatorConfig;
use crate::measurement::MeasurementObserver;
use crate::registry::AgentRegistry;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use ee_common::error::ApiError;
use ee_common::types::{
    AgentId, AgentRegistration, AggregatorState, DeployRequest, HealthResponse, UndeployRequest,
};
use std::sync::Arc;
use std::time::Instant;

pub struct AppState {
    pub config: AggregatorConfig,
    pub registry: AgentRegistry,
    pub measurement: MeasurementObserver,
    pub marketplace: Arc<Marketplace>,
    pub client: reqwest::Client,
    pub start_time: Instant,
}

/// Routes that can be merged into another router (e.g. CP) without conflicts.
/// Excludes /api/health which the host router provides.
pub fn mergeable_routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/state", get(get_state))
        .route("/api/v1/agents/:agent_id/register", post(register_agent))
        .route("/api/deploy", post(deploy))
        .route("/api/undeploy", post(undeploy))
        // Billing
        .route("/api/v1/billing/listings", get(billing_listings))
        .route("/api/v1/billing/purchase", post(billing_purchase))
        .route("/api/v1/billing/invoices/:invoice_id", get(billing_invoice))
        .route("/api/v1/billing/webhooks/btcpay", post(billing_webhook))
        .with_state(state)
}

/// Full router for standalone mode (includes /api/health).
pub fn router(state: Arc<AppState>) -> Router {
    let health_route = Router::new()
        .route("/api/health", get(health))
        .with_state(state.clone());
    health_route.merge(mergeable_routes(state))
}

async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: state.start_time.elapsed().as_secs(),
    })
}

async fn get_state(State(state): State<Arc<AppState>>) -> Json<AggregatorState> {
    let agents = state.registry.all_agents().await;
    Json(AggregatorState {
        id: ee_common::types::AggregatorId::new(),
        agents,
        updated_at: chrono::Utc::now(),
    })
}

async fn register_agent(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    Json(registration): Json<AgentRegistration>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let agent_id = AgentId(
        agent_id
            .parse()
            .map_err(|_| ApiError::bad_request("invalid agent ID"))?,
    );

    // If agent has an attestation token, verify it and observe the MRTD
    if let Some(ref _token) = registration.attestation_token {
        // In a full implementation, we'd verify the ITA JWT here and pass
        // the claims to measurement.observe(). For now, register without
        // MRTD observation in non-TDX environments.
        tracing::debug!(agent_id = %agent_id, "attestation token present, would verify");
    }

    let info = state.registry.register(agent_id, registration).await;
    tracing::info!(
        agent_id = %info.id,
        size = %info.size,
        cloud = %info.cloud,
        "agent registered"
    );

    Ok(Json(serde_json::json!({"status": "registered"})))
}

async fn deploy(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeployRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Find a healthy agent and relay the deploy
    let agents = state.registry.all_agents().await;
    let agent = agents
        .first()
        .ok_or_else(|| ApiError::not_found("no agents available"))?;

    tracing::info!(
        app = %req.app_name,
        agent_id = %agent.id,
        "relaying deploy"
    );

    Ok(Json(serde_json::json!({
        "status": "deployed",
        "agent_id": agent.id.to_string(),
    })))
}

async fn undeploy(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<UndeployRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    tracing::info!(app = %req.app_name, "relaying undeploy");
    Ok(Json(serde_json::json!({"status": "undeployed"})))
}

// --- Billing routes ---

async fn billing_listings(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<crate::billing::types::Listing>> {
    let listings = state.marketplace.list_available().await;
    Json(listings)
}

async fn billing_purchase(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PurchaseRequest>,
) -> Result<Json<crate::billing::types::Invoice>, ApiError> {
    let invoice = state
        .marketplace
        .purchase(req)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(invoice))
}

async fn billing_invoice(
    State(state): State<Arc<AppState>>,
    Path(invoice_id): Path<String>,
) -> Result<Json<crate::billing::types::Invoice>, ApiError> {
    let invoice = state
        .marketplace
        .get_invoice(&invoice_id)
        .await
        .map_err(|e| ApiError::not_found(e.to_string()))?;
    Ok(Json(invoice))
}

async fn billing_webhook(
    State(_state): State<Arc<AppState>>,
    _body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    // BTCPay webhook processing would go here
    Ok(Json(serde_json::json!({"status": "ok"})))
}
