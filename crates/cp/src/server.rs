//! CP HTTP server: REST API, admin, trusted aggregator management, measurements.

use crate::config::CpConfig;
use crate::db::Database;
use axum::extract::{Path, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use ee_common::error::ApiError;
use ee_common::types::{HealthResponse, MeasurementSubmission, TrustedMrtd};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Instant;

pub struct AppState {
    pub config: CpConfig,
    pub db: Database,
    pub start_time: Instant,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health
        .route("/api/health", get(health))
        // Measurements
        .route("/api/v1/measurements", get(list_measurements))
        .route("/api/v1/measurements", post(submit_measurement))
        // Trusted aggregator management
        .route("/api/v1/aggregators/trust", get(list_trusted))
        .route("/api/v1/aggregators/trust", post(add_trusted))
        .route("/api/v1/aggregators/trust/{id}", delete(remove_trusted))
        // Agent registration (for direct-connect via built-in aggregator)
        .route(
            "/api/v1/agents/{agent_id}/register",
            post(register_agent_direct),
        )
        .with_state(state)
}

async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: state.start_time.elapsed().as_secs(),
    })
}

// --- Measurements ---

async fn list_measurements(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<TrustedMrtd>>, ApiError> {
    let mrtds = state
        .db
        .get_all_mrtds()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(mrtds))
}

async fn submit_measurement(
    State(state): State<Arc<AppState>>,
    Json(submission): Json<MeasurementSubmission>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // In production, we'd extract the aggregator ID from the auth token
    // and verify it's in the trusted list. For now, accept all.
    tracing::info!(
        mrtd = %submission.mrtd,
        size = %submission.size,
        cloud = %submission.cloud,
        "measurement submitted"
    );

    state
        .db
        .insert_mrtd(&submission, "builtin")
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(serde_json::json!({"status": "accepted"})))
}

// --- Trusted aggregators ---

async fn list_trusted(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<String>>, ApiError> {
    let ids = state
        .db
        .list_trusted_aggregators()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(ids))
}

#[derive(Deserialize)]
struct TrustRequest {
    aggregator_id: String,
}

async fn add_trusted(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TrustRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .db
        .add_trusted_aggregator(&req.aggregator_id, "admin")
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    tracing::info!(id = %req.aggregator_id, "aggregator trusted");
    Ok(Json(serde_json::json!({"status": "trusted"})))
}

async fn remove_trusted(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .db
        .remove_trusted_aggregator(&id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    tracing::info!(%id, "aggregator trust revoked");
    Ok(Json(serde_json::json!({"status": "revoked"})))
}

// --- Direct agent registration (goes through built-in aggregator) ---

async fn register_agent_direct(
    State(_state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    Json(_registration): Json<ee_common::types::AgentRegistration>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // The built-in aggregator handles this.
    // This route exists so agents can register with CP's URL directly.
    tracing::info!(%agent_id, "direct agent registration (built-in aggregator)");
    Ok(Json(serde_json::json!({"status": "registered"})))
}
