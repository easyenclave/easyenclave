//! CP HTTP server: REST API, admin, trusted aggregator management, measurements.
//! When built-in aggregator is enabled, aggregator routes are merged in.

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

/// Build the CP-only routes.
pub fn cp_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health
        .route("/api/health", get(health))
        // Measurements
        .route("/api/v1/measurements", get(list_measurements))
        .route("/api/v1/measurements", post(submit_measurement))
        // Trusted aggregator management
        .route("/api/v1/aggregators/trust", get(list_trusted))
        .route("/api/v1/aggregators/trust", post(add_trusted))
        .route("/api/v1/aggregators/trust/:id", delete(remove_trusted))
        .with_state(state)
}

/// Build the full router, optionally merging aggregator routes.
pub fn router(
    cp_state: Arc<AppState>,
    aggregator_state: Option<Arc<ee_aggregator::server::AppState>>,
) -> Router {
    let mut app = cp_router(cp_state);

    if let Some(agg_state) = aggregator_state {
        // Merge aggregator routes into CP — agent registration, billing,
        // state endpoint, deploy/undeploy all served on the same port.
        // Uses mergeable_routes() to avoid /api/health overlap.
        app = app.merge(ee_aggregator::mergeable_routes(agg_state));
    }

    // Serve admin UI at /admin
    app = app.nest_service(
        "/admin",
        tower_http::services::ServeDir::new(admin_static_dir()).fallback(
            tower_http::services::ServeFile::new(admin_static_dir().join("index.html")),
        ),
    );

    app
}

/// Locate the admin static directory.
/// In development: crates/cp/static/
/// In production: /usr/share/easyenclave/static/ or next to binary.
fn admin_static_dir() -> std::path::PathBuf {
    // Check for dev path first
    let dev = std::path::PathBuf::from("crates/cp/static");
    if dev.exists() {
        return dev;
    }
    // Production path
    let prod = std::path::PathBuf::from("/usr/share/easyenclave/static");
    if prod.exists() {
        return prod;
    }
    // Fallback: next to binary
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.join("static")))
        .unwrap_or(dev)
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

async fn list_trusted(State(state): State<Arc<AppState>>) -> Result<Json<Vec<String>>, ApiError> {
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
