//! Agent HTTP server.

use crate::config::AgentConfig;
use crate::deployment::DeploymentManager;
use crate::tunnel::TunnelManager;
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use ee_common::error::ApiError;
use ee_common::types::{DeployRequest, DeploymentInfo, HealthResponse, UndeployRequest};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

pub struct AppState {
    pub config: AgentConfig,
    pub deployment_manager: DeploymentManager,
    pub tunnel_manager: Option<TunnelManager>,
    pub start_time: Instant,
}

pub fn router(state: Arc<Mutex<AppState>>) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/deploy", post(deploy))
        .route("/api/undeploy", post(undeploy))
        .route("/api/status", get(status))
        .with_state(state)
}

async fn health(State(state): State<Arc<Mutex<AppState>>>) -> Json<HealthResponse> {
    let s = state.lock().await;
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: s.start_time.elapsed().as_secs(),
    })
}

async fn deploy(
    State(state): State<Arc<Mutex<AppState>>>,
    Json(req): Json<DeployRequest>,
) -> Result<Json<DeploymentInfo>, ApiError> {
    let mut s = state.lock().await;
    let mut info = s
        .deployment_manager
        .deploy(&req)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // Create tunnel if configured
    if let Some(ref mut tunnel) = s.tunnel_manager {
        match tunnel.create(&req.app_name, 0).await {
            Ok(url) => {
                tracing::info!(app = %req.app_name, tunnel_url = %url, "tunnel created");
                info.tunnel_url = Some(url);
            }
            Err(e) => {
                tracing::warn!(app = %req.app_name, ?e, "tunnel creation failed, continuing without tunnel");
            }
        }
    }

    Ok(Json(info))
}

async fn undeploy(
    State(state): State<Arc<Mutex<AppState>>>,
    Json(req): Json<UndeployRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut s = state.lock().await;

    // Destroy tunnel first
    if let Some(ref mut tunnel) = s.tunnel_manager {
        if let Err(e) = tunnel.destroy().await {
            tracing::warn!(app = %req.app_name, ?e, "tunnel destroy failed");
        }
    }

    s.deployment_manager
        .undeploy(&req.app_name)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(serde_json::json!({"status": "ok"})))
}

async fn status(
    State(state): State<Arc<Mutex<AppState>>>,
) -> Result<Json<Option<DeploymentInfo>>, ApiError> {
    let s = state.lock().await;
    let deployment = s
        .deployment_manager
        .current_deployment()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(deployment))
}
