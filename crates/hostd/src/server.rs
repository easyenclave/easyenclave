//! Hostd HTTP server.

use crate::config::HostdConfig;
use crate::resources::HostResources;
use crate::vm::{VmInfo, VmManager};
use axum::extract::{Path, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use ee_common::error::ApiError;
use ee_common::types::{HealthResponse, VmSize};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

pub struct AppState {
    pub config: HostdConfig,
    pub vm_manager: VmManager,
    pub resources: HostResources,
    pub start_time: Instant,
}

pub fn router(state: Arc<Mutex<AppState>>) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/vms", get(list_vms))
        .route("/api/vms", post(launch_vm))
        .route("/api/vms/:vm_id", get(get_vm))
        .route("/api/vms/:vm_id", delete(stop_vm))
        .route("/api/resources", get(resources))
        .route("/api/images", get(list_images))
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

#[derive(Debug, Deserialize)]
struct LaunchRequest {
    size: VmSize,
    image: String,
}

async fn launch_vm(
    State(state): State<Arc<Mutex<AppState>>>,
    Json(req): Json<LaunchRequest>,
) -> Result<Json<VmInfo>, ApiError> {
    let mut s = state.lock().await;
    let info = s
        .vm_manager
        .launch(req.size, &req.image)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(info))
}

async fn list_vms(State(state): State<Arc<Mutex<AppState>>>) -> Json<Vec<VmInfo>> {
    let s = state.lock().await;
    Json(s.vm_manager.list())
}

async fn get_vm(
    State(state): State<Arc<Mutex<AppState>>>,
    Path(vm_id): Path<String>,
) -> Result<Json<VmInfo>, ApiError> {
    let s = state.lock().await;
    s.vm_manager
        .get(&vm_id)
        .cloned()
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("VM {vm_id} not found")))
}

async fn stop_vm(
    State(state): State<Arc<Mutex<AppState>>>,
    Path(vm_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut s = state.lock().await;
    s.vm_manager
        .stop(&vm_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(serde_json::json!({"status": "stopped"})))
}

async fn resources(State(state): State<Arc<Mutex<AppState>>>) -> Json<HostResources> {
    let s = state.lock().await;
    Json(s.resources.clone())
}

async fn list_images(
    State(state): State<Arc<Mutex<AppState>>>,
) -> Result<Json<Vec<crate::images::VmImage>>, ApiError> {
    let s = state.lock().await;
    let images = crate::images::list_images(&s.config.image_dir)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(images))
}
