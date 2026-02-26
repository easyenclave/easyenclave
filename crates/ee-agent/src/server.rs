use std::sync::Arc;

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use ee_common::error::{AppError, AppResult};
use serde::Deserialize;

use crate::{logs::LogBuffer, workload::WorkloadManager};

#[derive(Clone, Default)]
pub struct AgentHttpState {
    pub workload: WorkloadManager,
    pub logs: LogBuffer,
}

#[derive(Debug, Deserialize)]
struct DeployPayload {
    image: String,
}

pub fn router(state: Arc<AgentHttpState>) -> Router {
    Router::new()
        .route("/api/deploy", post(deploy))
        .route("/api/undeploy", post(undeploy))
        .route("/api/health", get(health))
        .route("/api/logs", get(logs))
        .with_state(state)
}

async fn deploy(
    State(state): State<Arc<AgentHttpState>>,
    Json(payload): Json<DeployPayload>,
) -> AppResult<Json<serde_json::Value>> {
    state.workload.deploy(&payload.image).await?;
    state.logs.push(format!("deployed {}", payload.image)).await;
    Ok(Json(serde_json::json!({"status":"ok"})))
}

async fn undeploy(State(state): State<Arc<AgentHttpState>>) -> AppResult<Json<serde_json::Value>> {
    state.workload.undeploy().await?;
    state.logs.push("undeployed").await;
    Ok(Json(serde_json::json!({"status":"ok"})))
}

async fn health(State(state): State<Arc<AgentHttpState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "current": state.workload.current().await
    }))
}

async fn logs(State(state): State<Arc<AgentHttpState>>) -> AppResult<Json<serde_json::Value>> {
    let lines = state.logs.snapshot().await;
    if lines.is_empty() {
        return Err(AppError::NotFound("no logs yet".to_owned()));
    }
    Ok(Json(serde_json::json!({"lines": lines})))
}
