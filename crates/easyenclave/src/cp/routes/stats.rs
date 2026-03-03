use crate::common::api::{RecentAgentStatsResponse, RecentAppStatsResponse};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::state::AppState;
use crate::stores::health::HealthStore;

#[derive(Debug, Clone, Deserialize)]
pub struct RecentStatsQuery {
    pub window_hours: Option<u32>,
}

pub async fn recent_app_stats(
    State(state): State<AppState>,
    Query(query): Query<RecentStatsQuery>,
) -> Result<Json<RecentAppStatsResponse>, StatusCode> {
    let window_hours = query.window_hours.unwrap_or(24).clamp(1, 168);
    let store = HealthStore::new(state.db_pool.clone());
    let stats = store
        .recent_app_stats(window_hours, state.heartbeat_interval_seconds)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(stats))
}

pub async fn recent_agent_stats(
    State(state): State<AppState>,
    Query(query): Query<RecentStatsQuery>,
) -> Result<Json<RecentAgentStatsResponse>, StatusCode> {
    let window_hours = query.window_hours.unwrap_or(24).clamp(1, 168);
    let store = HealthStore::new(state.db_pool.clone());
    let stats = store
        .recent_agent_stats(window_hours, state.heartbeat_interval_seconds)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(stats))
}
