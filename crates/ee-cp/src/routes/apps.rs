use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use chrono::Utc;
use ee_common::{
    api::{AppWithVersions, PublishAppRequest, PublishVersionRequest},
    error::{AppError, AppResult},
    types::AppRecord,
};

use crate::{github_oidc, state::SharedState};

pub async fn publish_app(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<PublishAppRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let auth_header = headers
        .get("authorization")
        .ok_or_else(|| AppError::Unauthorized("missing authorization".to_owned()))?
        .to_str()
        .map_err(|_| AppError::Unauthorized("invalid authorization header".to_owned()))?;

    let identity = github_oidc::verify_bearer(&state.config, auth_header).await?;

    let app = AppRecord {
        name: request.name,
        description: request.description.unwrap_or_default(),
        publisher: identity.repository_owner,
        source_repo: request.source_repo,
        created_at: Utc::now(),
    };

    let version = PublishVersionRequest {
        version: request.version,
        image: request.image,
        mrtd: request.mrtd,
        node_size: request.node_size,
    };

    let (app, version_record) = state.store_app(app, version);

    Ok(Json(serde_json::json!({
        "app": app,
        "version": version_record
    })))
}

pub async fn list_apps(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let apps: Vec<_> = state
        .apps
        .iter()
        .map(|entry| entry.value().clone())
        .collect();
    Json(serde_json::json!({"apps": apps}))
}

pub async fn get_app(
    State(state): State<SharedState>,
    Path(name): Path<String>,
) -> AppResult<Json<AppWithVersions>> {
    let app = state
        .apps
        .get(&name)
        .ok_or_else(|| AppError::NotFound("app not found".to_owned()))?
        .value()
        .clone();

    let versions = state
        .app_versions
        .get(&name)
        .map(|v| v.clone())
        .unwrap_or_default();

    Ok(Json(AppWithVersions { app, versions }))
}

pub async fn publish_app_version(
    State(state): State<SharedState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(request): Json<PublishVersionRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let auth_header = headers
        .get("authorization")
        .ok_or_else(|| AppError::Unauthorized("missing authorization".to_owned()))?
        .to_str()
        .map_err(|_| AppError::Unauthorized("invalid authorization header".to_owned()))?;

    let _identity = github_oidc::verify_bearer(&state.config, auth_header).await?;

    if !state.apps.contains_key(&name) {
        return Err(AppError::NotFound("app not found".to_owned()));
    }

    let version_record = ee_common::types::AppVersionRecord {
        version_id: uuid::Uuid::new_v4().to_string(),
        app_name: name.clone(),
        version: request.version,
        image: request.image,
        mrtd: request.mrtd,
        node_size: request.node_size,
        published_at: Utc::now(),
    };

    state
        .app_versions
        .entry(name)
        .or_default()
        .push(version_record.clone());

    Ok(Json(serde_json::json!({"version": version_record})))
}
