use axum::{extract::State, http::HeaderMap, Json};
use ee_common::{
    api::{DeployRequest, DeployResponse},
    error::{AppError, AppResult},
    types::AgentStatus,
};

use crate::{github_oidc, ownership::owner_matches, state::SharedState};

pub async fn deploy_app(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<DeployRequest>,
) -> AppResult<Json<DeployResponse>> {
    let auth_header = headers
        .get("authorization")
        .ok_or_else(|| AppError::Unauthorized("missing authorization".to_owned()))?
        .to_str()
        .map_err(|_| AppError::Unauthorized("invalid authorization header".to_owned()))?;

    let identity = github_oidc::verify_bearer(auth_header)?;

    let mut agent = state
        .agents
        .get_mut(&request.agent_id)
        .ok_or_else(|| AppError::NotFound("agent not found".to_owned()))?;

    if !owner_matches(&agent.owner, &identity.repository_owner) {
        return Err(AppError::Unauthorized(
            "repository owner does not own target agent".to_owned(),
        ));
    }

    let app_versions = state
        .app_versions
        .get(&request.app_name)
        .ok_or_else(|| AppError::NotFound("app not found".to_owned()))?;

    let matched = app_versions
        .iter()
        .find(|v| v.version == request.version)
        .ok_or_else(|| AppError::NotFound("app version not found".to_owned()))?;

    if matched.mrtd.is_empty() {
        return Err(AppError::BadRequest("app version missing MRTD".to_owned()));
    }

    agent.status = AgentStatus::Deployed;

    Ok(Json(DeployResponse {
        deployment_id: uuid::Uuid::new_v4().to_string(),
        status: "accepted".to_owned(),
    }))
}
