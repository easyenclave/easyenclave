use std::time::Duration;

use axum::{
    extract::{Path, State},
    Json,
};
use chrono::Utc;
use ee_common::{
    api::{
        AgentListResponse, ChallengeResponse, HeartbeatRequest, RegisterRequest, RegisterResponse,
    },
    error::{AppError, AppResult},
    types::{AgentRecord, AgentStatus},
};

use crate::{attestation, state::SharedState};

pub async fn challenge(State(state): State<SharedState>) -> Json<ChallengeResponse> {
    let nonce = state.nonces.issue(Duration::from_secs(300));
    Json(ChallengeResponse { nonce })
}

pub async fn register(
    State(state): State<SharedState>,
    Json(request): Json<RegisterRequest>,
) -> AppResult<Json<RegisterResponse>> {
    let mrtd = attestation::verify_registration(&state, &request).await?;

    let assignment = state
        .cloudflare
        .create_agent_tunnel(&request.vm_name, &request.owner, &state.config.domain)
        .await?;

    let now = Utc::now();
    let agent_id = uuid::Uuid::new_v4().to_string();
    let record = AgentRecord {
        agent_id: agent_id.clone(),
        vm_name: request.vm_name,
        status: AgentStatus::Undeployed,
        mrtd,
        hostname: Some(assignment.hostname.clone()),
        owner: request.owner,
        node_size: request.node_size,
        datacenter: request.datacenter,
        verified: true,
        tcb_status: Some("UpToDate".to_owned()),
        registered_at: now,
        last_heartbeat: now,
    };

    state.upsert_agent(record);

    Ok(Json(RegisterResponse {
        agent_id,
        tunnel_token: assignment.tunnel_token,
        hostname: assignment.hostname,
    }))
}

pub async fn heartbeat(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Json(request): Json<HeartbeatRequest>,
) -> AppResult<Json<serde_json::Value>> {
    state.set_agent_heartbeat(&id, request.mrtd)?;
    Ok(Json(serde_json::json!({"status":"ok"})))
}

pub async fn list_agents(State(state): State<SharedState>) -> Json<AgentListResponse> {
    let agents = state.agents.iter().map(|a| a.value().clone()).collect();
    Json(AgentListResponse { agents })
}

pub async fn get_agent(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> AppResult<Json<AgentRecord>> {
    let agent = state
        .agents
        .get(&id)
        .ok_or_else(|| AppError::NotFound("agent not found".to_owned()))?;

    Ok(Json(agent.value().clone()))
}

pub async fn get_agent_logs(Path(id): Path<String>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "agent_id": id,
        "logs": "log proxy not wired yet"
    }))
}

pub async fn undeploy_agent(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    state.undeploy_agent(&id)?;
    state.cloudflare.delete_agent_tunnel(&id).await?;
    Ok(Json(serde_json::json!({"status":"undeployed"})))
}
