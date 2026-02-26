use serde::{Deserialize, Serialize};

use crate::types::{AgentRecord, AppRecord, AppVersionRecord, HealthStatus};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub vm_name: String,
    pub owner: String,
    pub node_size: String,
    pub datacenter: String,
    pub attestation_jwt: String,
    pub mrtd: String,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub agent_id: String,
    pub tunnel_token: String,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub mrtd: String,
    pub health_status: HealthStatus,
    pub tcb_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployRequest {
    pub app_name: String,
    pub version: String,
    pub agent_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployResponse {
    pub deployment_id: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishAppRequest {
    pub name: String,
    pub description: Option<String>,
    pub source_repo: Option<String>,
    pub version: String,
    pub image: String,
    pub mrtd: String,
    pub node_size: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishVersionRequest {
    pub version: String,
    pub image: String,
    pub mrtd: String,
    pub node_size: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppWithVersions {
    pub app: AppRecord,
    pub versions: Vec<AppVersionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentListResponse {
    pub agents: Vec<AgentRecord>,
}
