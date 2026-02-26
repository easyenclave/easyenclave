use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationEvidence {
    pub quote: String,
    pub token: String,
    pub mrtd: String,
    pub generated_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentRegistrationRequest {
    pub agent_id: String,
    pub listen_url: String,
    pub datacenter: String,
    pub attestation: Option<AttestationEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentRegistrationResponse {
    pub accepted: bool,
    pub agent_secret: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentHeartbeatRequest {
    pub healthy: bool,
    pub deployment: Option<String>,
    pub attestation: Option<AttestationEvidence>,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentSnapshot {
    pub agent_id: String,
    pub listen_url: String,
    pub datacenter: String,
    pub source: String,
    pub healthy: bool,
    pub attested: bool,
    pub deployment: Option<String>,
    pub last_seen: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentListResponse {
    pub total: usize,
    pub agents: Vec<AgentSnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatorRegistrationRequest {
    pub aggregator_id: String,
    pub listen_url: String,
    pub datacenter: String,
    pub scrape_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatorRegistrationResponse {
    pub accepted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatorSnapshot {
    pub aggregator_id: String,
    pub listen_url: String,
    pub datacenter: String,
    pub last_seen: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatorListResponse {
    pub total: usize,
    pub aggregators: Vec<AggregatorSnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatorStateResponse {
    pub aggregator_id: String,
    pub collected_at: u64,
    pub agents: Vec<AgentSnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeployRequest {
    pub app_name: String,
    pub compose_url: Option<String>,
    pub target_agent_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UndeployRequest {
    pub app_name: Option<String>,
    pub target_agent_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeployResponse {
    pub dispatched: usize,
    pub failed: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub service: String,
    pub status: String,
    pub timestamp: u64,
    pub agent_id: Option<String>,
    pub deployment: Option<String>,
    pub attestation: Option<AttestationEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}
