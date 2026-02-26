use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Undeployed,
    Deployed,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    pub agent_id: String,
    pub vm_name: String,
    pub status: AgentStatus,
    pub mrtd: String,
    pub hostname: Option<String>,
    pub owner: String,
    pub node_size: String,
    pub datacenter: String,
    pub verified: bool,
    pub tcb_status: Option<String>,
    pub registered_at: DateTime<Utc>,
    pub last_heartbeat: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRecord {
    pub name: String,
    pub description: String,
    pub publisher: String,
    pub source_repo: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppVersionRecord {
    pub version_id: String,
    pub app_name: String,
    pub version: String,
    pub image: String,
    pub mrtd: String,
    pub node_size: Option<String>,
    pub published_at: DateTime<Utc>,
}
