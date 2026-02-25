use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentId(pub Uuid);

impl AgentId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Registering,
    Healthy,
    Unhealthy,
    Attested,
    AttestationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum VmSize {
    Small,
    Medium,
    Large,
    XLarge,
}

impl std::fmt::Display for VmSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmSize::Small => write!(f, "small"),
            VmSize::Medium => write!(f, "medium"),
            VmSize::Large => write!(f, "large"),
            VmSize::XLarge => write!(f, "xlarge"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Cloud {
    Gcp,
    Azure,
    Aws,
    SelfHosted,
}

impl std::fmt::Display for Cloud {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cloud::Gcp => write!(f, "gcp"),
            Cloud::Azure => write!(f, "azure"),
            Cloud::Aws => write!(f, "aws"),
            Cloud::SelfHosted => write!(f, "self_hosted"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub id: AgentId,
    pub status: AgentStatus,
    pub size: VmSize,
    pub cloud: Cloud,
    pub region: String,
    pub tags: Vec<String>,
    pub attestation_token: Option<String>,
    pub registered_at: DateTime<Utc>,
    pub last_health_check: Option<DateTime<Utc>>,
    pub deployment: Option<DeploymentInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRegistration {
    pub size: VmSize,
    pub cloud: Cloud,
    pub region: String,
    pub tags: Vec<String>,
    pub attestation_token: Option<String>,
    pub secret: String,
}

// ---------------------------------------------------------------------------
// Deployment
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentStatus {
    Pending,
    Pulling,
    Running,
    Failed,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentInfo {
    pub app_name: String,
    pub image: String,
    pub status: DeploymentStatus,
    pub tunnel_url: Option<String>,
    pub deployed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployRequest {
    pub app_name: String,
    pub image: String,
    pub env_vars: std::collections::HashMap<String, String>,
    pub owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndeployRequest {
    pub app_name: String,
}

// ---------------------------------------------------------------------------
// Aggregator
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatorId(pub Uuid);

impl AggregatorId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for AggregatorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatorRegistration {
    pub id: AggregatorId,
    pub url: url::Url,
    pub region: String,
    pub api_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatorState {
    pub id: AggregatorId,
    pub agents: Vec<AgentInfo>,
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Measurements (trusted MRTD)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasurementSubmission {
    pub size: VmSize,
    pub cloud: Cloud,
    pub mrtd: String,
    pub release_tag: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedMrtd {
    pub size: VmSize,
    pub cloud: Cloud,
    pub mrtd: String,
    pub release_tag: Option<String>,
    pub submitted_by: AggregatorId,
    pub submitted_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_secs: u64,
}
