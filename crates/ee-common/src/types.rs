use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Undeployed,
    Deploying,
    Deployed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentStatus {
    Pending,
    Deploying,
    Running,
    Failed,
    Stopped,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountType {
    Deployer,
    Agent,
    Contributor,
    Platform,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Agent {
    pub agent_id: Uuid,
    pub vm_name: String,
    pub status: AgentStatus,
    pub mrtd: Option<String>,
    pub rtmrs: Option<Vec<String>>,
    pub attestation: Option<Value>,
    pub tunnel_id: Option<String>,
    pub hostname: Option<String>,
    pub tunnel_token: Option<String>,
    pub health_status: Option<String>,
    pub verified: bool,
    pub tcb_status: Option<String>,
    pub node_size: Option<String>,
    pub datacenter: Option<String>,
    pub github_owner: Option<String>,
    pub deployed_app: Option<String>,
    pub account_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentControlCredential {
    pub agent_id: Uuid,
    pub api_secret_hash: String,
    pub api_secret_prefix: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Deployment {
    pub deployment_id: Uuid,
    pub compose: String,
    pub config: Option<Value>,
    pub agent_id: Uuid,
    pub status: DeploymentStatus,
    pub app_name: Option<String>,
    pub app_version: Option<String>,
    pub cpu_vcpus: i32,
    pub memory_gb: f64,
    pub gpu_count: i32,
    pub account_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Service {
    pub service_id: Uuid,
    pub name: String,
    pub compose_hash: String,
    pub mrtd: Option<String>,
    pub endpoints: Option<Value>,
    pub health_status: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct App {
    pub app_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub source_repo: Option<String>,
    pub maintainers: Option<Value>,
    pub tags: Option<Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppVersion {
    pub version_id: Uuid,
    pub app_name: String,
    pub version: String,
    pub node_size: Option<String>,
    pub compose: String,
    pub image_digest: Option<String>,
    pub mrtd: Option<String>,
    pub status: String,
    pub ingress: Option<Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Account {
    pub account_id: Uuid,
    pub name: String,
    pub account_type: AccountType,
    pub api_key_hash: Option<String>,
    pub api_key_prefix: Option<String>,
    pub github_id: Option<String>,
    pub github_login: Option<String>,
    pub github_org: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Setting {
    pub key: String,
    pub value: Value,
    pub is_secret: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdminSession {
    pub session_id: Uuid,
    pub token_hash: String,
    pub token_prefix: String,
    pub expires_at: DateTime<Utc>,
    pub auth_method: String,
    pub github_login: Option<String>,
    pub github_orgs: Option<Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustedMrtd {
    pub mrtd: String,
    pub mrtd_type: String,
    pub note: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
