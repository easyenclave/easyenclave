use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthResponse {
    pub ok: bool,
    pub boot_id: Option<String>,
    pub git_sha: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentChallengeResponse {
    pub nonce: String,
    pub expires_in_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentRegisterRequest {
    pub intel_ta_token: String,
    pub vm_name: String,
    pub nonce: String,
    pub node_size: Option<String>,
    pub datacenter: Option<String>,
    pub github_owner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentRegisterResponse {
    pub agent_id: Uuid,
    pub tunnel_token: String,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeployRequest {
    pub compose: String,
    pub config: Option<Value>,
    pub app_name: Option<String>,
    pub app_version: Option<String>,
    pub agent_name: Option<String>,
    pub node_size: Option<String>,
    pub datacenter: Option<String>,
    pub dry_run: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeployResponse {
    pub deployment_id: Uuid,
    pub agent_id: Uuid,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CreateAccountRequest {
    pub name: String,
    pub account_type: String,
    pub github_login: Option<String>,
    pub github_org: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CreateAccountResponse {
    pub account_id: Uuid,
    pub api_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdminLoginRequest {
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdminLoginResponse {
    pub token: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthMeResponse {
    pub auth_method: String,
    pub github_login: Option<String>,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PaymentIntentRequest {
    pub amount_cents: i64,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PaymentIntentResponse {
    pub client_secret: String,
    pub payment_intent_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiErrorResponse {
    pub code: String,
    pub message: String,
    pub request_id: Option<String>,
}
