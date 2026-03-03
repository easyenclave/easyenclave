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
pub struct RecentAppStatsResponse {
    pub window_hours: u32,
    pub window_start_unix: i64,
    pub window_end_unix: i64,
    pub total_apps: u64,
    pub apps: Vec<RecentAppStat>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecentAgentStatsResponse {
    pub window_hours: u32,
    pub window_start_unix: i64,
    pub window_end_unix: i64,
    pub total_agents: u64,
    pub agents: Vec<RecentAgentStat>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecentAppStat {
    pub app_name: String,
    pub checks_total: u64,
    pub failed_checks: u64,
    pub exempt_failures: u64,
    pub imperfect_now: u64,
    pub perfect_now: bool,
    pub last_imperfect_unix: Option<i64>,
    pub seconds_since_last_imperfect: Option<u64>,
    pub downtime_seconds_estimate: u64,
    pub uptime_ratio: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecentAgentStat {
    pub agent_id: Uuid,
    pub vm_name: Option<String>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub checks_total: u64,
    pub failed_checks: u64,
    pub exempt_failures: u64,
    pub imperfect_now: bool,
    pub perfect_now: bool,
    pub last_imperfect_unix: Option<i64>,
    pub seconds_since_last_imperfect: Option<u64>,
    pub downtime_seconds_estimate: u64,
    pub uptime_ratio: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentCheckIngestRequest {
    pub app_name: Option<String>,
    pub health_ok: bool,
    pub attestation_ok: bool,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentCheckIngestResponse {
    pub app_name: String,
    pub check_ok: bool,
    pub deployment_exempt: bool,
    pub counted_down: bool,
    pub imperfect_now: bool,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
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
pub struct ApiErrorResponse {
    pub code: String,
    pub message: String,
    pub request_id: Option<String>,
}
