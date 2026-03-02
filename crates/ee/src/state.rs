use chrono::{DateTime, Utc};
use sqlx::SqlitePool;

use crate::services::attestation::AttestationService;
use crate::services::github_oidc::GithubOidcService;
use crate::services::nonce::NonceService;
use crate::services::tunnel::TunnelService;
use crate::stores::setting::SettingsStore;

#[derive(Clone)]
pub struct AppState {
    pub boot_id: String,
    pub git_sha: Option<String>,
    pub started_at: DateTime<Utc>,
    pub admin_password: Option<String>,
    pub db_pool: SqlitePool,
    pub settings: SettingsStore,
    pub nonce: NonceService,
    pub attestation: AttestationService,
    pub github_oidc: GithubOidcService,
    pub tunnel: TunnelService,
    pub check_ingest_token: Option<String>,
    pub heartbeat_interval_seconds: u64,
    pub check_timeout_seconds: u64,
    pub down_after_failures: u32,
    pub recover_after_successes: u32,
    pub attestation_recheck_seconds: u64,
    pub agent_health_path: String,
    pub agent_attestation_path: Option<String>,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        boot_id: String,
        git_sha: Option<String>,
        admin_password: Option<String>,
        db_pool: SqlitePool,
        settings: SettingsStore,
        nonce: NonceService,
        attestation: AttestationService,
        github_oidc: GithubOidcService,
        tunnel: TunnelService,
    ) -> Self {
        Self {
            boot_id,
            git_sha,
            started_at: Utc::now(),
            admin_password,
            db_pool,
            settings,
            nonce,
            attestation,
            github_oidc,
            tunnel,
            check_ingest_token: env_optional("CP_AGENT_CHECK_TOKEN"),
            heartbeat_interval_seconds: env_u64("CP_HEARTBEAT_INTERVAL_SECONDS", 30),
            check_timeout_seconds: env_u64("CP_CHECK_TIMEOUT_SECONDS", 5),
            down_after_failures: env_u32("CP_DOWN_AFTER_CONSECUTIVE_FAILURES", 3),
            recover_after_successes: env_u32("CP_RECOVER_AFTER_CONSECUTIVE_SUCCESSES", 2),
            attestation_recheck_seconds: env_u64("CP_ATTESTATION_RECHECK_SECONDS", 300),
            agent_health_path: env_path("CP_AGENT_HEALTH_PATH", "/health"),
            agent_attestation_path: env_optional_path("CP_AGENT_ATTESTATION_PATH"),
        }
    }
}

fn env_optional(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn env_path(key: &str, default: &str) -> String {
    let raw = std::env::var(key)
        .ok()
        .unwrap_or_else(|| default.to_string());
    normalize_path(&raw).unwrap_or_else(|| default.to_string())
}

fn env_optional_path(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|raw| normalize_path(&raw))
}

fn normalize_path(raw: &str) -> Option<String> {
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }
    if value.starts_with('/') {
        Some(value.to_string())
    } else {
        Some(format!("/{value}"))
    }
}
