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
        }
    }
}
