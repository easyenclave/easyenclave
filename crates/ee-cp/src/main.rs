use std::error::Error;
use std::time::Duration;

use ee_common::config::CpConfig;
use ee_cp::db::connect_and_migrate;
use ee_cp::routes::build_router;
use ee_cp::services::attestation::AttestationService;
use ee_cp::services::github_oidc::GithubOidcService;
use ee_cp::services::nonce::NonceService;
use ee_cp::services::tunnel::TunnelService;
use ee_cp::state::AppState;
use ee_cp::stores::setting::SettingsStore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = CpConfig::from_env()?;
    let pool = connect_and_migrate(&config.database_url).await?;
    let settings = SettingsStore::new(pool.clone());
    let nonce = NonceService::new(Duration::from_secs(300));
    let attestation = AttestationService::from_env();
    let github_oidc = GithubOidcService::from_env();
    let tunnel = TunnelService::from_env();
    attestation.validate_runtime_requirements()?;
    tunnel.validate_runtime_requirements()?;

    let git_sha = std::env::var("GIT_SHA")
        .ok()
        .or_else(|| std::env::var("EASYENCLAVE_GIT_SHA").ok());
    let boot_id = std::env::var("EASYENCLAVE_BOOT_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("cp-{}", std::process::id()));
    let state = AppState::new(
        boot_id,
        git_sha,
        config.admin_password.clone(),
        pool,
        settings,
        nonce,
        attestation,
        github_oidc,
        tunnel,
    );

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
