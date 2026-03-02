use std::error::Error;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use ee_common::config::CpConfig;
use ee_cp::db::connect_and_migrate;
use ee_cp::routes::build_router;
use ee_cp::services::attestation::AttestationService;
use ee_cp::services::github_oidc::GithubOidcService;
use ee_cp::services::health_monitor;
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

    if public_ingress_enabled() {
        let protected = is_protected_env();
        let Some(public_hostname) = control_plane_public_hostname() else {
            if protected {
                return Err("missing control-plane public hostname (set EASYENCLAVE_CP_URL or CP_PUBLIC_HOSTNAME)".into());
            }
            eprintln!("ee-cp: public ingress disabled (no control-plane hostname configured)");
            return run_server(
                config,
                pool,
                settings,
                nonce,
                attestation,
                github_oidc,
                tunnel,
            )
            .await;
        };
        let tunnel_name = control_plane_tunnel_name();
        let registration = tunnel
            .create_tunnel_for_hostname(&tunnel_name, &public_hostname)
            .await
            .map_err(|err| format!("failed to provision CP Cloudflare ingress: {err}"))?;
        eprintln!(
            "ee-cp: provisioned control-plane ingress hostname={} tunnel_id={}",
            registration.hostname, registration.tunnel_id
        );
        start_cloudflared_supervisor(registration.tunnel_token);
    }

    run_server(
        config,
        pool,
        settings,
        nonce,
        attestation,
        github_oidc,
        tunnel,
    )
    .await
}

async fn run_server(
    config: ee_common::config::CpConfig,
    pool: sqlx::SqlitePool,
    settings: SettingsStore,
    nonce: NonceService,
    attestation: AttestationService,
    github_oidc: GithubOidcService,
    tunnel: TunnelService,
) -> Result<(), Box<dyn Error>> {
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

    let monitor_state = state.clone();
    tokio::spawn(async move {
        health_monitor::run(monitor_state).await;
    });

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn public_ingress_enabled() -> bool {
    std::env::var("CP_PUBLIC_INGRESS_ENABLED")
        .ok()
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or_else(is_protected_env)
}

fn is_protected_env() -> bool {
    let env_name = std::env::var("EASYENCLAVE_ENV")
        .or_else(|_| std::env::var("CP_ENV"))
        .unwrap_or_else(|_| "local".to_string())
        .to_ascii_lowercase();
    matches!(env_name.as_str(), "staging" | "production" | "prod")
}

fn control_plane_public_hostname() -> Option<String> {
    if let Ok(host) = std::env::var("CP_PUBLIC_HOSTNAME") {
        let trimmed = host.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_ascii_lowercase());
        }
    }
    let cp_url = std::env::var("EASYENCLAVE_CP_URL").ok()?;
    hostname_from_url(&cp_url)
}

fn hostname_from_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let no_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    let host_port = no_scheme.split('/').next().unwrap_or_default();
    let host = host_port.split(':').next().unwrap_or_default().trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

fn control_plane_tunnel_name() -> String {
    if let Ok(name) = std::env::var("CP_PUBLIC_TUNNEL_NAME") {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let env_name = std::env::var("EASYENCLAVE_ENV")
        .unwrap_or_else(|_| "local".to_string())
        .to_ascii_lowercase();
    format!("cp-{env_name}")
}

fn start_cloudflared_supervisor(token: String) {
    let token = token.trim().to_string();
    if token.is_empty() {
        eprintln!("ee-cp: skipping cloudflared start (empty token)");
        return;
    }
    if token.starts_with("pending-") {
        eprintln!("ee-cp: skipping cloudflared start (pending token)");
        return;
    }

    thread::spawn(move || loop {
        match spawn_cloudflared(&token) {
            Ok(mut child) => {
                eprintln!("ee-cp: started cloudflared pid={}", child.id());
                match child.wait() {
                    Ok(status) => {
                        eprintln!("ee-cp: cloudflared exited status={status}; restarting")
                    }
                    Err(err) => eprintln!("ee-cp: cloudflared wait failed: {err}; restarting"),
                }
            }
            Err(err) => eprintln!("ee-cp: failed to start cloudflared: {err}; retrying"),
        }
        thread::sleep(Duration::from_secs(3));
    });
}

fn spawn_cloudflared(token: &str) -> Result<Child, std::io::Error> {
    Command::new("cloudflared")
        .args(["tunnel", "run", "--token", token])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
}
