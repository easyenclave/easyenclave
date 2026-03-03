use std::error::Error;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use easyenclave::config::CpConfig;
use easyenclave::db::connect_and_migrate;
use easyenclave::routes::build_router;
use easyenclave::services::attestation::AttestationService;
use easyenclave::services::github_oidc::GithubOidcService;
use easyenclave::services::health_monitor;
use easyenclave::services::nonce::NonceService;
use easyenclave::services::tunnel::TunnelService;
use easyenclave::state::AppState;
use easyenclave::stores::setting::SettingsStore;

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

    let ingress_plan = desired_public_ingress_plan()?;

    run_server(
        config,
        ServerDeps {
            pool,
            settings,
            nonce,
            attestation,
            github_oidc,
            tunnel,
            ingress_plan,
        },
    )
    .await
}

struct ServerDeps {
    pool: sqlx::SqlitePool,
    settings: SettingsStore,
    nonce: NonceService,
    attestation: AttestationService,
    github_oidc: GithubOidcService,
    tunnel: TunnelService,
    ingress_plan: Option<IngressPlan>,
}

async fn run_server(
    config: easyenclave::config::CpConfig,
    deps: ServerDeps,
) -> Result<(), Box<dyn Error>> {
    let bind_addr = config.bind_addr.clone();
    let ingress_tunnel = deps.tunnel.clone();

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
        deps.pool,
        deps.settings,
        deps.nonce,
        deps.attestation,
        deps.github_oidc,
        deps.tunnel,
    );

    let monitor_state = state.clone();
    tokio::spawn(async move {
        health_monitor::run(monitor_state).await;
    });

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;

    if let Some(plan) = deps.ingress_plan {
        tokio::spawn(async move {
            provision_public_ingress_when_ready(ingress_tunnel, bind_addr, plan).await;
        });
    }

    axum::serve(listener, app).await?;

    Ok(())
}

#[derive(Debug, Clone)]
struct IngressPlan {
    tunnel_name: String,
    public_hostname: String,
}

fn desired_public_ingress_plan() -> Result<Option<IngressPlan>, Box<dyn Error>> {
    if !public_ingress_enabled() {
        return Ok(None);
    }

    let protected = is_protected_env();
    let Some(public_hostname) = control_plane_public_hostname() else {
        if protected {
            return Err(
                "missing control-plane public hostname (set EASYENCLAVE_CP_URL or CP_PUBLIC_HOSTNAME)"
                    .into(),
            );
        }
        eprintln!("ee-cp: public ingress disabled (no control-plane hostname configured)");
        return Ok(None);
    };

    Ok(Some(IngressPlan {
        tunnel_name: control_plane_tunnel_name(),
        public_hostname,
    }))
}

async fn provision_public_ingress_when_ready(
    tunnel: TunnelService,
    bind_addr: String,
    plan: IngressPlan,
) {
    if !wait_for_local_health(&bind_addr).await {
        eprintln!(
            "ee-cp: local health did not become ready; skipping public ingress reconcile hostname={}",
            plan.public_hostname
        );
        return;
    }

    match tunnel
        .create_tunnel_for_hostname(&plan.tunnel_name, &plan.public_hostname)
        .await
    {
        Ok(registration) => {
            eprintln!(
                "ee-cp: provisioned control-plane ingress hostname={} tunnel_id={}",
                registration.hostname, registration.tunnel_id
            );
            start_cloudflared_supervisor(registration.tunnel_token);
        }
        Err(err) => {
            eprintln!(
                "ee-cp: failed to provision control-plane ingress hostname={} error={}",
                plan.public_hostname, err
            );
        }
    }
}

async fn wait_for_local_health(bind_addr: &str) -> bool {
    let port = port_from_bind_addr(bind_addr).unwrap_or(8080);
    let url = format!("http://127.0.0.1:{port}/health");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("http client");

    for _ in 0..150 {
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    false
}

fn port_from_bind_addr(bind_addr: &str) -> Option<u16> {
    if let Ok(addr) = bind_addr.parse::<SocketAddr>() {
        return Some(addr.port());
    }
    bind_addr
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
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
    let mut name = format!("cp-{env_name}");
    let suffix = std::env::var("EASYENCLAVE_RELEASE_TAG")
        .ok()
        .or_else(|| std::env::var("EASYENCLAVE_BOOT_ID").ok())
        .or_else(|| std::env::var("EASYENCLAVE_GIT_SHA").ok())
        .map(|raw| sanitize_tunnel_name_component(&raw))
        .unwrap_or_default();
    if !suffix.is_empty() {
        let max_suffix = 63usize.saturating_sub(name.len() + 1);
        if max_suffix > 0 {
            name.push('-');
            name.push_str(&suffix[..suffix.len().min(max_suffix)]);
        }
    }
    name
}

fn sanitize_tunnel_name_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_dash = false;
    for ch in raw.chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '-'
        };
        if mapped == '-' {
            if prev_dash || out.is_empty() {
                continue;
            }
            prev_dash = true;
            out.push('-');
        } else {
            prev_dash = false;
            out.push(mapped);
        }
        if out.len() >= 63 {
            break;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
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
