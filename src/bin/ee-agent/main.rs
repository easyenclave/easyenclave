mod config;
mod measure;
mod oci;
mod cp_client_api {
    include!(concat!(env!("OUT_DIR"), "/cp_client_api.rs"));
}

use std::collections::HashMap;
use std::fs;
use std::process::{Child, Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::cp_client_api::{AgentChallengeResponse, AgentRegisterResponse};
use config::{AgentMode, AgentRuntimeConfig, ProvidedApp};
use easyenclave::attestation::tsm::generate_tdx_quote_base64;
use easyenclave::common::error::{AppError, AppResult};
use oci::{DockerOciRuntime, LaunchRequest, OciRuntimeEngine, PortMapping};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

const TSM_REPORT_PATH: &str = "/sys/kernel/config/tsm/report";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ee-agent error: {err}");
            ExitCode::from(1)
        }
    }
}

fn run() -> AppResult<()> {
    let cfg = AgentRuntimeConfig::load()?;
    match cfg.mode {
        AgentMode::Agent => run_agent_mode(&cfg),
        AgentMode::ControlPlane => run_control_plane_mode(&cfg),
        AgentMode::Measure => measure::run_measure_mode(),
    }
}

fn run_agent_mode(cfg: &AgentRuntimeConfig) -> AppResult<()> {
    let cp_url = cfg
        .control_plane_url
        .as_ref()
        .ok_or_else(|| AppError::Config("agent mode requires control_plane_url".to_string()))?
        .to_string();
    let vm_name = resolve_vm_name();
    let runtime = DockerOciRuntime::new();

    eprintln!(
        "ee-agent: mode=agent cp_url={cp_url} vm_name={vm_name} node_size={} datacenter={} oci_backend={} ita_key_present={}",
        cfg.node_size,
        cfg.datacenter,
        runtime.backend_name(),
        cfg.intel_api_key.is_some(),
    );

    let reconcile_interval_seconds = std::env::var("AGENT_CP_RECONCILE_INTERVAL_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30)
        .max(5);
    let probe_failures_before_reregister =
        std::env::var("AGENT_CP_RECONCILE_FAILURES_BEFORE_REREGISTER")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(3)
            .max(1);

    eprintln!(
        "ee-agent: cp reconcile interval={}s failures_before_reregister={}",
        reconcile_interval_seconds, probe_failures_before_reregister
    );

    let mut registered = register_with_retries(cfg, &cp_url, &vm_name)?;
    let mut tunnel = start_cloudflared(&registered.tunnel_token)?;
    let mut consecutive_probe_failures: u32 = 0;
    let mut next_reconcile = Instant::now() + Duration::from_secs(reconcile_interval_seconds);

    if let Some(app) = cfg.provided_app {
        run_provided_app(cfg, &runtime, app)?;
    }

    loop {
        let mut cloudflared_exited = false;
        if let Some(child) = &mut tunnel {
            let maybe_status = child.try_wait().map_err(command_err)?;
            if let Some(status) = maybe_status {
                eprintln!("ee-agent: cloudflared exited with status={status}; re-registering");
                cloudflared_exited = true;
            }
        }

        if cloudflared_exited {
            registered = register_with_retries(cfg, &cp_url, &vm_name)?;
            tunnel = restart_cloudflared(tunnel, &registered.tunnel_token)?;
            consecutive_probe_failures = 0;
        }

        let now = Instant::now();
        if now >= next_reconcile {
            next_reconcile = now + Duration::from_secs(reconcile_interval_seconds);
            match is_vm_registered_on_cp(&cp_url, &vm_name) {
                Ok(true) => {
                    if consecutive_probe_failures > 0 {
                        eprintln!(
                            "ee-agent: cp registration probe recovered after {} failures",
                            consecutive_probe_failures
                        );
                    }
                    consecutive_probe_failures = 0;
                }
                Ok(false) => {
                    eprintln!(
                        "ee-agent: vm_name={} missing from cp agent list; re-registering",
                        vm_name
                    );
                    registered = register_with_retries(cfg, &cp_url, &vm_name)?;
                    tunnel = restart_cloudflared(tunnel, &registered.tunnel_token)?;
                    consecutive_probe_failures = 0;
                }
                Err(err) => {
                    consecutive_probe_failures = consecutive_probe_failures.saturating_add(1);
                    eprintln!(
                        "ee-agent: cp registration probe failed attempt={} error={}",
                        consecutive_probe_failures, err
                    );
                    if consecutive_probe_failures >= probe_failures_before_reregister {
                        eprintln!(
                            "ee-agent: cp probe failures reached {}; forcing re-registration",
                            probe_failures_before_reregister
                        );
                        registered = register_with_retries(cfg, &cp_url, &vm_name)?;
                        tunnel = restart_cloudflared(tunnel, &registered.tunnel_token)?;
                        consecutive_probe_failures = 0;
                    }
                }
            }
        }

        thread::sleep(Duration::from_secs(10));
    }
}
fn run_control_plane_mode(cfg: &AgentRuntimeConfig) -> AppResult<()> {
    let image = cfg.control_plane_image.as_ref().ok_or_else(|| {
        AppError::Config("control-plane mode requires control_plane_image".to_string())
    })?;

    let runtime = DockerOciRuntime::new();
    let request = LaunchRequest {
        name: "easyenclave-control-plane".to_string(),
        image: image.clone(),
        env: build_control_plane_env(cfg),
        ports: vec![PortMapping::tcp(cfg.port, 8080)],
        binds: vec!["/var/run/docker.sock:/var/run/docker.sock:ro".to_string()],
        restart_unless_stopped: true,
    };

    eprintln!(
        "ee-agent: mode=control-plane image={} port={} oci_backend={}",
        request.image,
        cfg.port,
        runtime.backend_name()
    );
    runtime.launch(&request)?;

    loop {
        thread::sleep(Duration::from_secs(30));
    }
}

fn run_provided_app(
    cfg: &AgentRuntimeConfig,
    runtime: &dyn OciRuntimeEngine,
    app: ProvidedApp,
) -> AppResult<()> {
    let request = match app {
        ProvidedApp::ControlPlane => {
            let image = cfg.control_plane_image.as_ref().ok_or_else(|| {
                AppError::Config(
                    "provided_app=control-plane requires control_plane_image".to_string(),
                )
            })?;
            LaunchRequest {
                name: "easyenclave-control-plane".to_string(),
                image: image.clone(),
                env: build_control_plane_env(cfg),
                ports: vec![PortMapping::tcp(cfg.port, 8080)],
                binds: vec!["/var/run/docker.sock:/var/run/docker.sock:ro".to_string()],
                restart_unless_stopped: true,
            }
        }
        ProvidedApp::Measure => {
            let image = cfg.measure_app_image.as_ref().ok_or_else(|| {
                AppError::Config("provided_app=measure requires measure_app_image".to_string())
            })?;
            LaunchRequest {
                name: "easyenclave-measure".to_string(),
                image: image.clone(),
                env: vec![],
                ports: vec![],
                binds: vec![],
                restart_unless_stopped: true,
            }
        }
    };

    eprintln!(
        "ee-agent: launching provided app name={} image={} via {}",
        request.name,
        request.image,
        runtime.backend_name()
    );
    runtime.launch(&request)
}

fn build_control_plane_env(cfg: &AgentRuntimeConfig) -> Vec<(String, String)> {
    let mut env: HashMap<String, String> = HashMap::new();

    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "cloudflare_api_token",
        "CLOUDFLARE_API_TOKEN",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "cloudflare_account_id",
        "CLOUDFLARE_ACCOUNT_ID",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "cloudflare_zone_id",
        "CLOUDFLARE_ZONE_ID",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "easyenclave_domain",
        "EASYENCLAVE_DOMAIN",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "easyenclave_cp_url",
        "EASYENCLAVE_CP_URL",
    );
    insert_mapped(&mut env, &cfg.raw_kv, "easyenclave_env", "EASYENCLAVE_ENV");
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "easyenclave_network_name",
        "EASYENCLAVE_NETWORK_NAME",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "easyenclave_boot_id",
        "EASYENCLAVE_BOOT_ID",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "easyenclave_git_sha",
        "EASYENCLAVE_GIT_SHA",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "easyenclave_release_tag",
        "EASYENCLAVE_RELEASE_TAG",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "ee_agent_ita_api_key",
        "EE_AGENT_ITA_API_KEY",
    );
    insert_mapped(&mut env, &cfg.raw_kv, "gcp_project_id", "GCP_PROJECT_ID");
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "gcp_service_account_key",
        "GCP_SERVICE_ACCOUNT_KEY",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "ee_gcp_image_project",
        "EE_GCP_IMAGE_PROJECT",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "ee_gcp_image_family",
        "EE_GCP_IMAGE_FAMILY",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "ee_gcp_image_name",
        "EE_GCP_IMAGE_NAME",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "github_oauth_client_id",
        "GITHUB_OAUTH_CLIENT_ID",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "github_oauth_client_secret",
        "GITHUB_OAUTH_CLIENT_SECRET",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "github_oauth_redirect_uri",
        "GITHUB_OAUTH_REDIRECT_URI",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "cp_github_oidc_audience",
        "CP_GITHUB_OIDC_AUDIENCE",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "cp_github_oidc_jwks_url",
        "CP_GITHUB_OIDC_JWKS_URL",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "cp_github_oidc_issuer",
        "CP_GITHUB_OIDC_ISSUER",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "cp_github_oidc_jwks_ttl_seconds",
        "CP_GITHUB_OIDC_JWKS_TTL_SECONDS",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "admin_github_logins",
        "ADMIN_GITHUB_LOGINS",
    );
    insert_mapped(&mut env, &cfg.raw_kv, "admin_password", "CP_ADMIN_PASSWORD");
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "admin_password_hash",
        "ADMIN_PASSWORD_HASH",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "cp_measurements_signing_key",
        "CP_MEASUREMENTS_SIGNING_KEY",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "stripe_secret_key",
        "STRIPE_SECRET_KEY",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "stripe_webhook_secret",
        "STRIPE_WEBHOOK_SECRET",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "cp_attestation_allow_insecure",
        "CP_ATTESTATION_ALLOW_INSECURE",
    );
    insert_mapped(&mut env, &cfg.raw_kv, "cp_ita_jwks_url", "CP_ITA_JWKS_URL");
    insert_mapped(&mut env, &cfg.raw_kv, "cp_ita_issuer", "CP_ITA_ISSUER");
    insert_mapped(&mut env, &cfg.raw_kv, "cp_ita_audience", "CP_ITA_AUDIENCE");
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "cp_ita_jwks_ttl_seconds",
        "CP_ITA_JWKS_TTL_SECONDS",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "tcb_enforcement_mode",
        "CP_TCB_ENFORCEMENT_MODE",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "rtmr_enforcement_mode",
        "CP_RTMR_ENFORCEMENT_MODE",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "nonce_enforcement_mode",
        "CP_NONCE_ENFORCEMENT_MODE",
    );

    // Keep legacy unprefixed policy env names as compatibility shims.
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "tcb_enforcement_mode",
        "TCB_ENFORCEMENT_MODE",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "rtmr_enforcement_mode",
        "RTMR_ENFORCEMENT_MODE",
    );
    insert_mapped(
        &mut env,
        &cfg.raw_kv,
        "nonce_enforcement_mode",
        "NONCE_ENFORCEMENT_MODE",
    );

    for key in [
        "trusted_agent_mrtds",
        "trusted_proxy_mrtds",
        "trusted_agent_rtmrs",
        "trusted_proxy_rtmrs",
        "trusted_agent_rtmrs_by_size",
        "trusted_proxy_rtmrs_by_size",
    ] {
        if let Some(value) = cfg.raw_kv.get(key) {
            env.insert(key.to_ascii_uppercase(), value.clone());
        }
    }

    if let Some(git_sha) = cfg.raw_kv.get("easyenclave_git_sha") {
        if !git_sha.trim().is_empty() {
            env.insert("GIT_SHA".to_string(), git_sha.clone());
        }
    }
    env.entry("CP_BIND_ADDR".to_string())
        .or_insert_with(|| "0.0.0.0:8080".to_string());
    env.entry("CP_DATABASE_URL".to_string())
        .or_insert_with(|| "sqlite://easyenclave.db?mode=rwc".to_string());

    let mut out: Vec<(String, String)> = env.into_iter().collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn insert_mapped(
    target: &mut HashMap<String, String>,
    source: &HashMap<String, String>,
    source_key: &str,
    env_key: &str,
) {
    if let Some(value) = source.get(source_key) {
        if !value.trim().is_empty() {
            target.insert(env_key.to_string(), value.clone());
        }
    }
}

fn resolve_vm_name() -> String {
    if let Ok(vm_name) = std::env::var("VM_NAME") {
        if !vm_name.trim().is_empty() {
            return vm_name;
        }
    }
    if let Ok(hostname) = fs::read_to_string("/etc/hostname") {
        let value = hostname.trim().to_string();
        if !value.is_empty() {
            return value;
        }
    }
    if let Ok(value) = gcp_metadata_get("instance/name") {
        if !value.trim().is_empty() {
            return value;
        }
    }
    format!("tdx-agent-{}", &Uuid::new_v4().simple().to_string()[..8])
}

fn register_with_retries(
    cfg: &AgentRuntimeConfig,
    cp_url: &str,
    vm_name: &str,
) -> AppResult<RegisteredAgent> {
    let max_attempts = std::env::var("AGENT_REGISTRATION_MAX_ATTEMPTS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let retry_base = std::env::var("AGENT_REGISTRATION_RETRY_BASE_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(3)
        .max(1);

    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match register_once(cfg, cp_url, vm_name) {
            Ok(ok) => return Ok(ok),
            Err(err) => {
                eprintln!("ee-agent: registration attempt {attempt} failed: {err}");
                if max_attempts > 0 && attempt >= max_attempts {
                    return Err(err);
                }
                let sleep_s = (retry_base * u64::from(attempt)).min(60);
                thread::sleep(Duration::from_secs(sleep_s));
            }
        }
    }
}

fn register_once(
    cfg: &AgentRuntimeConfig,
    cp_url: &str,
    vm_name: &str,
) -> AppResult<RegisteredAgent> {
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| AppError::External(format!("http client init failed: {e}")))?;
    let nonce = request_nonce(&client, cp_url)?;
    let quote_b64 = generate_quote_with_nonce(&nonce)?;
    let ita_token = mint_ita_token(cfg, &client, &quote_b64)?;

    let payload = json!({
        "intel_ta_token": ita_token,
        "vm_name": vm_name,
        "nonce": nonce,
        "node_size": cfg.node_size,
        "datacenter": cfg.datacenter,
    });

    let url = format!("{}/api/agents/register", cp_url.trim_end_matches('/'));
    let resp = client
        .post(url)
        .json(&payload)
        .send()
        .map_err(|e| AppError::External(format!("register request failed: {e}")))?;
    let status = resp.status();
    if status != StatusCode::OK {
        let body = resp.text().unwrap_or_default();
        return Err(AppError::External(format!(
            "register failed status={} body={}",
            status, body
        )));
    }
    let result: AgentRegisterResponse = resp
        .json()
        .map_err(|e| AppError::External(format!("register response parse failed: {e}")))?;

    eprintln!(
        "ee-agent: registered agent_id={} hostname={}",
        result.agent_id, result.hostname
    );

    Ok(RegisteredAgent {
        tunnel_token: result.tunnel_token,
    })
}

fn request_nonce(client: &Client, cp_url: &str) -> AppResult<String> {
    let url = format!("{}/api/agents/challenge", cp_url.trim_end_matches('/'));
    let resp = client
        .get(url)
        .send()
        .map_err(|e| AppError::External(format!("challenge request failed: {e}")))?;
    let status = resp.status();
    if status != StatusCode::OK {
        let body = resp.text().unwrap_or_default();
        return Err(AppError::External(format!(
            "challenge failed status={} body={}",
            status, body
        )));
    }
    let payload: AgentChallengeResponse = resp
        .json()
        .map_err(|e| AppError::External(format!("challenge parse failed: {e}")))?;
    if payload.nonce.trim().is_empty() {
        return Err(AppError::External(
            "challenge response missing nonce".to_string(),
        ));
    }
    Ok(payload.nonce)
}

fn generate_quote_with_nonce(nonce: &str) -> AppResult<String> {
    let nonce_bytes = hex_to_bytes(nonce)
        .ok_or_else(|| AppError::External("nonce is not valid hex".to_string()))?;
    generate_tdx_quote_base64(TSM_REPORT_PATH, Some(&nonce_bytes))
}

fn hex_to_bytes(input: &str) -> Option<Vec<u8>> {
    let normalized = input.trim();
    if !normalized.len().is_multiple_of(2) || normalized.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(normalized.len() / 2);
    let mut chars = normalized.chars();
    while let (Some(hi), Some(lo)) = (chars.next(), chars.next()) {
        let pair = format!("{hi}{lo}");
        let byte = u8::from_str_radix(&pair, 16).ok()?;
        out.push(byte);
    }
    Some(out)
}

fn mint_ita_token(cfg: &AgentRuntimeConfig, client: &Client, quote_b64: &str) -> AppResult<String> {
    let api_key = cfg.intel_api_key.as_ref().ok_or_else(|| {
        AppError::Config("agent mode requires ITA_API_KEY/INTEL_API_KEY".to_string())
    })?;
    let api_url = std::env::var("ITA_API_URL")
        .or_else(|_| std::env::var("INTEL_API_URL"))
        .unwrap_or_else(|_| "https://api.trustauthority.intel.com".to_string());
    let base = normalize_ita_base_url(&api_url);
    let url = format!("{base}/appraisal/v1/attest");

    let resp = client
        .post(url)
        .header("x-api-key", api_key)
        .header("accept", "application/json")
        .json(&json!({ "quote": quote_b64 }))
        .send()
        .map_err(|e| AppError::External(format!("ITA attest request failed: {e}")))?;
    let status = resp.status();
    if status != StatusCode::OK {
        let body = resp.text().unwrap_or_default();
        return Err(AppError::External(format!(
            "ITA attest failed status={} body={}",
            status, body
        )));
    }
    let value: Value = resp
        .json()
        .map_err(|e| AppError::External(format!("ITA response parse failed: {e}")))?;
    let token = value
        .get("token")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    if token.is_empty() {
        return Err(AppError::External(
            "ITA response missing token field".to_string(),
        ));
    }
    Ok(token)
}

fn normalize_ita_base_url(raw: &str) -> String {
    let mut base = raw.trim().trim_end_matches('/').to_string();
    for suffix in ["/appraisal/v2", "/appraisal/v1", "/appraisal/v1/attest"] {
        if base.ends_with(suffix) {
            base = base
                .trim_end_matches(suffix)
                .trim_end_matches('/')
                .to_string();
            break;
        }
    }
    if base.is_empty() {
        "https://api.trustauthority.intel.com".to_string()
    } else {
        base
    }
}

fn start_cloudflared(token: &str) -> AppResult<Option<Child>> {
    let token = token.trim();
    if token.is_empty() {
        return Ok(None);
    }
    if token.starts_with("pending-") {
        eprintln!("ee-agent: tunnel token is pending placeholder, skipping cloudflared start");
        return Ok(None);
    }

    let version = Command::new("cloudflared")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if version.is_err() {
        return Err(AppError::External(
            "cloudflared is not installed on this VM".to_string(),
        ));
    }

    let child = Command::new("cloudflared")
        .args(["tunnel", "run", "--token", token])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(command_err)?;
    eprintln!("ee-agent: started cloudflared pid={}", child.id());
    Ok(Some(child))
}

fn stop_cloudflared(mut child: Child) -> AppResult<()> {
    if child.try_wait().map_err(command_err)?.is_some() {
        return Ok(());
    }

    child.kill().map_err(command_err)?;
    let _ = child.wait().map_err(command_err)?;
    Ok(())
}

fn restart_cloudflared(current: Option<Child>, token: &str) -> AppResult<Option<Child>> {
    if let Some(child) = current {
        stop_cloudflared(child)?;
    }
    start_cloudflared(token)
}

fn is_vm_registered_on_cp(cp_url: &str, vm_name: &str) -> AppResult<bool> {
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| AppError::External(format!("http client init failed: {e}")))?;

    let url = format!("{}/api/agents", cp_url.trim_end_matches('/'));
    let resp = client
        .get(url)
        .send()
        .map_err(|e| AppError::External(format!("agents list request failed: {e}")))?;
    let status = resp.status();
    if status != StatusCode::OK {
        let body = resp.text().unwrap_or_default();
        return Err(AppError::External(format!(
            "agents list failed status={} body={}",
            status, body
        )));
    }

    let payload: Vec<CpAgentListItem> = resp
        .json()
        .map_err(|e| AppError::External(format!("agents list parse failed: {e}")))?;
    Ok(payload.iter().any(|item| item.vm_name == vm_name))
}

fn gcp_metadata_get(path: &str) -> AppResult<String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| AppError::External(format!("http client init failed: {e}")))?;
    let url = format!(
        "http://metadata.google.internal/computeMetadata/v1/{}",
        path.trim_start_matches('/')
    );
    let resp = client
        .get(url)
        .header("Metadata-Flavor", "Google")
        .send()
        .map_err(|e| AppError::External(format!("gcp metadata request failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::External(format!(
            "gcp metadata returned status={}",
            resp.status()
        )));
    }
    let text = resp
        .text()
        .map_err(|e| AppError::External(format!("gcp metadata body read failed: {e}")))?;
    Ok(text.trim().to_string())
}

fn command_err(err: std::io::Error) -> AppError {
    AppError::External(format!("process launch failed: {err}"))
}

struct RegisteredAgent {
    tunnel_token: String,
}

#[derive(Debug, Deserialize)]
struct CpAgentListItem {
    vm_name: String,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::build_control_plane_env;
    use crate::config::{AgentMode, AgentRuntimeConfig};

    #[test]
    fn control_plane_env_includes_github_oidc_settings() {
        let mut raw_kv = HashMap::new();
        raw_kv.insert(
            "cp_github_oidc_audience".to_string(),
            "easyenclave".to_string(),
        );
        raw_kv.insert(
            "cp_github_oidc_jwks_url".to_string(),
            "https://token.actions.githubusercontent.com/.well-known/jwks".to_string(),
        );
        raw_kv.insert(
            "cp_github_oidc_issuer".to_string(),
            "https://token.actions.githubusercontent.com".to_string(),
        );
        raw_kv.insert(
            "cp_github_oidc_jwks_ttl_seconds".to_string(),
            "300".to_string(),
        );

        let cfg = AgentRuntimeConfig {
            mode: AgentMode::ControlPlane,
            control_plane_url: None,
            node_size: "tiny".to_string(),
            datacenter: "gcp:test".to_string(),
            intel_api_key: None,
            control_plane_image: Some("ghcr.io/example/control-plane:latest".to_string()),
            measure_app_image: None,
            provided_app: None,
            port: 8080,
            raw_kv,
        };

        let env: HashMap<String, String> = build_control_plane_env(&cfg).into_iter().collect();
        assert_eq!(
            env.get("CP_GITHUB_OIDC_AUDIENCE").map(String::as_str),
            Some("easyenclave")
        );
        assert_eq!(
            env.get("CP_GITHUB_OIDC_JWKS_URL").map(String::as_str),
            Some("https://token.actions.githubusercontent.com/.well-known/jwks")
        );
        assert_eq!(
            env.get("CP_GITHUB_OIDC_ISSUER").map(String::as_str),
            Some("https://token.actions.githubusercontent.com")
        );
        assert_eq!(
            env.get("CP_GITHUB_OIDC_JWKS_TTL_SECONDS")
                .map(String::as_str),
            Some("300")
        );
    }
}
