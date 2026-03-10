use std::time::Duration;

use crate::common::error::{AppError, AppResult};
use crate::types::DeploymentStatus;
use serde_json::Value;

use crate::state::AppState;
use crate::stores::agent::AgentStore;
use crate::stores::deployment::DeploymentStore;
use crate::stores::health::HealthStore;

pub async fn run(state: AppState) {
    let tick_seconds = state.heartbeat_interval_seconds.max(1);
    let mut interval = tokio::time::interval(Duration::from_secs(tick_seconds));
    loop {
        interval.tick().await;
        if let Err(err) = run_once(&state).await {
            eprintln!("health monitor tick failed: {err}");
        }
    }
}

pub async fn run_once(state: &AppState) -> AppResult<()> {
    let deployment_store = DeploymentStore::new(state.db_pool.clone());
    let agent_store = AgentStore::new(state.db_pool.clone());
    let health_store = HealthStore::new(state.db_pool.clone());
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(state.check_timeout_seconds.max(1)))
        .build()
        .map_err(|e| AppError::External(format!("failed to build probe client: {e}")))?;

    let now_unix = chrono::Utc::now().timestamp();
    let stale_after_seconds =
        (state.heartbeat_interval_seconds + state.check_timeout_seconds) as i64;
    let targets = deployment_store.list_active_targets().await?;

    for target in targets {
        let deployment_exempt = target.status == DeploymentStatus::Deploying;
        let probe = if let Some(base_url) = normalize_base_url(target.hostname.as_deref()) {
            Some(
                probe_agent(
                    &http,
                    &base_url,
                    &state.agent_health_path,
                    state.agent_attestation_path.as_deref(),
                )
                .await,
            )
        } else {
            None
        };

        let (check_ok, attestation_ok, failure_reason) = if let Some(probe) = probe {
            (probe.check_ok, probe.attestation_ok, probe.failure_reason)
        } else {
            let last_check_unix = health_store
                .last_check_unix_for_agent(target.agent_id)
                .await?;
            let reference = last_check_unix.unwrap_or(target.created_at_unix);
            if now_unix - reference <= stale_after_seconds {
                continue;
            }
            (false, true, Some("missing_check_timeout".to_string()))
        };

        if check_ok && deployment_exempt {
            let _ = deployment_store
                .promote_deploying_to_running_for_agent(target.agent_id)
                .await;
            let _ = agent_store
                .update_status(target.agent_id, crate::types::AgentStatus::Deployed)
                .await;
        }

        let counted_down = !deployment_exempt;
        let _ = agent_store
            .record_check_result(
                target.agent_id,
                check_ok,
                attestation_ok,
                counted_down && !check_ok,
                state.down_after_failures,
                state.recover_after_successes,
            )
            .await?;

        health_store
            .insert_check(
                target.agent_id,
                &target.app_name,
                check_ok,
                deployment_exempt,
                failure_reason.as_deref(),
            )
            .await?;
    }

    Ok(())
}

fn normalize_base_url(hostname: Option<&str>) -> Option<String> {
    let raw = hostname?.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.starts_with("http://") || raw.starts_with("https://") {
        return Some(raw.trim_end_matches('/').to_string());
    }
    Some(format!("https://{}", raw.trim_end_matches('/')))
}

#[derive(Debug)]
struct ProbeResult {
    check_ok: bool,
    attestation_ok: bool,
    failure_reason: Option<String>,
}

async fn probe_agent(
    client: &reqwest::Client,
    base_url: &str,
    health_path: &str,
    attestation_path: Option<&str>,
) -> ProbeResult {
    let health_url = format!("{base_url}{health_path}");
    let health_resp = match client.get(health_url).send().await {
        Ok(resp) => resp,
        Err(_) => {
            return ProbeResult {
                check_ok: false,
                attestation_ok: true,
                failure_reason: Some("health_probe_error".to_string()),
            };
        }
    };
    if !health_resp.status().is_success() {
        return ProbeResult {
            check_ok: false,
            attestation_ok: true,
            failure_reason: Some("health_probe_status".to_string()),
        };
    }

    let mut attestation_ok = true;
    let mut failure_reason = None;
    let health_json: Option<Value> = health_resp.json().await.ok();
    if let Some(v) = health_json
        .as_ref()
        .and_then(|json| json.get("attestation_ok"))
        .and_then(Value::as_bool)
    {
        attestation_ok = v;
        if !v {
            failure_reason = Some("attestation_unhealthy".to_string());
        }
    }

    if let Some(path) = attestation_path {
        let attestation_url = format!("{base_url}{path}");
        match client.get(attestation_url).send().await {
            Ok(resp) if resp.status().is_success() => {}
            Ok(_) => {
                attestation_ok = false;
                if failure_reason.is_none() {
                    failure_reason = Some("attestation_probe_status".to_string());
                }
            }
            Err(_) => {
                attestation_ok = false;
                if failure_reason.is_none() {
                    failure_reason = Some("attestation_probe_error".to_string());
                }
            }
        }
    }

    ProbeResult {
        check_ok: attestation_ok,
        attestation_ok,
        failure_reason,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use mockito::Server;
    use sqlx::sqlite::SqlitePoolOptions;
    use uuid::Uuid;

    use crate::services::attestation::AttestationService;
    use crate::services::github_oidc::GithubOidcService;
    use crate::services::nonce::NonceService;
    use crate::services::tunnel::TunnelService;
    use crate::state::AppState;
    use crate::stores::agent::AgentStore;
    use crate::stores::deployment::{DeploymentStore, NewDeployment};
    use crate::stores::health::HealthStore;
    use crate::stores::setting::SettingsStore;
    use crate::types::{AgentRegistrationState, AgentStatus, DeploymentStatus};

    #[tokio::test]
    async fn run_once_marks_stale_running_target_as_failed_check() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("pool");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrate");

        let settings = SettingsStore::new_with_ttl(pool.clone(), Duration::from_secs(5));
        let nonce = NonceService::new(Duration::from_secs(300));
        let attestation = AttestationService::insecure_for_tests();
        let github_oidc = GithubOidcService::disabled_for_tests();
        let tunnel = TunnelService::disabled_for_tests();
        let mut state = AppState::new(
            "boot-test".to_string(),
            None,
            None,
            pool.clone(),
            settings,
            nonce,
            attestation,
            github_oidc,
            tunnel,
        );
        state.heartbeat_interval_seconds = 1;
        state.check_timeout_seconds = 1;
        state.down_after_failures = 1;

        let deployments = DeploymentStore::new(pool.clone());
        let agents = AgentStore::new(pool.clone());
        let agent = agents
            .create(
                "monitor-agent",
                AgentStatus::Deployed,
                AgentRegistrationState::Ready,
                true,
                Some("standard"),
                Some("gcp:test"),
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .expect("create agent");
        let _ = deployments
            .create(NewDeployment {
                compose: "services: {}".to_string(),
                app_name: Some("monitor-app".to_string()),
                app_version: Some("v1".to_string()),
                agent_id: agent.agent_id,
                account_id: Uuid::new_v4(),
                auth_method: "api_key".to_string(),
                status: DeploymentStatus::Running,
                cpu_vcpus: 1,
                memory_gb: 1.0,
                gpu_count: 0,
            })
            .await
            .expect("create deployment");

        tokio::time::sleep(Duration::from_secs(3)).await;
        super::run_once(&state).await.expect("run once");

        let stats = HealthStore::new(pool.clone())
            .recent_app_stats(24, 1)
            .await
            .expect("stats");
        let app = stats
            .apps
            .iter()
            .find(|a| a.app_name == "monitor-app")
            .expect("monitor app");
        assert!(app.failed_checks >= 1);
        assert!(!app.perfect_now);
    }

    #[tokio::test]
    async fn run_once_uses_http_health_probe_when_hostname_present() {
        let mut server = Server::new_async().await;
        let _health_mock = server
            .mock("GET", "/health")
            .with_status(200)
            .with_body(r#"{"ok":true,"attestation_ok":true}"#)
            .create_async()
            .await;

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("pool");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrate");

        let settings = SettingsStore::new_with_ttl(pool.clone(), Duration::from_secs(5));
        let nonce = NonceService::new(Duration::from_secs(300));
        let attestation = AttestationService::insecure_for_tests();
        let github_oidc = GithubOidcService::disabled_for_tests();
        let tunnel = TunnelService::disabled_for_tests();
        let mut state = AppState::new(
            "boot-test".to_string(),
            None,
            None,
            pool.clone(),
            settings,
            nonce,
            attestation,
            github_oidc,
            tunnel,
        );
        state.agent_health_path = "/health".to_string();
        state.agent_attestation_path = None;
        state.down_after_failures = 1;

        let deployments = DeploymentStore::new(pool.clone());
        let agents = AgentStore::new(pool.clone());
        let agent = agents
            .create(
                "probe-agent",
                AgentStatus::Deployed,
                AgentRegistrationState::Ready,
                true,
                Some("standard"),
                Some("gcp:test"),
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .expect("create agent");
        agents
            .set_tunnel(agent.agent_id, "tunnel-id", &server.url(), "token")
            .await
            .expect("set tunnel");
        let _ = deployments
            .create(NewDeployment {
                compose: "services: {}".to_string(),
                app_name: Some("probe-app".to_string()),
                app_version: Some("v1".to_string()),
                agent_id: agent.agent_id,
                account_id: Uuid::new_v4(),
                auth_method: "api_key".to_string(),
                status: DeploymentStatus::Running,
                cpu_vcpus: 1,
                memory_gb: 1.0,
                gpu_count: 0,
            })
            .await
            .expect("create deployment");

        super::run_once(&state).await.expect("run once");

        let stats = HealthStore::new(pool.clone())
            .recent_app_stats(24, 1)
            .await
            .expect("stats");
        let app = stats
            .apps
            .iter()
            .find(|a| a.app_name == "probe-app")
            .expect("probe app");
        assert!(app.checks_total >= 1);
        assert_eq!(app.failed_checks, 0);
        assert!(app.perfect_now);
    }
}
