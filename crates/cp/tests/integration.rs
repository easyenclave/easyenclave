//! Integration tests: CP with built-in aggregator, agent registration, full lifecycle.

use ee_common::types::*;
use std::collections::HashMap;

fn test_cp_config() -> ee_cp::config::CpConfig {
    ee_cp::config::CpConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        db_path: ":memory:".to_string(),
        builtin_aggregator: true,
        trusted_aggregator_ids: vec![],
        admin_github_logins: vec![],
        github_oauth_client_id: String::new(),
        github_oauth_client_secret: String::new(),
        github_oauth_redirect_uri: String::new(),
    }
}

#[tokio::test]
async fn test_cp_starts_with_builtin_aggregator() {
    let config = test_cp_config();
    let handle = ee_cp::start(config).await.unwrap();

    assert!(handle.builtin_aggregator.is_some());

    // Health check
    let client = ee_common::http::build_client();
    let resp = client
        .get(format!("{}/api/health", handle.url))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let health: HealthResponse = resp.json().await.unwrap();
    assert_eq!(health.status, "ok");

    handle.shutdown().await;
}

#[tokio::test]
async fn test_agent_registers_with_cp() {
    let config = test_cp_config();
    let handle = ee_cp::start(config).await.unwrap();

    let client = ee_common::http::build_client();
    let agent_id = uuid::Uuid::new_v4();

    let registration = AgentRegistration {
        url: "http://127.0.0.1:9999".to_string(),
        size: VmSize::Medium,
        cloud: Cloud::Gcp,
        region: "us-central1".to_string(),
        tags: vec!["test".to_string()],
        attestation_token: None,
        secret: "test-secret".to_string(),
    };

    // Verify aggregator routes are available
    let probe = client
        .get(format!("{}/api/state", handle.url))
        .send()
        .await
        .unwrap();
    assert!(
        probe.status().is_success(),
        "aggregator /api/state not available: {}",
        probe.status()
    );

    // Register agent
    let url = format!("{}/api/v1/agents/{}/register", handle.url, agent_id);
    let resp = client.post(&url).json(&registration).send().await.unwrap();

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "registration at {url} failed: {status} - {body}"
    );

    // Verify agent shows up in aggregator state
    let resp = client
        .get(format!("{}/api/state", handle.url))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let state: AggregatorState = resp.json().await.unwrap();
    assert_eq!(state.agents.len(), 1);
    assert_eq!(state.agents[0].id.0, agent_id);
    assert_eq!(state.agents[0].size, VmSize::Medium);

    handle.shutdown().await;
}

#[tokio::test]
async fn test_measurement_submission() {
    let config = test_cp_config();
    let handle = ee_cp::start(config).await.unwrap();

    let client = ee_common::http::build_client();

    // Submit a measurement
    let measurement = MeasurementSubmission {
        size: VmSize::Medium,
        cloud: Cloud::Gcp,
        mrtd: "abc123def456".to_string(),
        release_tag: Some("v0.1.0".to_string()),
    };

    let resp = client
        .post(format!("{}/api/v1/measurements", handle.url))
        .json(&measurement)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // List measurements
    let resp = client
        .get(format!("{}/api/v1/measurements", handle.url))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let mrtds: Vec<TrustedMrtd> = resp.json().await.unwrap();
    assert_eq!(mrtds.len(), 1);
    assert_eq!(mrtds[0].mrtd, "abc123def456");
    assert_eq!(mrtds[0].size, VmSize::Medium);

    handle.shutdown().await;
}

#[tokio::test]
async fn test_trusted_aggregator_management() {
    let config = test_cp_config();
    let handle = ee_cp::start(config).await.unwrap();

    let client = ee_common::http::build_client();
    let agg_id = uuid::Uuid::new_v4().to_string();

    // Add trusted aggregator
    let resp = client
        .post(format!("{}/api/v1/aggregators/trust", handle.url))
        .json(&serde_json::json!({"aggregator_id": agg_id}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // List trusted
    let resp = client
        .get(format!("{}/api/v1/aggregators/trust", handle.url))
        .send()
        .await
        .unwrap();
    let ids: Vec<String> = resp.json().await.unwrap();
    assert!(ids.contains(&agg_id));

    // Remove trusted
    let resp = client
        .delete(format!(
            "{}/api/v1/aggregators/trust/{}",
            handle.url, agg_id
        ))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "remove trusted failed: {status} - {body}"
    );

    // Verify removed
    let resp = client
        .get(format!("{}/api/v1/aggregators/trust", handle.url))
        .send()
        .await
        .unwrap();
    let ids: Vec<String> = resp.json().await.unwrap();
    assert!(!ids.contains(&agg_id));

    handle.shutdown().await;
}

#[tokio::test]
async fn test_billing_listings() {
    let config = test_cp_config();
    let handle = ee_cp::start(config).await.unwrap();

    let client = ee_common::http::build_client();

    // List billing listings (should be empty)
    let resp = client
        .get(format!("{}/api/v1/billing/listings", handle.url))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let listings: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(listings.is_empty());

    handle.shutdown().await;
}

#[tokio::test]
async fn test_deploy_undeploy_via_cp() {
    let config = test_cp_config();
    let handle = ee_cp::start(config).await.unwrap();

    let client = ee_common::http::build_client();

    // Register an agent first
    let agent_id = uuid::Uuid::new_v4();
    let registration = AgentRegistration {
        url: "http://127.0.0.1:9998".to_string(),
        size: VmSize::Small,
        cloud: Cloud::Gcp,
        region: "us-east1".to_string(),
        tags: vec![],
        attestation_token: None,
        secret: "test".to_string(),
    };

    client
        .post(format!(
            "{}/api/v1/agents/{}/register",
            handle.url, agent_id
        ))
        .json(&registration)
        .send()
        .await
        .unwrap();

    // Deploy — this will attempt to relay to the fake agent URL.
    // Since there's no real agent running, we expect the relay to fail with 500.
    let deploy_req = DeployRequest {
        app_name: "test-app".to_string(),
        image: "nginx:latest".to_string(),
        env_vars: HashMap::new(),
        owner: "testuser".to_string(),
    };

    let resp = client
        .post(format!("{}/api/deploy", handle.url))
        .json(&deploy_req)
        .send()
        .await
        .unwrap();
    // Relay should fail because there's no real agent at 127.0.0.1:9998
    assert_eq!(
        resp.status().as_u16(),
        500,
        "expected relay failure to fake agent"
    );

    // Undeploy — same, relay to agent fails
    let undeploy_req = UndeployRequest {
        app_name: "test-app".to_string(),
    };

    let resp = client
        .post(format!("{}/api/undeploy", handle.url))
        .json(&undeploy_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        500,
        "expected relay failure to fake agent"
    );

    handle.shutdown().await;
}
