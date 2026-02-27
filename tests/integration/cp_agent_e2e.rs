use std::{net::SocketAddr, sync::Arc};

use axum::{routing::post, Json, Router};
use ee_common::api::{ChallengeResponse, DeployRequest, PublishAppRequest, RegisterRequest};
use ee_common::config::CpConfig;

fn base_config() -> CpConfig {
    CpConfig {
        bind_addr: "127.0.0.1:0".to_owned(),
        database_url: "".to_owned(),
        domain: "easyenclave.local".to_owned(),
        cf_account_id: "".to_owned(),
        cf_api_token: "".to_owned(),
        cf_zone_id: "".to_owned(),
        ita_jwks_url: "https://ita.invalid/jwks".to_owned(),
        ita_appraisal_url: "https://ita.invalid/appraisal".to_owned(),
        ita_api_key: "".to_owned(),
        allow_insecure_test_attestation: true,
        github_oidc_jwks_url: "https://github.invalid/jwks".to_owned(),
        github_oidc_issuer: "https://token.actions.githubusercontent.com".to_owned(),
        github_oidc_audience: None,
        allow_insecure_test_oidc: true,
    }
}

async fn spawn_cp(config: CpConfig) -> (SocketAddr, reqwest::Client) {
    let app = ee_cp::app_from_config(config).await.expect("app setup");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (addr, reqwest::Client::new())
}

async fn get_challenge(client: &reqwest::Client, addr: SocketAddr) -> ChallengeResponse {
    client
        .get(format!("http://{addr}/api/v1/agents/challenge"))
        .send()
        .await
        .expect("challenge request")
        .error_for_status()
        .expect("challenge status")
        .json::<ChallengeResponse>()
        .await
        .expect("challenge json")
}

fn build_register(challenge_nonce: &str, quote_nonce: &str) -> RegisterRequest {
    let quote = ee_attestation::tsm::build_mock_quote_blob(&"ab".repeat(48), quote_nonce)
        .expect("build mock quote");

    RegisterRequest {
        vm_name: "ee-agent-test".to_owned(),
        owner: "github:org/easyenclave".to_owned(),
        node_size: "c3-standard-4".to_owned(),
        datacenter: "gcp:us-central1-a".to_owned(),
        quote_b64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, quote),
        nonce: challenge_nonce.to_owned(),
    }
}

#[tokio::test]
async fn cp_agent_publish_register_deploy_cycle() {
    let (addr, client) = spawn_cp(base_config()).await;

    let challenge = get_challenge(&client, addr).await;
    let register = build_register(&challenge.nonce, &challenge.nonce);

    let register_response = client
        .post(format!("http://{addr}/api/v1/agents/register"))
        .json(&register)
        .send()
        .await
        .expect("register request")
        .error_for_status()
        .expect("register status")
        .json::<ee_common::api::RegisterResponse>()
        .await
        .expect("register json");

    let publish = PublishAppRequest {
        name: "hello-tdx".to_owned(),
        description: Some("demo app".to_owned()),
        source_repo: Some("easyenclave/demo".to_owned()),
        version: "v1".to_owned(),
        image: "ghcr.io/easyenclave/demo:v1".to_owned(),
        mrtd: "ab".repeat(48),
        node_size: Some("c3-standard-4".to_owned()),
    };

    client
        .post(format!("http://{addr}/api/v1/apps"))
        .header("authorization", "Bearer test-owner:easyenclave")
        .json(&publish)
        .send()
        .await
        .expect("publish request")
        .error_for_status()
        .expect("publish status");

    let deploy = DeployRequest {
        app_name: "hello-tdx".to_owned(),
        version: "v1".to_owned(),
        agent_id: register_response.agent_id,
    };

    client
        .post(format!("http://{addr}/api/v1/deploy"))
        .header("authorization", "Bearer test-owner:easyenclave")
        .json(&deploy)
        .send()
        .await
        .expect("deploy request")
        .error_for_status()
        .expect("deploy status");
}

#[tokio::test]
async fn registration_rejects_nonce_mismatch() {
    let (addr, client) = spawn_cp(base_config()).await;

    let challenge = get_challenge(&client, addr).await;
    let request = build_register(&challenge.nonce, &"cd".repeat(16));

    let response = client
        .post(format!("http://{addr}/api/v1/agents/register"))
        .json(&request)
        .send()
        .await
        .expect("register request");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn registration_rejects_replayed_nonce() {
    let (addr, client) = spawn_cp(base_config()).await;

    let challenge = get_challenge(&client, addr).await;
    let request = build_register(&challenge.nonce, &challenge.nonce);

    client
        .post(format!("http://{addr}/api/v1/agents/register"))
        .json(&request)
        .send()
        .await
        .expect("first register request")
        .error_for_status()
        .expect("first register status");

    let response = client
        .post(format!("http://{addr}/api/v1/agents/register"))
        .json(&request)
        .send()
        .await
        .expect("second register request");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn registration_rejects_malformed_quote_b64() {
    let (addr, client) = spawn_cp(base_config()).await;

    let challenge = get_challenge(&client, addr).await;
    let mut request = build_register(&challenge.nonce, &challenge.nonce);
    request.quote_b64 = "not-base64***".to_owned();

    let response = client
        .post(format!("http://{addr}/api/v1/agents/register"))
        .json(&request)
        .send()
        .await
        .expect("register request");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn registration_rejects_non_uptodate_tcb_from_ita() {
    let mrtd = "ab".repeat(48);
    let mock_ita_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock ita");
    let mock_ita_addr = mock_ita_listener.local_addr().expect("mock ita addr");

    let expected_mrtd = Arc::new(mrtd.clone());
    let ita_app = Router::new().route(
        "/appraisal/v2/attest",
        post({
            let expected_mrtd = expected_mrtd.clone();
            move || {
                let expected_mrtd = expected_mrtd.clone();
                async move {
                    Json(serde_json::json!({
                        "status": "success",
                        "result": {
                            "mrtd": (*expected_mrtd).clone(),
                            "tcb_status": "OutOfDate"
                        }
                    }))
                }
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(mock_ita_listener, ita_app).await;
    });

    let mut config = base_config();
    config.allow_insecure_test_attestation = false;
    config.ita_api_key = "test-key".to_owned();
    config.ita_appraisal_url = format!("http://{mock_ita_addr}/appraisal/v2/attest");
    let (addr, client) = spawn_cp(config).await;

    let challenge = get_challenge(&client, addr).await;
    let request = build_register(&challenge.nonce, &challenge.nonce);

    let response = client
        .post(format!("http://{addr}/api/v1/agents/register"))
        .json(&request)
        .send()
        .await
        .expect("register request");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}
