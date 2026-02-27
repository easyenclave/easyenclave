use std::net::SocketAddr;

use ee_common::api::{ChallengeResponse, DeployRequest, PublishAppRequest, RegisterRequest};
use ee_common::config::CpConfig;

async fn spawn_cp() -> (SocketAddr, reqwest::Client) {
    let config = CpConfig {
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
    };

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
    let (addr, client) = spawn_cp().await;

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
    let (addr, client) = spawn_cp().await;

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
    let (addr, client) = spawn_cp().await;

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
    let (addr, client) = spawn_cp().await;

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
