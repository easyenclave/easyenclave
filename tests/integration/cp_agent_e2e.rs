use ee_common::api::{DeployRequest, PublishAppRequest, RegisterRequest};
use ee_common::config::CpConfig;

#[tokio::test]
async fn cp_agent_publish_register_deploy_cycle() {
    let config = CpConfig {
        bind_addr: "127.0.0.1:0".to_owned(),
        database_url: "".to_owned(),
        domain: "easyenclave.local".to_owned(),
        cf_account_id: "".to_owned(),
        cf_api_token: "".to_owned(),
        cf_zone_id: "".to_owned(),
        ita_jwks_url: "https://ita.invalid/jwks".to_owned(),
        github_oidc_jwks_url: "https://github.invalid/jwks".to_owned(),
    };

    let app = ee_cp::app_from_config(config).await.expect("app setup");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let client = reqwest::Client::new();

    let challenge = client
        .get(format!("http://{addr}/api/v1/agents/challenge"))
        .send()
        .await
        .expect("challenge request")
        .error_for_status()
        .expect("challenge status")
        .json::<ee_common::api::ChallengeResponse>()
        .await
        .expect("challenge json");

    let register = RegisterRequest {
        vm_name: "ee-agent-test".to_owned(),
        owner: "github:org/easyenclave".to_owned(),
        node_size: "c3-standard-4".to_owned(),
        datacenter: "gcp:us-central1-a".to_owned(),
        attestation_jwt: format!("test-ita:{}", "ab".repeat(48)),
        mrtd: "ab".repeat(48),
        nonce: challenge.nonce,
    };

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
