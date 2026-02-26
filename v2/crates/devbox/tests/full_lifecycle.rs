use anyhow::Result;
use ee_common::api::{AgentListResponse, DeployRequest, DeployResponse};
use std::time::Duration;

#[tokio::test]
async fn full_stack_lifecycle_works_in_process() -> Result<()> {
    let cp = ee_cp::start(ee_cp::Config {
        listen_addr: "127.0.0.1:0".parse()?,
        scrape_interval: Duration::from_millis(200),
        ..ee_cp::Config::default()
    })
    .await?;

    let aggregator = ee_aggregator::start(ee_aggregator::Config {
        listen_addr: "127.0.0.1:0".parse()?,
        cp_url: Some(cp.url()),
        health_interval: Duration::from_millis(100),
        attestation_interval: Duration::from_millis(500),
        ..ee_aggregator::Config::default()
    })
    .await?;

    let agent = ee_agent::start(ee_agent::Config {
        listen_addr: "127.0.0.1:0".parse()?,
        registration_target: Some(aggregator.url()),
        heartbeat_interval: Duration::from_millis(100),
        test_mode: true,
        ..ee_agent::Config::default()
    })
    .await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    let cp_agents: AgentListResponse = reqwest::get(format!("{}/api/v1/agents", cp.url()))
        .await?
        .error_for_status()?
        .json()
        .await?;

    assert_eq!(cp_agents.total, 1);
    assert_eq!(cp_agents.agents[0].agent_id, "agent-local");

    let deploy_outcome: DeployResponse = reqwest::Client::new()
        .post(format!("{}/api/deploy", aggregator.url()))
        .json(&DeployRequest {
            app_name: "hello-tdx".to_string(),
            compose_url: Some(
                "https://apps.easyenclave.io/apps/hello-tdx/v1.compose.yml".to_string(),
            ),
            target_agent_id: None,
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    assert_eq!(deploy_outcome.failed, 0);
    assert_eq!(deploy_outcome.dispatched, 1);

    agent.shutdown().await;
    aggregator.shutdown().await;
    cp.shutdown().await;

    Ok(())
}
