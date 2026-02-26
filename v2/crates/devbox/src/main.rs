use anyhow::Result;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();

    let cp = ee_cp::start(ee_cp::Config::default()).await?;

    let aggregator = ee_aggregator::start(ee_aggregator::Config {
        cp_url: Some(cp.url()),
        ..ee_aggregator::Config::default()
    })
    .await?;

    let agent = ee_agent::start(ee_agent::Config {
        registration_target: Some(aggregator.url()),
        heartbeat_interval: Duration::from_secs(3),
        ..ee_agent::Config::default()
    })
    .await?;

    println!("devbox started");
    println!("  cp: {}", cp.url());
    println!("  aggregator: {}", aggregator.url());
    println!("  agent: {}", agent.url());

    tokio::signal::ctrl_c().await?;

    agent.shutdown().await;
    aggregator.shutdown().await;
    cp.shutdown().await;

    Ok(())
}
