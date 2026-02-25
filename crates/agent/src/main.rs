use ee_agent::config::AgentConfig;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let config = AgentConfig::from_env();
    let handle = ee_agent::start(config).await?;

    tracing::info!(url = %handle.url, "agent running");

    // Wait for SIGTERM
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    handle.shutdown().await;

    Ok(())
}
