use ee_hostd::config::HostdConfig;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let config = HostdConfig::from_env();
    let handle = ee_hostd::start(config).await?;

    tracing::info!(url = %handle.url, "hostd running");

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    handle.shutdown().await;

    Ok(())
}
