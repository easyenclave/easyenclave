use ee_cp::config::CpConfig;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let config = CpConfig::from_env();
    let handle = ee_cp::start(config).await?;

    tracing::info!(url = %handle.url, "CP running");

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    handle.shutdown().await;

    Ok(())
}
