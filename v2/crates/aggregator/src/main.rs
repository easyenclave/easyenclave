use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();

    let config = ee_aggregator::Config::default();
    let aggregator = ee_aggregator::start(config).await?;
    println!("aggregator listening on {}", aggregator.local_addr());
    tokio::signal::ctrl_c().await?;
    aggregator.shutdown().await;
    Ok(())
}
