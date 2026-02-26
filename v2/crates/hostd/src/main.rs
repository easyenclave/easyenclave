use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();

    let hostd = ee_hostd::start(ee_hostd::Config::default()).await?;
    println!("hostd listening on {}", hostd.local_addr());
    tokio::signal::ctrl_c().await?;
    hostd.shutdown().await;
    Ok(())
}
