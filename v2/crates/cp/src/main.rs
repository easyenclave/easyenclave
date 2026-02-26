use anyhow::Result;
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();

    let mut config = ee_cp::Config::default();
    if let Ok(listen) = std::env::var("EE_CP_LISTEN") {
        config.listen_addr = std::net::SocketAddr::from_str(&listen)?;
    }

    let cp = ee_cp::start(config).await?;
    println!("cp listening on {}", cp.local_addr());
    tokio::signal::ctrl_c().await?;
    cp.shutdown().await;
    Ok(())
}
