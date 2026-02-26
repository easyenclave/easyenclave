use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();

    let agent = ee_agent::start(ee_agent::Config::default()).await?;
    println!("agent listening on {}", agent.local_addr());
    tokio::signal::ctrl_c().await?;
    agent.shutdown().await;
    Ok(())
}
