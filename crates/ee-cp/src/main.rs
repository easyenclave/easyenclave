use ee_common::config::CpConfig;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = CpConfig::from_env();
    if let Err(err) = ee_cp::serve(config).await {
        eprintln!("ee-cp failed: {err}");
        std::process::exit(1);
    }
}
