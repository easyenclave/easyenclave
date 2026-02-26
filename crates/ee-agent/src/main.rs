mod attestation;
mod logs;
mod mode_agent;
mod mode_cp;
mod registration;
mod server;
mod tunnel;
mod workload;

use clap::{Parser, ValueEnum};
use ee_common::config::AgentConfig;

#[derive(Debug, Clone, ValueEnum)]
enum Mode {
    Agent,
    CpBootstrap,
}

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long, value_enum)]
    mode: Option<Mode>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let mut config = AgentConfig::from_env();

    if let Some(mode) = cli.mode {
        config.mode = match mode {
            Mode::Agent => "agent".to_owned(),
            Mode::CpBootstrap => "cp-bootstrap".to_owned(),
        };
    }

    let result = match config.mode.as_str() {
        "cp-bootstrap" => mode_cp::run(config).await,
        _ => mode_agent::run(config).await,
    };

    if let Err(err) = result {
        eprintln!("ee-agent failed: {err}");
        std::process::exit(1);
    }
}
