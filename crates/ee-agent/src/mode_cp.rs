use ee_common::{config::AgentConfig, error::AppResult};

pub async fn run(config: AgentConfig) -> AppResult<()> {
    tracing::info!(
        "cp-bootstrap mode selected for vm={} owner={}",
        config.vm_name,
        config.owner
    );
    tracing::info!("expected runtime: ee-cp + cloudflared managed by supervisord in guest VM");
    Ok(())
}
