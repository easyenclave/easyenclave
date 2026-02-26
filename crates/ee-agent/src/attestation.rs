use ee_common::{config::AgentConfig, error::AppResult};

pub async fn mint_attestation_token(config: &AgentConfig, mrtd: &str) -> AppResult<String> {
    let _ = config;
    Ok(format!("test-ita:{mrtd}"))
}
