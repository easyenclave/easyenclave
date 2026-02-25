//! Agent registration with the aggregator / CP.

use crate::config::AgentConfig;
use crate::error::AgentError;
use ee_attestation::{ita, tdx};
use ee_common::types::{AgentId, AgentRegistration};
use std::time::Duration;
use tracing::{error, info, warn};

/// Register this agent with the aggregator / CP.
/// Retries indefinitely with backoff until successful.
pub async fn register(
    client: &reqwest::Client,
    config: &AgentConfig,
    agent_id: &AgentId,
) -> Result<(), AgentError> {
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        info!(attempt, "attempting registration");

        match try_register(client, config, agent_id).await {
            Ok(()) => {
                info!("registration successful");
                return Ok(());
            }
            Err(e) => {
                let backoff = Duration::from_secs(std::cmp::min(2u64.pow(attempt.min(6)), 60));
                warn!(?e, ?backoff, "registration attempt failed, retrying");
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

async fn try_register(
    client: &reqwest::Client,
    config: &AgentConfig,
    agent_id: &AgentId,
) -> Result<(), AgentError> {
    // Generate attestation token
    let attestation_token = if config.test_mode {
        None
    } else {
        let nonce = agent_id.0.to_string();
        let mut report_data = [0u8; 64];
        let nonce_bytes = nonce.as_bytes();
        let copy_len = nonce_bytes.len().min(64);
        report_data[..copy_len].copy_from_slice(&nonce_bytes[..copy_len]);

        let quote = tdx::generate_quote(&report_data)?;
        let token = ita::request_token(
            client,
            &config.ita_api_url,
            &config.ita_api_key,
            &quote,
            Some(&nonce),
        )
        .await
        .map_err(AgentError::Attestation)?;
        Some(token)
    };

    let registration = AgentRegistration {
        size: config.size,
        cloud: config.cloud,
        region: config.region.clone(),
        tags: config.tags.clone(),
        attestation_token,
        secret: config.agent_secret.clone(),
    };

    let url = format!(
        "{}/api/v1/agents/{}/register",
        config.cp_url.trim_end_matches('/'),
        agent_id
    );

    let resp = client.post(&url).json(&registration).send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(AgentError::Registration(format!("{status}: {body}")));
    }

    Ok(())
}
