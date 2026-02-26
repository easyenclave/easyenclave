use std::time::Duration;

use ee_common::{
    api::{ChallengeResponse, RegisterRequest, RegisterResponse},
    config::AgentConfig,
    error::{AppError, AppResult},
};
use reqwest::Client;

use crate::attestation;

pub async fn register_with_retry(
    client: &Client,
    config: &AgentConfig,
) -> AppResult<RegisterResponse> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        match register_once(client, config).await {
            Ok(response) => return Ok(response),
            Err(err) if attempt < 6 => {
                let wait = Duration::from_secs(1_u64 << (attempt - 1));
                tracing::warn!(
                    "registration attempt {attempt} failed: {err}; retrying in {wait:?}"
                );
                tokio::time::sleep(wait).await;
            }
            Err(err) => return Err(err),
        }
    }
}

async fn register_once(client: &Client, config: &AgentConfig) -> AppResult<RegisterResponse> {
    let challenge_url = format!("{}/api/v1/agents/challenge", config.cp_url);
    let challenge = client
        .get(challenge_url)
        .send()
        .await
        .map_err(|e| AppError::External(format!("challenge request failed: {e}")))?
        .error_for_status()
        .map_err(|e| AppError::External(format!("challenge response error: {e}")))?
        .json::<ChallengeResponse>()
        .await
        .map_err(|e| AppError::External(format!("challenge json error: {e}")))?;

    let mrtd = "00".repeat(48);
    let attestation_jwt = attestation::mint_attestation_token(config, &mrtd).await?;

    let register_url = format!("{}/api/v1/agents/register", config.cp_url);
    let request = RegisterRequest {
        vm_name: config.vm_name.clone(),
        owner: config.owner.clone(),
        node_size: config.node_size.clone(),
        datacenter: config.datacenter.clone(),
        attestation_jwt,
        mrtd,
        nonce: challenge.nonce,
    };

    client
        .post(register_url)
        .json(&request)
        .send()
        .await
        .map_err(|e| AppError::External(format!("register request failed: {e}")))?
        .error_for_status()
        .map_err(|e| AppError::External(format!("register response error: {e}")))?
        .json::<RegisterResponse>()
        .await
        .map_err(|e| AppError::External(format!("register json error: {e}")))
}
