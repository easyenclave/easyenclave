use std::{env, fs};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ee_attestation::tsm::build_mock_quote_blob;
use ee_common::{
    config::AgentConfig,
    error::{AppError, AppResult},
};

pub async fn collect_quote_b64(_config: &AgentConfig, nonce_hex: &str) -> AppResult<String> {
    if let Ok(path) = env::var("AGENT_QUOTE_PATH") {
        let bytes = fs::read(path)
            .map_err(|e| AppError::Internal(format!("failed reading AGENT_QUOTE_PATH: {e}")))?;
        return Ok(B64.encode(bytes));
    }

    let mrtd = env::var("AGENT_TEST_MRTD").unwrap_or_else(|_| "00".repeat(48));
    let quote = build_mock_quote_blob(&mrtd, nonce_hex)?;
    Ok(B64.encode(quote))
}
