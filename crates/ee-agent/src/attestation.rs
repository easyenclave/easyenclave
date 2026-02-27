use std::{env, fs, process::Command};

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

    if let Ok(cmdline) = env::var("AGENT_TDX_QUOTE_CMD") {
        let bytes = run_quote_command(&cmdline, nonce_hex)?;
        return Ok(B64.encode(bytes));
    }

    if let Some(bytes) = try_collect_quote_from_tsm(nonce_hex)? {
        return Ok(B64.encode(bytes));
    }

    let allow_mock = env::var("AGENT_ALLOW_MOCK_QUOTE")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "True"))
        .unwrap_or(true);

    if !allow_mock {
        return Err(AppError::Internal(
            "failed to collect TDX quote and AGENT_ALLOW_MOCK_QUOTE=false".to_owned(),
        ));
    }

    let mrtd = env::var("AGENT_TEST_MRTD").unwrap_or_else(|_| "00".repeat(48));
    let quote = build_mock_quote_blob(&mrtd, nonce_hex)?;
    Ok(B64.encode(quote))
}

fn run_quote_command(cmdline: &str, nonce_hex: &str) -> AppResult<Vec<u8>> {
    let output = Command::new("bash")
        .arg("-lc")
        .arg(cmdline)
        .env("EE_NONCE_HEX", nonce_hex)
        .output()
        .map_err(|e| AppError::Internal(format!("failed running AGENT_TDX_QUOTE_CMD: {e}")))?;

    if !output.status.success() {
        return Err(AppError::Internal(format!(
            "AGENT_TDX_QUOTE_CMD failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    if output.stdout.is_empty() {
        return Err(AppError::Internal(
            "AGENT_TDX_QUOTE_CMD produced empty stdout".to_owned(),
        ));
    }

    Ok(output.stdout)
}

fn try_collect_quote_from_tsm(nonce_hex: &str) -> AppResult<Option<Vec<u8>>> {
    let report_data_path = env::var("AGENT_TSM_REPORT_DATA_PATH")
        .unwrap_or_else(|_| "/sys/kernel/config/tsm/report/reportdata".to_owned());
    let quote_path = env::var("AGENT_TSM_QUOTE_PATH")
        .unwrap_or_else(|_| "/sys/kernel/config/tsm/report/quote".to_owned());

    if !std::path::Path::new(&report_data_path).exists()
        || !std::path::Path::new(&quote_path).exists()
    {
        return Ok(None);
    }

    fs::write(&report_data_path, nonce_hex).map_err(|e| {
        AppError::Internal(format!(
            "failed writing nonce to AGENT_TSM_REPORT_DATA_PATH ({report_data_path}): {e}"
        ))
    })?;

    let quote = fs::read(&quote_path).map_err(|e| {
        AppError::Internal(format!(
            "failed reading quote from AGENT_TSM_QUOTE_PATH ({quote_path}): {e}"
        ))
    })?;

    if quote.is_empty() {
        return Err(AppError::Internal(
            "TSM quote path returned empty quote".to_owned(),
        ));
    }

    Ok(Some(quote))
}
