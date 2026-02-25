//! TDX quote generation.
//!
//! On a real TDX VM this reads from the configfs-tsm interface.
//! In test mode it returns a placeholder.

use crate::error::AttestationError;
use std::path::Path;

const CONFIGFS_TSM_REPORT: &str = "/sys/kernel/config/tsm/report";

/// Generate a TDX quote for the given report data (nonce).
///
/// On a TDX VM this writes to configfs-tsm and reads back the binary quote.
/// In test mode (no TDX hardware) returns a placeholder.
pub fn generate_quote(report_data: &[u8; 64]) -> Result<Vec<u8>, AttestationError> {
    if !Path::new(CONFIGFS_TSM_REPORT).exists() {
        tracing::warn!("TDX configfs not available, returning test quote");
        return Ok(test_quote(report_data));
    }

    generate_quote_configfs(report_data)
}

fn generate_quote_configfs(report_data: &[u8; 64]) -> Result<Vec<u8>, AttestationError> {
    use std::fs;

    // Create a new report entry
    let entry_name = format!("ee-{}", uuid::Uuid::new_v4());
    let entry_path = format!("{CONFIGFS_TSM_REPORT}/{entry_name}");

    fs::create_dir_all(&entry_path)
        .map_err(|e| AttestationError::QuoteGeneration(format!("mkdir: {e}")))?;

    // Write report data
    fs::write(format!("{entry_path}/inblob"), report_data)
        .map_err(|e| AttestationError::QuoteGeneration(format!("write inblob: {e}")))?;

    // Read the generated quote
    let quote = fs::read(format!("{entry_path}/outblob"))
        .map_err(|e| AttestationError::QuoteGeneration(format!("read outblob: {e}")))?;

    // Clean up
    let _ = fs::remove_dir_all(&entry_path);

    Ok(quote)
}

fn test_quote(report_data: &[u8; 64]) -> Vec<u8> {
    // Return a minimal fake quote for testing.
    // Real verification will reject this — that's intentional.
    let mut quote = Vec::with_capacity(128);
    quote.extend_from_slice(b"TEST_QUOTE_V1");
    quote.extend_from_slice(report_data);
    quote
}

/// Check whether TDX hardware is available.
pub fn is_tdx_available() -> bool {
    Path::new(CONFIGFS_TSM_REPORT).exists()
}
