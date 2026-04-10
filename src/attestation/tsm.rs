//! TDX quote generation via Linux configfs-tsm.

use base64::Engine;

/// Generate a TDX quote by writing user data to the configfs-tsm report
/// interface and reading back the binary quote.
///
/// `report_root` -- path to the tsm report entry, e.g.
/// `/sys/kernel/config/tsm/report/report0`.
/// `user_data` -- up to 64 bytes that will be embedded as report data.
fn generate_tdx_quote(report_root: &str, user_data: &[u8]) -> Result<Vec<u8>, String> {
    use std::fs;
    use std::path::Path;

    let root = Path::new(report_root);

    // Pad or truncate user data to exactly 64 bytes (configfs-tsm requirement).
    let mut padded = [0u8; 64];
    let copy_len = user_data.len().min(64);
    padded[..copy_len].copy_from_slice(&user_data[..copy_len]);

    // Write raw binary user data to the inblob file.
    let inblob_path = root.join("inblob");
    fs::write(&inblob_path, padded).map_err(|e| format!("write inblob: {e}"))?;

    // Read the generated binary quote.
    let outblob_path = root.join("outblob");
    fs::read(&outblob_path).map_err(|e| format!("read outblob: {e}"))
}

/// Generate a TDX quote with the given user data and return it base64-encoded.
fn generate_tdx_quote_base64(user_data: &[u8]) -> Result<String, String> {
    // Create a unique report entry under configfs-tsm.
    let report_name = format!("report_{}", uuid::Uuid::new_v4().as_simple());
    let report_root = format!("/sys/kernel/config/tsm/report/{report_name}");

    std::fs::create_dir_all(&report_root).map_err(|e| format!("create tsm report dir: {e}"))?;

    let quote_bytes = generate_tdx_quote(&report_root, user_data)?;

    // Clean up.
    let _ = std::fs::remove_dir_all(&report_root);

    Ok(base64::engine::general_purpose::STANDARD.encode(&quote_bytes))
}

/// TDX attestation backend using configfs-tsm.
pub struct TdxBackend;

impl super::AttestationBackend for TdxBackend {
    fn attestation_type(&self) -> &str {
        "tdx"
    }

    fn generate_quote_b64(&self) -> Option<String> {
        generate_tdx_quote_base64(&[]).ok()
    }

    fn generate_quote_with_nonce(&self, nonce: &[u8]) -> Option<String> {
        generate_tdx_quote_base64(nonce).ok()
    }
}
