//! TDX quote generation via Linux configfs-tsm.

use base64::Engine;
use std::path::{Path, PathBuf};

const TDX_REPORT_DATA_SIZE: usize = 64;

/// Generate a TDX quote by writing user data to the configfs-tsm report
/// interface and reading back the binary quote.
///
/// `report_root` -- path to the tsm report entry, e.g.
/// `/sys/kernel/config/tsm/report/report0`.
/// `user_data` -- up to 64 bytes that will be embedded as report data.
fn generate_tdx_quote(report_root: &Path, user_data: &[u8]) -> Result<Vec<u8>, String> {
    use std::fs;

    if user_data.len() > TDX_REPORT_DATA_SIZE {
        return Err(format!(
            "TDX report data is {} bytes; maximum is {TDX_REPORT_DATA_SIZE}",
            user_data.len()
        ));
    }

    // Pad user data to exactly 64 bytes (configfs-tsm requirement).
    let mut padded = [0u8; TDX_REPORT_DATA_SIZE];
    padded[..user_data.len()].copy_from_slice(user_data);

    // Write raw binary user data to the inblob file.
    let inblob_path = report_root.join("inblob");
    fs::write(&inblob_path, padded).map_err(|e| format!("write inblob: {e}"))?;

    // Read the generated binary quote.
    let outblob_path = report_root.join("outblob");
    fs::read(&outblob_path).map_err(|e| format!("read outblob: {e}"))
}

struct ReportDir {
    path: PathBuf,
}

impl ReportDir {
    fn create(path: PathBuf) -> Result<Self, String> {
        std::fs::create_dir_all(&path).map_err(|e| format!("create tsm report dir: {e}"))?;
        Ok(Self { path })
    }
}

impl Drop for ReportDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Generate a TDX quote with the given user data and return it base64-encoded.
fn generate_tdx_quote_base64(user_data: &[u8]) -> Result<String, String> {
    // Create a unique report entry under configfs-tsm.
    let report_name = format!("report_{}", uuid::Uuid::new_v4().as_simple());
    let report_root = PathBuf::from(format!("/sys/kernel/config/tsm/report/{report_name}"));

    let report_dir = ReportDir::create(report_root)?;
    let quote_bytes = generate_tdx_quote(&report_dir.path, user_data)?;

    Ok(base64::engine::general_purpose::STANDARD.encode(&quote_bytes))
}

/// TDX attestation backend using configfs-tsm.
pub struct TdxBackend;

impl super::AttestationBackend for TdxBackend {
    fn attestation_type(&self) -> &str {
        "tdx"
    }

    fn generate_quote_b64(&self) -> Result<String, String> {
        generate_tdx_quote_base64(&[])
    }

    fn generate_quote_with_report_data(&self, report_data: &[u8]) -> Result<String, String> {
        generate_tdx_quote_base64(report_data)
    }
}
