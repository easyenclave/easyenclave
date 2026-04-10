pub mod tsm;

/// Pluggable attestation backend. Each platform (TDX, SEV, etc.)
/// implements this trait. The runtime auto-detects at startup.
pub trait AttestationBackend: Send + Sync {
    /// Platform identifier: "tdx", etc.
    fn attestation_type(&self) -> &str;

    /// Generate a base64-encoded attestation quote, if available.
    fn generate_quote_b64(&self) -> Option<String>;

    /// Generate a quote with caller-supplied nonce embedded in report data.
    fn generate_quote_with_nonce(&self, nonce: &[u8]) -> Option<String>;
}

/// Detect the attestation backend. Returns an error if no hardware
/// attestation is available — easyenclave refuses to run without it.
pub fn detect() -> Result<Box<dyn AttestationBackend>, String> {
    if std::path::Path::new("/sys/kernel/config/tsm/report").exists() {
        return Ok(Box::new(tsm::TdxBackend));
    }

    Err("no attestation backend found (configfs-tsm not available). easyenclave requires a real TDX VM.".into())
}
