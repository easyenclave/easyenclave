pub mod tsm;

/// Pluggable attestation backend. Each platform (TDX, SEV, etc.)
/// implements this trait. The runtime auto-detects at startup.
pub trait AttestationBackend: Send + Sync {
    /// Platform identifier: "tdx", etc.
    fn attestation_type(&self) -> &str;

    /// Generate a base64-encoded attestation quote, if available.
    fn generate_quote_b64(&self) -> Result<String, String>;

    /// Generate a base64-encoded quote with caller-supplied report data.
    ///
    /// For TDX this is the raw TD report_data buffer before zero padding.
    /// Callers that integrate an external verifier such as Intel Trust
    /// Authority should compute that verifier's required report_data binding
    /// outside the enclave runtime and pass it here.
    fn generate_quote_with_report_data(&self, report_data: &[u8]) -> Result<String, String>;
}

/// Detect the attestation backend. Returns an error if no hardware
/// attestation is available — easyenclave refuses to run without it.
pub fn detect() -> Result<Box<dyn AttestationBackend>, String> {
    if std::path::Path::new("/sys/kernel/config/tsm/report").exists() {
        return Ok(Box::new(tsm::TdxBackend));
    }

    Err("no attestation backend found (configfs-tsm not available). easyenclave requires a real TDX VM.".into())
}
