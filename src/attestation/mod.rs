pub mod nvgpu;
pub mod tsm;

use crate::config::GpuAttestationConfig;

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

/// Auxiliary GPU evidence backend. Optional: present only on confidential
/// GPU hosts (NVIDIA H100 in CC mode). Failure to collect GPU evidence
/// must NOT break the TDX path — the runtime is "evidence producer, not
/// verifier" and should never make policy decisions about partial evidence.
pub trait GpuEvidenceBackend: Send + Sync {
    /// Identifier for the helper, e.g. "nvidia-cc". Surfaced in `health`
    /// so clients can detect capability without an `attest` round-trip.
    fn evidence_type(&self) -> &str;

    /// Collect the current GPU attestation report (and optional NVSwitch
    /// report on multi-GPU/NVL configurations).
    fn collect(&self) -> Result<GpuEvidence, String>;
}

/// Raw GPU evidence as emitted by the helper. The runtime does NOT
/// interpret the bytes — they're forwarded base64-encoded to the
/// relying party, which submits them to ITA v2 (or another verifier).
#[derive(Debug, Clone)]
pub struct GpuEvidence {
    pub gpu_report: Vec<u8>,
    pub switch_report: Option<Vec<u8>>,
    pub collected_at: u64,
}

/// Soft detection: returns `None` if disabled or the helper is missing.
/// This is by design — booting on a non-GPU host with the llm-cuda
/// config baked in must not fail the runtime, just yield TDX-only quotes.
pub fn detect_gpu_evidence(
    cfg: Option<&GpuAttestationConfig>,
) -> Option<Box<dyn GpuEvidenceBackend>> {
    let cfg = cfg?;
    if !cfg.enabled {
        return None;
    }
    if !std::path::Path::new(&cfg.helper_path).exists() {
        eprintln!(
            "easyenclave: gpu attestation enabled but helper missing at {} — staying TDX-only",
            cfg.helper_path
        );
        return None;
    }
    Some(Box::new(nvgpu::HelperBackend::new(cfg.clone())))
}

#[cfg(test)]
pub mod testing {
    use super::{AttestationBackend, GpuEvidence, GpuEvidenceBackend};
    use std::sync::Mutex;

    /// Deterministic TDX backend for unit tests. Returns a fixed quote
    /// payload and remembers the last `report_data` it was handed so
    /// tests can assert on the binding.
    pub struct MockTdxBackend {
        pub quote_payload: Vec<u8>,
        pub last_report_data: Mutex<Option<Vec<u8>>>,
    }

    impl MockTdxBackend {
        pub fn new() -> Self {
            Self {
                quote_payload: b"mock-tdx-quote".to_vec(),
                last_report_data: Mutex::new(None),
            }
        }
    }

    impl AttestationBackend for MockTdxBackend {
        fn attestation_type(&self) -> &str {
            "tdx"
        }

        fn generate_quote_b64(&self) -> Result<String, String> {
            use base64::Engine;
            *self.last_report_data.lock().unwrap() = Some(Vec::new());
            Ok(base64::engine::general_purpose::STANDARD.encode(&self.quote_payload))
        }

        fn generate_quote_with_report_data(&self, report_data: &[u8]) -> Result<String, String> {
            use base64::Engine;
            *self.last_report_data.lock().unwrap() = Some(report_data.to_vec());
            Ok(base64::engine::general_purpose::STANDARD.encode(&self.quote_payload))
        }
    }

    /// Deterministic GPU evidence backend for unit tests. Configurable
    /// to either return a fixed payload or fail with a chosen error.
    pub struct MockGpuBackend {
        pub result: Result<GpuEvidence, String>,
    }

    impl MockGpuBackend {
        pub fn ok() -> Self {
            Self {
                result: Ok(GpuEvidence {
                    gpu_report: b"mock-gpu-report".to_vec(),
                    switch_report: Some(b"mock-switch-report".to_vec()),
                    collected_at: 1_700_000_000,
                }),
            }
        }

        pub fn err(msg: &str) -> Self {
            Self {
                result: Err(msg.to_string()),
            }
        }
    }

    impl GpuEvidenceBackend for MockGpuBackend {
        fn evidence_type(&self) -> &str {
            "nvidia-cc"
        }

        fn collect(&self) -> Result<GpuEvidence, String> {
            self.result.clone()
        }
    }
}
