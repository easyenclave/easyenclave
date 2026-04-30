//! Configuration for easyenclave runtime.

use serde::Deserialize;

use crate::release::GithubRelease;

const DEFAULT_SOCKET_PATH: &str = "/var/lib/easyenclave/agent.sock";
const DEFAULT_DATA_DIR: &str = "/var/lib/easyenclave";
const CONFIG_FILE_PATH: &str = "/etc/easyenclave/config.json";

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_socket_path")]
    pub socket_path: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default)]
    pub boot_workloads: Vec<BootWorkload>,
    #[serde(default)]
    pub gpu_attestation: Option<GpuAttestationConfig>,
}

/// Optional auxiliary evidence backend for confidential GPUs (NVIDIA H100 CC).
/// PID 1 shells out to `helper_path` on each `attest` call; the helper
/// prints raw GPU evidence bytes on stdout in a length-prefixed wire
/// format (see `docs/gpu-attestation.md`). Absent or `enabled: false` →
/// the runtime keeps producing TDX-only quotes (existing behaviour).
#[derive(Debug, Clone, Deserialize)]
pub struct GpuAttestationConfig {
    #[serde(default = "default_gpu_enabled")]
    pub enabled: bool,
    #[serde(default = "default_gpu_helper_path")]
    pub helper_path: String,
    #[serde(default = "default_gpu_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_gpu_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
}

impl Default for GpuAttestationConfig {
    fn default() -> Self {
        Self {
            enabled: default_gpu_enabled(),
            helper_path: default_gpu_helper_path(),
            timeout_secs: default_gpu_timeout_secs(),
            cache_ttl_secs: default_gpu_cache_ttl_secs(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BootWorkload {
    #[serde(default)]
    pub cmd: Option<Vec<String>>,
    #[serde(default = "default_app_name")]
    pub app_name: String,
    #[serde(default)]
    pub env: Option<Vec<String>>,
    #[serde(default)]
    pub tty: bool,
    /// Download a static binary from a GitHub release before starting.
    /// If `cmd` is empty, this is a fetch-only workload — the binary is
    /// downloaded into the bin dir (and added to PATH) but nothing is
    /// spawned. That's how third-party tools like cloudflared get
    /// installed without running them directly.
    #[serde(default)]
    pub github_release: Option<GithubRelease>,
    /// When true, EE injects `EE_TOKEN=<hex>` into this workload's env
    /// at spawn. The workload must include `"token": "<hex>"` on every
    /// EE socket request; unauth'd requests are rejected with
    /// `{"ok":false,"error":"unauthenticated"}`. Today only `dd-agent`
    /// needs this — every other workload runs without socket access,
    /// which is the whole point of the seal.
    #[serde(default)]
    pub inherit_token: bool,
}

fn default_socket_path() -> String {
    DEFAULT_SOCKET_PATH.to_string()
}

fn default_data_dir() -> String {
    DEFAULT_DATA_DIR.to_string()
}

fn default_app_name() -> String {
    "unnamed".to_string()
}

fn default_gpu_enabled() -> bool {
    false
}

fn default_gpu_helper_path() -> String {
    "/usr/local/bin/ee-gpu-evidence".to_string()
}

fn default_gpu_timeout_secs() -> u64 {
    15
}

fn default_gpu_cache_ttl_secs() -> u64 {
    60
}

impl Config {
    /// Load config from file, then overlay with environment variables.
    pub fn load() -> Result<Self, String> {
        let mut config = if std::path::Path::new(CONFIG_FILE_PATH).exists() {
            let data = std::fs::read_to_string(CONFIG_FILE_PATH)
                .map_err(|e| format!("read config: {e}"))?;
            serde_json::from_str::<Config>(&data).map_err(|e| format!("parse config: {e}"))?
        } else {
            Config {
                socket_path: default_socket_path(),
                data_dir: default_data_dir(),
                boot_workloads: Vec::new(),
                gpu_attestation: None,
            }
        };

        if let Ok(val) = std::env::var("EE_SOCKET_PATH") {
            config.socket_path = val;
        }
        if let Ok(val) = std::env::var("EE_DATA_DIR") {
            config.data_dir = val;
        }

        if let Ok(val) = std::env::var("EE_BOOT_WORKLOADS") {
            match serde_json::from_str::<Vec<BootWorkload>>(&val) {
                Ok(workloads) => config.boot_workloads = workloads,
                Err(e) => eprintln!("easyenclave: warning: EE_BOOT_WORKLOADS parse error: {e}"),
            }
        }

        // GPU attestation env overrides. Any of these creates the block
        // if absent in the file, so a deployment can opt in purely via
        // kernel cmdline / agent.env without baking config.json.
        if let Ok(val) = std::env::var("EE_GPU_ATTESTATION_ENABLED") {
            let enabled = matches!(val.as_str(), "1" | "true" | "yes");
            config
                .gpu_attestation
                .get_or_insert_with(GpuAttestationConfig::default)
                .enabled = enabled;
        }
        if let Ok(val) = std::env::var("EE_GPU_ATTESTATION_HELPER") {
            config
                .gpu_attestation
                .get_or_insert_with(GpuAttestationConfig::default)
                .helper_path = val;
        }
        if let Ok(val) = std::env::var("EE_GPU_ATTESTATION_TIMEOUT") {
            if let Ok(secs) = val.parse() {
                config
                    .gpu_attestation
                    .get_or_insert_with(GpuAttestationConfig::default)
                    .timeout_secs = secs;
            } else {
                eprintln!("easyenclave: warning: EE_GPU_ATTESTATION_TIMEOUT not an integer: {val}");
            }
        }
        if let Ok(val) = std::env::var("EE_GPU_ATTESTATION_CACHE_TTL") {
            if let Ok(secs) = val.parse() {
                config
                    .gpu_attestation
                    .get_or_insert_with(GpuAttestationConfig::default)
                    .cache_ttl_secs = secs;
            } else {
                eprintln!(
                    "easyenclave: warning: EE_GPU_ATTESTATION_CACHE_TTL not an integer: {val}"
                );
            }
        }

        Ok(config)
    }
}
