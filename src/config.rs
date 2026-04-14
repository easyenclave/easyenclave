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

        Ok(config)
    }
}
