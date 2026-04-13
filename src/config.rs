//! Configuration for easyenclave runtime.

use serde::Deserialize;

const DEFAULT_SOCKET_PATH: &str = "/var/lib/easyenclave/agent.sock";
const DEFAULT_DATA_DIR: &str = "/var/lib/easyenclave";
const CONFIG_FILE_PATH: &str = "/etc/easyenclave/config.json";

/// Runtime configuration loaded from disk and environment.
///
/// ```
/// let cfg = easyenclave::config::Config::default();
/// assert_eq!(cfg.socket_path, "/var/lib/easyenclave/agent.sock");
/// assert_eq!(cfg.data_dir, "/var/lib/easyenclave");
/// assert!(cfg.boot_workloads.is_empty());
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_socket_path")]
    pub socket_path: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default)]
    pub boot_workloads: Vec<BootWorkload>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            data_dir: default_data_dir(),
            boot_workloads: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BootWorkload {
    #[serde(default)]
    pub cmd: Option<Vec<String>>,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default = "default_app_name")]
    pub app_name: String,
    #[serde(default)]
    pub env: Option<Vec<String>>,
    #[serde(default)]
    pub volumes: Option<Vec<String>>,
    /// Run the OCI image natively by extracting a single static ELF
    /// executable and exec'ing it on the host instead of through
    /// libcontainer. The binary gets full host access including the
    /// easyenclave agent socket.
    #[serde(default)]
    pub native: bool,
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

fn parse_boot_workloads_json(raw: &str, source: &str) -> Result<Vec<BootWorkload>, String> {
    serde_json::from_str::<Vec<BootWorkload>>(raw).map_err(|e| format!("{source} parse error: {e}"))
}

impl Config {
    /// Load config from file, then overlay with environment variables.
    pub fn load() -> Result<Self, String> {
        // Start with config file if it exists
        let mut config = if std::path::Path::new(CONFIG_FILE_PATH).exists() {
            let data = std::fs::read_to_string(CONFIG_FILE_PATH)
                .map_err(|e| format!("read config: {e}"))?;
            serde_json::from_str::<Config>(&data).map_err(|e| format!("parse config: {e}"))?
        } else {
            Config::default()
        };

        // Overlay env vars
        if let Ok(val) = std::env::var("EE_SOCKET_PATH") {
            config.socket_path = val;
        }
        if let Ok(val) = std::env::var("EE_DATA_DIR") {
            config.data_dir = val;
        }

        // Boot workloads from env (JSON array)
        if let Ok(val) = std::env::var("EE_BOOT_WORKLOADS") {
            config.boot_workloads = parse_boot_workloads_json(&val, "EE_BOOT_WORKLOADS")?;
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::parse_boot_workloads_json;

    #[test]
    fn parse_boot_workloads_accepts_valid_json() {
        let workloads =
            parse_boot_workloads_json(r#"[{"app_name":"demo","cmd":["/bin/demo"]}]"#, "test")
                .unwrap();

        assert_eq!(workloads.len(), 1);
        assert_eq!(workloads[0].app_name, "demo");
        assert_eq!(workloads[0].cmd.as_ref().unwrap(), &vec!["/bin/demo"]);
    }

    #[test]
    fn parse_boot_workloads_rejects_invalid_json() {
        let err = parse_boot_workloads_json(r#"{"app_name":"demo"}"#, "test").unwrap_err();
        assert!(err.contains("test parse error"));
    }
}
