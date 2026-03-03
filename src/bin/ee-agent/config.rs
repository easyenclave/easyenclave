use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;

use easyenclave::common::error::{AppError, AppResult};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentMode {
    Agent,
    ControlPlane,
    Measure,
}

impl AgentMode {
    fn parse(raw: &str) -> AppResult<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "agent" => Ok(Self::Agent),
            "control-plane" | "control_plane" | "cp" => Ok(Self::ControlPlane),
            "measure" => Ok(Self::Measure),
            other => Err(AppError::Config(format!(
                "invalid mode '{other}' (expected agent|control-plane|measure)"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvidedApp {
    ControlPlane,
    Measure,
}

impl ProvidedApp {
    fn parse(raw: &str) -> AppResult<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "control-plane" | "control_plane" | "cp" => Ok(Self::ControlPlane),
            "measure" => Ok(Self::Measure),
            other => Err(AppError::Config(format!(
                "invalid provided_app '{other}' (expected control-plane|measure)"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AgentRuntimeConfig {
    pub mode: AgentMode,
    pub control_plane_url: Option<String>,
    pub node_size: String,
    pub datacenter: String,
    pub intel_api_key: Option<String>,
    pub control_plane_image: Option<String>,
    pub measure_app_image: Option<String>,
    pub provided_app: Option<ProvidedApp>,
    pub port: u16,
    pub raw_kv: HashMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
struct JsonConfig {
    mode: Option<String>,
    provided_app: Option<String>,
    app: Option<String>,
    control_plane_url: Option<String>,
    node_size: Option<String>,
    datacenter: Option<String>,
    intel_api_key: Option<String>,
    ita_api_key: Option<String>,
    control_plane_image: Option<String>,
    measure_app_image: Option<String>,
    port: Option<u16>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

impl AgentRuntimeConfig {
    pub fn load() -> AppResult<Self> {
        let json = read_json_config().unwrap_or_default();

        let mode_raw = env_first("EE_AGENT_MODE", "AGENT_MODE")
            .or_else(|| json.mode.clone())
            .unwrap_or_else(|| "agent".to_string());
        let mode = AgentMode::parse(&mode_raw)?;

        let control_plane_url = env_first("AGENT_CP_URL", "CP_URL")
            .or_else(|| json.control_plane_url.clone())
            .map(|v| v.trim().trim_end_matches('/').to_string())
            .filter(|v| !v.is_empty());

        let node_size = env_first("AGENT_NODE_SIZE", "EASYENCLAVE_DEFAULT_SIZE")
            .or_else(|| json.node_size.clone())
            .unwrap_or_else(|| "tiny".to_string())
            .trim()
            .to_ascii_lowercase();

        let datacenter = env_first("AGENT_DATACENTER", "EASYENCLAVE_DEFAULT_DATACENTER")
            .or_else(|| json.datacenter.clone())
            .unwrap_or_else(|| "gcp:unknown".to_string())
            .trim()
            .to_ascii_lowercase();

        let intel_api_key = env_first("ITA_API_KEY", "INTEL_API_KEY")
            .or_else(|| json.intel_api_key.clone())
            .or_else(|| json.ita_api_key.clone())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        let control_plane_image = env_first("CONTROL_PLANE_IMAGE", "EE_CONTROL_PLANE_IMAGE")
            .or_else(|| json.control_plane_image.clone())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        let measure_app_image = env_first("MEASURE_APP_IMAGE", "EE_MEASURE_APP_IMAGE")
            .or_else(|| json.measure_app_image.clone())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        let provided_app = env_first("AGENT_PROVIDED_APP", "EE_AGENT_APP")
            .or_else(|| json.provided_app.clone())
            .or_else(|| json.app.clone())
            .map(|v| ProvidedApp::parse(&v))
            .transpose()?;

        let port = env_first("EE_AGENT_PORT", "AGENT_PORT")
            .and_then(|v| v.trim().parse::<u16>().ok())
            .or(json.port)
            .unwrap_or(8080);

        let mut raw_kv: HashMap<String, String> = HashMap::new();
        for (key, value) in &json.extra {
            if let Some(rendered) = value_to_string(value) {
                raw_kv.insert(key.clone(), rendered);
            }
        }

        Ok(Self {
            mode,
            control_plane_url,
            node_size,
            datacenter,
            intel_api_key,
            control_plane_image,
            measure_app_image,
            provided_app,
            port,
            raw_kv,
        })
    }
}

fn env_first(a: &str, b: &str) -> Option<String> {
    for key in [a, b] {
        if let Ok(val) = env::var(key) {
            if !val.trim().is_empty() {
                return Some(val);
            }
        }
    }
    None
}

fn read_json_config() -> Option<JsonConfig> {
    let path = config_path();
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str::<JsonConfig>(&raw).ok()
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(s) => {
            if s.trim().is_empty() {
                None
            } else {
                Some(s.clone())
            }
        }
        Value::Bool(b) => Some(if *b { "true" } else { "false" }.to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn config_path() -> PathBuf {
    if let Ok(path) = env::var("EASYENCLAVE_CONFIG") {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }
    PathBuf::from("/etc/easyenclave/agent.json")
}
