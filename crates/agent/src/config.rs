use ee_common::config::{env_bool, env_or, listen_addr, optional_env, require_env};
use ee_common::types::{Cloud, VmSize};
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub listen_addr: SocketAddr,
    pub cp_url: String,
    pub agent_secret: String,
    pub size: VmSize,
    pub cloud: Cloud,
    pub region: String,
    pub tags: Vec<String>,
    pub test_mode: bool,
    pub ita_api_url: String,
    pub ita_api_key: String,
    pub cloudflare_api_token: Option<String>,
    pub cloudflare_account_id: Option<String>,
    pub easyenclave_domain: String,
}

impl AgentConfig {
    pub fn from_env() -> Self {
        Self {
            listen_addr: listen_addr("LISTEN_ADDR", "0.0.0.0:8081"),
            cp_url: require_env("CP_URL"),
            agent_secret: require_env("AGENT_SECRET"),
            size: serde_json::from_str(&format!("\"{}\"", env_or("VM_SIZE", "medium")))
                .unwrap_or(VmSize::Medium),
            cloud: serde_json::from_str(&format!("\"{}\"", env_or("CLOUD", "gcp")))
                .unwrap_or(Cloud::Gcp),
            region: env_or("REGION", "us-central1"),
            tags: ee_common::config::env_csv("TAGS"),
            test_mode: env_bool("TEST_MODE", false),
            ita_api_url: env_or(
                "ITA_API_URL",
                "https://api.trustauthority.intel.com/appraisal/v2",
            ),
            ita_api_key: env_or("ITA_API_KEY", ""),
            cloudflare_api_token: optional_env("CLOUDFLARE_API_TOKEN"),
            cloudflare_account_id: optional_env("CLOUDFLARE_ACCOUNT_ID"),
            easyenclave_domain: env_or("EASYENCLAVE_DOMAIN", "easyenclave.io"),
        }
    }
}
