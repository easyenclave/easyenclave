use std::env;

#[derive(Debug, Clone)]
pub struct CpConfig {
    pub bind_addr: String,
    pub database_url: String,
    pub domain: String,
    pub cf_account_id: String,
    pub cf_api_token: String,
    pub cf_zone_id: String,
    pub ita_jwks_url: String,
    pub github_oidc_jwks_url: String,
    pub github_oidc_issuer: String,
    pub github_oidc_audience: Option<String>,
    pub allow_insecure_test_oidc: bool,
}

impl CpConfig {
    pub fn from_env() -> Self {
        Self {
            bind_addr: env::var("CP_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_owned()),
            database_url: env::var("CP_DATABASE_URL")
                .unwrap_or_else(|_| "sqlite://easyenclave.db".to_owned()),
            domain: env::var("CP_DOMAIN").unwrap_or_else(|_| "easyenclave.com".to_owned()),
            cf_account_id: env::var("CF_ACCOUNT_ID").unwrap_or_default(),
            cf_api_token: env::var("CF_API_TOKEN").unwrap_or_default(),
            cf_zone_id: env::var("CF_ZONE_ID").unwrap_or_default(),
            ita_jwks_url: env::var("ITA_JWKS_URL").unwrap_or_else(|_| {
                "https://api.trustauthority.intel.com/.well-known/jwks.json".to_owned()
            }),
            github_oidc_jwks_url: env::var("GITHUB_OIDC_JWKS_URL").unwrap_or_else(|_| {
                "https://token.actions.githubusercontent.com/.well-known/jwks".to_owned()
            }),
            github_oidc_issuer: env::var("GITHUB_OIDC_ISSUER")
                .unwrap_or_else(|_| "https://token.actions.githubusercontent.com".to_owned()),
            github_oidc_audience: env::var("GITHUB_OIDC_AUDIENCE").ok().and_then(|s| {
                if s.trim().is_empty() {
                    None
                } else {
                    Some(s)
                }
            }),
            allow_insecure_test_oidc: env::var("CP_ALLOW_INSECURE_TEST_OIDC")
                .ok()
                .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "True"))
                .unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub mode: String,
    pub vm_name: String,
    pub owner: String,
    pub node_size: String,
    pub datacenter: String,
    pub cp_url: String,
    pub bind_addr: String,
    pub heartbeat_seconds: u64,
}

impl AgentConfig {
    pub fn from_env() -> Self {
        Self {
            mode: env::var("AGENT_MODE").unwrap_or_else(|_| "agent".to_owned()),
            vm_name: env::var("AGENT_VM_NAME").unwrap_or_else(|_| "ee-agent-1".to_owned()),
            owner: env::var("AGENT_OWNER").unwrap_or_else(|_| "github:org/example".to_owned()),
            node_size: env::var("AGENT_NODE_SIZE").unwrap_or_else(|_| "c3-standard-4".to_owned()),
            datacenter: env::var("AGENT_DATACENTER")
                .unwrap_or_else(|_| "gcp:us-central1-a".to_owned()),
            cp_url: env::var("AGENT_CP_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_owned()),
            bind_addr: env::var("AGENT_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:9000".to_owned()),
            heartbeat_seconds: env::var("AGENT_HEARTBEAT_SECONDS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(60),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LauncherConfig {
    pub qemu_bin: String,
    pub default_memory_mb: u64,
    pub default_vcpus: u8,
}

impl LauncherConfig {
    pub fn from_env() -> Self {
        Self {
            qemu_bin: env::var("LAUNCHER_QEMU_BIN")
                .unwrap_or_else(|_| "qemu-system-x86_64".to_owned()),
            default_memory_mb: env::var("LAUNCHER_DEFAULT_MEMORY_MB")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(8192),
            default_vcpus: env::var("LAUNCHER_DEFAULT_VCPUS")
                .ok()
                .and_then(|v| v.parse::<u8>().ok())
                .unwrap_or(4),
        }
    }
}
