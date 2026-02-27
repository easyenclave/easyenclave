use std::collections::HashMap;
use std::env;

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpConfig {
    pub bind_addr: String,
    pub database_url: String,
    pub admin_password: Option<String>,
    pub tcb_enforcement_mode: String,
    pub rtmr_enforcement_mode: String,
    pub nonce_enforcement_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    pub cp_url: String,
    pub bootstrap_token: Option<String>,
    pub node_size: String,
    pub datacenter: String,
    pub owner: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LauncherConfig {
    pub cp_url: String,
    pub default_node_size: String,
    pub default_datacenter: String,
}

impl CpConfig {
    pub fn from_env() -> AppResult<Self> {
        Self::from_map(&env_map())
    }

    pub fn from_map(vars: &HashMap<String, String>) -> AppResult<Self> {
        Ok(Self {
            bind_addr: get(vars, "CP_BIND_ADDR", "0.0.0.0:8080"),
            database_url: get(vars, "CP_DATABASE_URL", "sqlite://easyenclave.db?mode=rwc"),
            admin_password: optional(vars, "CP_ADMIN_PASSWORD"),
            tcb_enforcement_mode: get(vars, "CP_TCB_ENFORCEMENT_MODE", "strict"),
            rtmr_enforcement_mode: get(vars, "CP_RTMR_ENFORCEMENT_MODE", "strict"),
            nonce_enforcement_mode: get(vars, "CP_NONCE_ENFORCEMENT_MODE", "required"),
        })
    }
}

impl AgentConfig {
    pub fn from_env() -> AppResult<Self> {
        Self::from_map(&env_map())
    }

    pub fn from_map(vars: &HashMap<String, String>) -> AppResult<Self> {
        let cp_url = required(vars, "AGENT_CP_URL")?;
        Ok(Self {
            cp_url,
            bootstrap_token: optional(vars, "AGENT_BOOTSTRAP_TOKEN"),
            node_size: get(vars, "AGENT_NODE_SIZE", "standard"),
            datacenter: get(vars, "AGENT_DATACENTER", "local:qemu"),
            owner: optional(vars, "AGENT_OWNER"),
        })
    }
}

impl LauncherConfig {
    pub fn from_env() -> AppResult<Self> {
        Self::from_map(&env_map())
    }

    pub fn from_map(vars: &HashMap<String, String>) -> AppResult<Self> {
        let cp_url = required(vars, "LAUNCHER_CP_URL")?;
        Ok(Self {
            cp_url,
            default_node_size: get(vars, "LAUNCHER_DEFAULT_NODE_SIZE", "standard"),
            default_datacenter: get(vars, "LAUNCHER_DEFAULT_DATACENTER", "local:qemu"),
        })
    }
}

fn env_map() -> HashMap<String, String> {
    env::vars().collect()
}

fn get(vars: &HashMap<String, String>, key: &str, default: &str) -> String {
    vars.get(key)
        .cloned()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn required(vars: &HashMap<String, String>, key: &str) -> AppResult<String> {
    vars.get(key)
        .cloned()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::Config(format!("missing required env var {key}")))
}

fn optional(vars: &HashMap<String, String>, key: &str) -> Option<String> {
    vars.get(key).cloned().filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{AgentConfig, CpConfig, LauncherConfig};

    #[test]
    fn cp_config_defaults_apply() {
        let vars = HashMap::new();
        let cfg = CpConfig::from_map(&vars).expect("cp config");

        assert_eq!(cfg.bind_addr, "0.0.0.0:8080");
        assert_eq!(cfg.database_url, "sqlite://easyenclave.db?mode=rwc");
        assert_eq!(cfg.tcb_enforcement_mode, "strict");
        assert_eq!(cfg.rtmr_enforcement_mode, "strict");
        assert_eq!(cfg.nonce_enforcement_mode, "required");
    }

    #[test]
    fn agent_config_requires_cp_url() {
        let vars = HashMap::new();
        let err = AgentConfig::from_map(&vars).expect_err("should fail");
        assert!(err.to_string().contains("AGENT_CP_URL"));
    }

    #[test]
    fn launcher_config_parses_required_url() {
        let mut vars = HashMap::new();
        vars.insert("LAUNCHER_CP_URL".into(), "http://127.0.0.1:8080".into());

        let cfg = LauncherConfig::from_map(&vars).expect("launcher config");
        assert_eq!(cfg.cp_url, "http://127.0.0.1:8080");
        assert_eq!(cfg.default_node_size, "standard");
    }
}
