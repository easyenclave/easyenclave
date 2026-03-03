use std::collections::HashMap;
use std::env;

use crate::common::error::AppResult;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpConfig {
    pub bind_addr: String,
    pub database_url: String,
    pub admin_password: Option<String>,
    pub tcb_enforcement_mode: String,
    pub rtmr_enforcement_mode: String,
    pub nonce_enforcement_mode: String,
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

fn env_map() -> HashMap<String, String> {
    env::vars().collect()
}

fn get(vars: &HashMap<String, String>, key: &str, default: &str) -> String {
    vars.get(key)
        .cloned()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn optional(vars: &HashMap<String, String>, key: &str) -> Option<String> {
    vars.get(key).cloned().filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::CpConfig;

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
}
