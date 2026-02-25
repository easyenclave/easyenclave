use ee_common::config::{env_bool, env_csv, env_or, listen_addr, optional_env};
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct CpConfig {
    pub listen_addr: SocketAddr,
    pub db_path: String,
    pub builtin_aggregator: bool,
    pub trusted_aggregator_ids: Vec<String>,
    pub admin_github_logins: Vec<String>,
    pub github_oauth_client_id: String,
    pub github_oauth_client_secret: String,
    pub github_oauth_redirect_uri: String,
}

impl CpConfig {
    pub fn from_env() -> Self {
        Self {
            listen_addr: listen_addr("LISTEN_ADDR", "0.0.0.0:8080"),
            db_path: env_or("DB_PATH", "easyenclave.db"),
            builtin_aggregator: env_bool("BUILTIN_AGGREGATOR", true),
            trusted_aggregator_ids: env_csv("TRUSTED_AGGREGATOR_IDS"),
            admin_github_logins: env_csv("ADMIN_GITHUB_LOGINS"),
            github_oauth_client_id: env_or("GITHUB_OAUTH_CLIENT_ID", ""),
            github_oauth_client_secret: env_or("GITHUB_OAUTH_CLIENT_SECRET", ""),
            github_oauth_redirect_uri: env_or("GITHUB_OAUTH_REDIRECT_URI", ""),
        }
    }
}
