use ee_common::config::{env_bool, env_or, env_parse, listen_addr, optional_env};
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct AggregatorConfig {
    pub listen_addr: SocketAddr,
    /// CP URL to register with and submit measurements to.
    pub cp_url: Option<String>,
    /// API key for authenticating with CP.
    pub api_key: String,
    /// Whether this aggregator is trusted (can submit measurements).
    pub is_trusted: bool,
    /// Region identifier for this aggregator.
    pub region: String,
    /// Health scrape interval in seconds.
    pub health_interval_secs: u64,
    /// Attestation re-verify interval in seconds.
    pub attestation_interval_secs: u64,
    /// Intel Trust Authority base URL.
    pub ita_api_url: String,
    /// BTCPay configuration (if set, enables real billing).
    pub btcpay: Option<BtcPayConfig>,
}

#[derive(Debug, Clone)]
pub struct BtcPayConfig {
    pub url: String,
    pub api_key: String,
    pub store_id: String,
    pub webhook_secret: String,
}

impl AggregatorConfig {
    pub fn from_env() -> Self {
        let btcpay = optional_env("BTCPAY_URL").map(|url| BtcPayConfig {
            url,
            api_key: env_or("BTCPAY_API_KEY", ""),
            store_id: env_or("BTCPAY_STORE_ID", ""),
            webhook_secret: env_or("BTCPAY_WEBHOOK_SECRET", ""),
        });

        Self {
            listen_addr: listen_addr("LISTEN_ADDR", "0.0.0.0:8083"),
            cp_url: optional_env("CP_URL"),
            api_key: env_or("AGGREGATOR_API_KEY", ""),
            is_trusted: env_bool("IS_TRUSTED", false),
            region: env_or("REGION", "us-central1"),
            health_interval_secs: env_parse("HEALTH_INTERVAL_SECS", 15),
            attestation_interval_secs: env_parse("ATTESTATION_INTERVAL_SECS", 300),
            ita_api_url: env_or(
                "ITA_API_URL",
                "https://api.trustauthority.intel.com/appraisal/v2",
            ),
            btcpay,
        }
    }

    /// Create config for the built-in aggregator inside CP.
    pub fn builtin(cp_listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr: cp_listen_addr,
            cp_url: Some(format!("http://{cp_listen_addr}")),
            api_key: String::new(),
            is_trusted: true,
            region: "builtin".to_string(),
            health_interval_secs: 15,
            attestation_interval_secs: 300,
            ita_api_url: env_or(
                "ITA_API_URL",
                "https://api.trustauthority.intel.com/appraisal/v2",
            ),
            btcpay: None,
        }
    }
}
