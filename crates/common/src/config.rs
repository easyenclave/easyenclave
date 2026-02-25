use std::env;
use std::net::SocketAddr;
use std::str::FromStr;

/// Read a required env var or panic with a helpful message.
pub fn require_env(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

/// Read an optional env var.
pub fn optional_env(key: &str) -> Option<String> {
    env::var(key).ok().filter(|v| !v.is_empty())
}

/// Read an env var with a default fallback.
pub fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Parse an env var into the target type, with a default.
pub fn env_parse<T: FromStr>(key: &str, default: T) -> T {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Parse a listen address from env.
pub fn listen_addr(key: &str, default: &str) -> SocketAddr {
    env_or(key, default)
        .parse()
        .expect("invalid listen address")
}

/// Parse a comma-separated list from env.
pub fn env_csv(key: &str) -> Vec<String> {
    env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parse a bool from env (true/1/yes).
pub fn env_bool(key: &str, default: bool) -> bool {
    env::var(key)
        .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"))
        .unwrap_or(default)
}
