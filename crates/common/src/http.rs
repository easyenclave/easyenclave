use reqwest::{Client, ClientBuilder};
use std::time::Duration;

/// Build a standard HTTP client with reasonable defaults.
pub fn build_client() -> Client {
    ClientBuilder::new()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(4)
        .build()
        .expect("failed to build HTTP client")
}

/// Extract a bearer token from an Authorization header value.
pub fn extract_bearer(header: &str) -> Option<&str> {
    header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
}
