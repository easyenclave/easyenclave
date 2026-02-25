//! CP-level proxy: fallback routing when no aggregator is nearby.

use ee_common::error::ApiError;

/// For now, CP proxy is a placeholder.
/// In production, CP would route requests to the nearest aggregator
/// or directly to agents registered via the built-in aggregator.
pub async fn proxy_fallback() -> Result<String, ApiError> {
    Ok("CP proxy: not yet implemented".to_string())
}
