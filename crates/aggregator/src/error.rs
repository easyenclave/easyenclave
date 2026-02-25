use thiserror::Error;

#[derive(Debug, Error)]
pub enum AggregatorError {
    #[error("agent not found: {0}")]
    AgentNotFound(String),

    #[error("agent rejected: {0}")]
    AgentRejected(String),

    #[error("scrape failed: {0}")]
    ScrapeFailed(String),

    #[error("proxy error: {0}")]
    Proxy(String),

    #[error("measurement submission failed: {0}")]
    MeasurementSubmission(String),

    #[error("billing error: {0}")]
    Billing(String),

    #[error("attestation error: {0}")]
    Attestation(#[from] ee_attestation::error::AttestationError),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}
