use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("registration failed: {0}")]
    Registration(String),

    #[error("deployment failed: {0}")]
    Deployment(String),

    #[error("container error: {0}")]
    Container(String),

    #[error("tunnel error: {0}")]
    Tunnel(String),

    #[error("attestation error: {0}")]
    Attestation(#[from] ee_attestation::error::AttestationError),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}
