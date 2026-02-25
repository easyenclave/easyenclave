use thiserror::Error;

#[derive(Debug, Error)]
pub enum HostdError {
    #[error("VM launch failed: {0}")]
    VmLaunch(String),

    #[error("VM stop failed: {0}")]
    VmStop(String),

    #[error("image not found: {0}")]
    ImageNotFound(String),

    #[error("resource exhausted: {0}")]
    ResourceExhausted(String),

    #[error("command failed: {0}")]
    Command(String),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}
