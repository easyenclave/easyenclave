use thiserror::Error;

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("TDX quote generation failed: {0}")]
    QuoteGeneration(String),

    #[error("Intel TA token verification failed: {0}")]
    TokenVerification(String),

    #[error("JWKS fetch failed: {0}")]
    JwksFetch(String),

    #[error("MRTD extraction failed: {0}")]
    MrtdExtraction(String),

    #[error("MRTD mismatch: expected {expected}, got {actual}")]
    MrtdMismatch { expected: String, actual: String },

    #[error("TCB status unacceptable: {0}")]
    TcbStatus(String),

    #[error("nonce mismatch")]
    NonceMismatch,

    #[error("token expired")]
    TokenExpired,

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}
