use thiserror::Error;

#[derive(Debug, Error)]
pub enum CpError {
    #[error("database error: {0}")]
    Database(String),

    #[error("scrape failed: {0}")]
    ScrapeFailed(String),

    #[error("aggregator not found: {0}")]
    AggregatorNotFound(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

impl From<rusqlite::Error> for CpError {
    fn from(e: rusqlite::Error) -> Self {
        CpError::Database(e.to_string())
    }
}
