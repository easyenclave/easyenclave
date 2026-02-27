use http::StatusCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("external service error: {0}")]
    External(String),
    #[error("internal error")]
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

impl AppError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidInput(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::External(_) => StatusCode::BAD_GATEWAY,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "invalid_input",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict(_) => "conflict",
            Self::Config(_) => "config_error",
            Self::External(_) => "external_error",
            Self::Internal => "internal_error",
        }
    }

    pub fn to_error_body(&self) -> ErrorBody {
        ErrorBody {
            code: self.code().to_string(),
            message: self.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AppError;

    #[test]
    fn error_body_serializes() {
        let err = AppError::InvalidInput("bad payload".to_string());
        let body = err.to_error_body();

        let json = serde_json::to_string(&body).expect("serialize");
        assert!(json.contains("invalid_input"));
        assert!(json.contains("bad payload"));
    }
}
