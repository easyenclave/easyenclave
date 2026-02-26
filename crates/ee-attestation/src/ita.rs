use chrono::{DateTime, Utc};
use ee_common::error::{AppError, AppResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItaClaims {
    pub sub: String,
    pub mrtd: String,
    pub tcb_status: String,
    pub issued_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ItaVerifier {
    pub jwks_url: String,
}

impl ItaVerifier {
    pub fn new(jwks_url: impl Into<String>) -> Self {
        Self {
            jwks_url: jwks_url.into(),
        }
    }

    pub async fn verify_attestation_jwt(&self, token: &str) -> AppResult<ItaClaims> {
        if token.is_empty() {
            return Err(AppError::Unauthorized("empty ITA token".to_owned()));
        }

        if let Some(mrtd) = token.strip_prefix("test-ita:") {
            return Ok(ItaClaims {
                sub: "test-agent".to_owned(),
                mrtd: mrtd.to_owned(),
                tcb_status: "UpToDate".to_owned(),
                issued_at: Utc::now(),
            });
        }

        Err(AppError::Unauthorized(format!(
            "ITA verification not implemented for non-test tokens (JWKS: {})",
            self.jwks_url
        )))
    }
}
