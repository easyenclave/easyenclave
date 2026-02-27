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
    pub appraisal_url: String,
    pub api_key: String,
    pub allow_insecure_test_attestation: bool,
}

impl ItaVerifier {
    pub fn new(
        appraisal_url: impl Into<String>,
        api_key: impl Into<String>,
        allow_insecure_test_attestation: bool,
    ) -> Self {
        Self {
            appraisal_url: appraisal_url.into(),
            api_key: api_key.into(),
            allow_insecure_test_attestation,
        }
    }

    pub async fn appraise_quote(&self, quote_b64: &str, mrtd: &str) -> AppResult<ItaClaims> {
        if quote_b64.is_empty() {
            return Err(AppError::Unauthorized("empty quote payload".to_owned()));
        }

        // Explicit local/test mode: do not call ITA, but keep same CP-side flow.
        if self.allow_insecure_test_attestation {
            return Ok(ItaClaims {
                sub: "test-agent".to_owned(),
                mrtd: mrtd.to_owned(),
                tcb_status: "UpToDate".to_owned(),
                issued_at: Utc::now(),
            });
        }

        if self.api_key.trim().is_empty() {
            return Err(AppError::Unauthorized(
                "ITA_API_KEY is required when insecure test attestation is disabled".to_owned(),
            ));
        }

        let body = serde_json::json!({"quote": quote_b64});
        let response = reqwest::Client::new()
            .post(&self.appraisal_url)
            .header("x-api-key", &self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::External(format!("ITA appraisal request failed: {e}")))?
            .error_for_status()
            .map_err(|e| AppError::External(format!("ITA appraisal response error: {e}")))?
            .json::<serde_json::Value>()
            .await
            .map_err(|e| AppError::External(format!("ITA appraisal decode failed: {e}")))?;

        let tcb_status = response
            .get("tcb_status")
            .and_then(|v| v.as_str())
            .or_else(|| {
                response
                    .get("result")
                    .and_then(|v| v.get("tcb_status"))
                    .and_then(|v| v.as_str())
            })
            .unwrap_or("Unknown")
            .to_owned();

        Ok(ItaClaims {
            sub: "ita-agent".to_owned(),
            mrtd: mrtd.to_owned(),
            tcb_status,
            issued_at: Utc::now(),
        })
    }
}
