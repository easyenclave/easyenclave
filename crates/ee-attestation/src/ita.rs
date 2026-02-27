use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
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

#[derive(Debug, Deserialize)]
struct ItaAppraisalResponse {
    token: Option<String>,
    appraisal_token: Option<String>,
    result: Option<ItaResult>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ItaResult {
    tcb_status: Option<String>,
    mrtd: Option<String>,
    attester_tcb_status: Option<String>,
    tdx: Option<ItaTdxResult>,
}

#[derive(Debug, Deserialize)]
struct ItaTdxResult {
    tcb_status: Option<String>,
    mrtd: Option<String>,
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

    pub async fn appraise_quote(
        &self,
        quote_b64: &str,
        expected_mrtd: &str,
    ) -> AppResult<ItaClaims> {
        if quote_b64.is_empty() {
            return Err(AppError::Unauthorized("empty quote payload".to_owned()));
        }

        if self.allow_insecure_test_attestation {
            return Ok(ItaClaims {
                sub: "test-agent".to_owned(),
                mrtd: expected_mrtd.to_owned(),
                tcb_status: "UpToDate".to_owned(),
                issued_at: Utc::now(),
            });
        }

        if self.api_key.trim().is_empty() {
            return Err(AppError::Unauthorized(
                "ITA_API_KEY is required when insecure test attestation is disabled".to_owned(),
            ));
        }

        let response = reqwest::Client::new()
            .post(&self.appraisal_url)
            .header("x-api-key", &self.api_key)
            .json(&serde_json::json!({"quote": quote_b64}))
            .send()
            .await
            .map_err(|e| AppError::External(format!("ITA appraisal request failed: {e}")))?
            .error_for_status()
            .map_err(|e| AppError::External(format!("ITA appraisal response error: {e}")))?
            .json::<ItaAppraisalResponse>()
            .await
            .map_err(|e| AppError::External(format!("ITA appraisal decode failed: {e}")))?;

        if let Some(status) = &response.status {
            let normalized = status.to_ascii_lowercase();
            if normalized != "ok" && normalized != "success" {
                return Err(AppError::Unauthorized(format!(
                    "ITA appraisal status is not successful: {status}"
                )));
            }
        }

        let (mrtd, tcb_status) = if let Some(token) = response.token.or(response.appraisal_token) {
            extract_from_jwt_claims(&token)?
        } else if let Some(result) = response.result {
            let mrtd = result
                .mrtd
                .or_else(|| result.tdx.as_ref().and_then(|t| t.mrtd.clone()))
                .ok_or_else(|| AppError::Unauthorized("missing mrtd in ITA response".to_owned()))?;
            let tcb_status = result
                .tcb_status
                .or(result.attester_tcb_status)
                .or_else(|| result.tdx.and_then(|t| t.tcb_status))
                .ok_or_else(|| {
                    AppError::Unauthorized("missing tcb_status in ITA response".to_owned())
                })?;
            (mrtd, tcb_status)
        } else {
            return Err(AppError::Unauthorized(
                "ITA response missing token and result fields".to_owned(),
            ));
        };

        if !mrtd.eq_ignore_ascii_case(expected_mrtd) {
            return Err(AppError::Unauthorized(
                "ITA response mrtd does not match parsed quote mrtd".to_owned(),
            ));
        }

        Ok(ItaClaims {
            sub: "ita-agent".to_owned(),
            mrtd,
            tcb_status,
            issued_at: Utc::now(),
        })
    }
}

fn extract_from_jwt_claims(token: &str) -> AppResult<(String, String)> {
    let claims = parse_jwt_claims(token)?;

    let mrtd = claims
        .get("mrtd")
        .and_then(|v| v.as_str())
        .or_else(|| claims.get("tdx_mrtd").and_then(|v| v.as_str()))
        .or_else(|| {
            claims
                .get("tdx")
                .and_then(|v| v.get("mrtd"))
                .and_then(|v| v.as_str())
        })
        .ok_or_else(|| AppError::Unauthorized("missing mrtd in ITA token claims".to_owned()))?
        .to_owned();

    let tcb_status = claims
        .get("tcb_status")
        .and_then(|v| v.as_str())
        .or_else(|| claims.get("attester_tcb_status").and_then(|v| v.as_str()))
        .or_else(|| claims.get("tdx_tcb_status").and_then(|v| v.as_str()))
        .or_else(|| {
            claims
                .get("tdx")
                .and_then(|v| v.get("tcb_status"))
                .and_then(|v| v.as_str())
        })
        .ok_or_else(|| AppError::Unauthorized("missing tcb_status in ITA token claims".to_owned()))?
        .to_owned();

    Ok((mrtd, tcb_status))
}

fn parse_jwt_claims(token: &str) -> AppResult<serde_json::Value> {
    let mut parts = token.split('.');
    let _header = parts
        .next()
        .ok_or_else(|| AppError::Unauthorized("invalid ITA JWT format".to_owned()))?;
    let claims = parts
        .next()
        .ok_or_else(|| AppError::Unauthorized("invalid ITA JWT format".to_owned()))?;

    let decoded = URL_SAFE_NO_PAD
        .decode(claims)
        .map_err(|e| AppError::Unauthorized(format!("invalid ITA JWT claims encoding: {e}")))?;

    serde_json::from_slice::<serde_json::Value>(&decoded)
        .map_err(|e| AppError::Unauthorized(format!("invalid ITA JWT claims JSON: {e}")))
}

#[cfg(test)]
mod tests {
    use super::parse_jwt_claims;

    #[test]
    fn parse_jwt_claims_decodes_payload() {
        let token = "eyJhbGciOiJub25lIn0.eyJtcnRkIjoiYWIiLCJ0Y2Jfc3RhdHVzIjoiVXBUb0RhdGUifQ.";
        let claims = parse_jwt_claims(token).expect("must decode claims");
        assert_eq!(claims["mrtd"].as_str(), Some("ab"));
    }
}
