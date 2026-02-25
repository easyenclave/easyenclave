//! Intel Trust Authority (ITA) token verification.
//!
//! The agent sends its TDX quote to Intel TA and receives a JWT.
//! The aggregator verifies that JWT using Intel's JWKS.

use crate::error::AttestationError;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::Utc;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// ITA JWT claims
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItaClaims {
    /// Token issuer (Intel Trust Authority)
    pub iss: Option<String>,
    /// Subject (attester identifier)
    pub sub: Option<String>,
    /// Issued at (unix timestamp)
    pub iat: Option<i64>,
    /// Expiration (unix timestamp)
    pub exp: Option<i64>,
    /// Nonce echoed from request
    pub nonce: Option<String>,
    /// TDX-specific measurements
    #[serde(rename = "attester_tcb_status")]
    pub tcb_status: Option<String>,
    /// MRTD (build-time measurement of the TD)
    #[serde(rename = "attester_held_data")]
    pub held_data: Option<String>,
    /// TD report body fields
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

impl ItaClaims {
    /// Extract the MRTD value from the token body.
    pub fn mrtd(&self) -> Option<String> {
        // Intel TA puts MRTD in the tdx_mrtd field within the flattened extras
        self.extra
            .get("tdx_mrtd")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }
}

// ---------------------------------------------------------------------------
// JWKS cache
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    n: Option<String>,
    e: Option<String>,
    #[allow(dead_code)]
    alg: Option<String>,
}

/// Cached JWKS for Intel Trust Authority.
#[derive(Clone)]
pub struct JwksCache {
    url: String,
    client: reqwest::Client,
    cache: Arc<RwLock<Option<CachedJwks>>>,
}

struct CachedJwks {
    keys: Vec<Jwk>,
    fetched_at: chrono::DateTime<Utc>,
}

impl JwksCache {
    pub fn new(ita_base_url: &str, client: reqwest::Client) -> Self {
        let url = format!(
            "{}/.well-known/jwks.json",
            ita_base_url.trim_end_matches('/')
        );
        Self {
            url,
            client,
            cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Fetch or return cached JWKS. Refreshes every 60 minutes.
    async fn get_keys(&self) -> Result<Vec<Jwk>, AttestationError> {
        {
            let guard = self.cache.read().await;
            if let Some(cached) = guard.as_ref() {
                let age = Utc::now() - cached.fetched_at;
                if age.num_minutes() < 60 {
                    return Ok(cached.keys.clone());
                }
            }
        }

        let resp = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| AttestationError::JwksFetch(e.to_string()))?;

        let jwks: JwkSet = resp
            .json()
            .await
            .map_err(|e| AttestationError::JwksFetch(e.to_string()))?;

        let keys = jwks.keys;
        let mut guard = self.cache.write().await;
        *guard = Some(CachedJwks {
            keys: keys.clone(),
            fetched_at: Utc::now(),
        });

        Ok(keys)
    }

    /// Find a decoding key by the JWT's `kid` header.
    async fn find_key(&self, kid: &str) -> Result<DecodingKey, AttestationError> {
        let keys = self.get_keys().await?;
        let jwk = keys
            .iter()
            .find(|k| k.kid.as_deref() == Some(kid))
            .ok_or_else(|| {
                AttestationError::TokenVerification(format!("kid {kid} not found in JWKS"))
            })?;

        if jwk.kty != "RSA" {
            return Err(AttestationError::TokenVerification(format!(
                "unsupported key type: {}",
                jwk.kty
            )));
        }

        let n = jwk
            .n
            .as_ref()
            .ok_or_else(|| AttestationError::TokenVerification("missing n in JWK".to_string()))?;
        let e = jwk
            .e
            .as_ref()
            .ok_or_else(|| AttestationError::TokenVerification("missing e in JWK".to_string()))?;

        DecodingKey::from_rsa_components(n, e)
            .map_err(|e| AttestationError::TokenVerification(format!("RSA key decode: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Verification config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum EnforcementMode {
    Strict,
    Warn,
    Disabled,
}

impl EnforcementMode {
    pub fn from_env_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "strict" => Self::Strict,
            "warn" => Self::Warn,
            "disabled" => Self::Disabled,
            _ => Self::Strict,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifyConfig {
    pub tcb_mode: EnforcementMode,
    pub allowed_tcb_statuses: Vec<String>,
    pub nonce_mode: EnforcementMode,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            tcb_mode: EnforcementMode::Strict,
            allowed_tcb_statuses: vec!["UpToDate".to_string()],
            nonce_mode: EnforcementMode::Strict,
        }
    }
}

// ---------------------------------------------------------------------------
// Token request (agent → Intel TA)
// ---------------------------------------------------------------------------

/// Request an attestation token from Intel Trust Authority.
pub async fn request_token(
    client: &reqwest::Client,
    ita_url: &str,
    api_key: &str,
    quote: &[u8],
    nonce: Option<&str>,
) -> Result<String, AttestationError> {
    let body = serde_json::json!({
        "quote": BASE64.encode(quote),
        "nonce": nonce,
    });

    let resp = client
        .post(format!("{}/attest", ita_url.trim_end_matches('/')))
        .header("x-api-key", api_key)
        .json(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(AttestationError::TokenVerification(format!(
            "ITA returned {status}: {body}"
        )));
    }

    #[derive(Deserialize)]
    struct TokenResp {
        token: String,
    }

    let token_resp: TokenResp = resp
        .json()
        .await
        .map_err(|e| AttestationError::TokenVerification(e.to_string()))?;

    Ok(token_resp.token)
}

// ---------------------------------------------------------------------------
// Token verification (aggregator side)
// ---------------------------------------------------------------------------

/// Verify an Intel TA JWT token and extract claims.
pub async fn verify_token(
    jwks: &JwksCache,
    token: &str,
    expected_nonce: Option<&str>,
    config: &VerifyConfig,
) -> Result<ItaClaims, AttestationError> {
    let header = decode_header(token)
        .map_err(|e| AttestationError::TokenVerification(format!("decode header: {e}")))?;

    let kid = header.kid.ok_or_else(|| {
        AttestationError::TokenVerification("missing kid in JWT header".to_string())
    })?;

    let key = jwks.find_key(&kid).await?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    validation.set_issuer(&["Intel Trust Authority"]);

    let token_data = decode::<ItaClaims>(token, &key, &validation)
        .map_err(|e| AttestationError::TokenVerification(format!("JWT decode: {e}")))?;

    let claims = token_data.claims;

    // Nonce check
    if let Some(expected) = expected_nonce {
        match config.nonce_mode {
            EnforcementMode::Strict => {
                if claims.nonce.as_deref() != Some(expected) {
                    return Err(AttestationError::NonceMismatch);
                }
            }
            EnforcementMode::Warn => {
                if claims.nonce.as_deref() != Some(expected) {
                    tracing::warn!("nonce mismatch (warn mode)");
                }
            }
            EnforcementMode::Disabled => {}
        }
    }

    // TCB status check
    if let Some(tcb) = &claims.tcb_status {
        match config.tcb_mode {
            EnforcementMode::Strict => {
                if !config.allowed_tcb_statuses.iter().any(|s| s == tcb) {
                    return Err(AttestationError::TcbStatus(tcb.clone()));
                }
            }
            EnforcementMode::Warn => {
                if !config.allowed_tcb_statuses.iter().any(|s| s == tcb) {
                    tracing::warn!(tcb_status = %tcb, "TCB status not in allowed list (warn mode)");
                }
            }
            EnforcementMode::Disabled => {}
        }
    }

    Ok(claims)
}
