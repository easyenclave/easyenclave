use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use base64::Engine as _;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use ee_common::error::{AppError, AppResult};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationClaims {
    pub iss: String,
    pub aud: Value,
    pub exp: usize,
    #[serde(default)]
    pub nbf: Option<usize>,
    #[serde(default)]
    pub tdx_mrtd: Option<String>,
    #[serde(default)]
    pub attester_tcb_status: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwksDocument {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: Option<String>,
    pub alg: Option<String>,
    #[serde(rename = "use")]
    pub use_field: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
    pub k: Option<String>,
}

#[derive(Debug, Clone)]
struct CachedJwks {
    fetched_at: Instant,
    jwks: JwksDocument,
}

pub struct ItaVerifier {
    jwks_url: String,
    issuer: String,
    audience: String,
    ttl: Duration,
    client: reqwest::blocking::Client,
    cache: RwLock<Option<CachedJwks>>,
}

impl ItaVerifier {
    pub fn new(jwks_url: String, issuer: String, audience: String, ttl: Duration) -> Self {
        Self {
            jwks_url,
            issuer,
            audience,
            ttl,
            client: reqwest::blocking::Client::new(),
            cache: RwLock::new(None),
        }
    }

    pub fn verify_attestation_token(&self, token: &str) -> AppResult<AttestationClaims> {
        let header = decode_header(token)
            .map_err(|e| AppError::InvalidInput(format!("invalid token header: {e}")))?;
        let jwks = self.jwks()?;
        let jwk = self
            .select_key(&jwks, header.kid.as_deref())
            .ok_or(AppError::Unauthorized)?;

        let decoding_key = decoding_key_from_jwk(jwk)?;
        let mut validation = Validation::new(map_algorithm(header.alg)?);
        validation.validate_aud = false;
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let decoded = decode::<AttestationClaims>(token, &decoding_key, &validation)
            .map_err(|_| AppError::Unauthorized)?;

        let claims = decoded.claims;
        if claims.iss != self.issuer {
            return Err(AppError::Unauthorized);
        }
        if !audience_matches(&claims.aud, &self.audience) {
            return Err(AppError::Unauthorized);
        }

        Ok(claims)
    }

    fn jwks(&self) -> AppResult<JwksDocument> {
        if let Some(cached) = self.cache.read().expect("rwlock poisoned").as_ref() {
            if cached.fetched_at.elapsed() < self.ttl {
                return Ok(cached.jwks.clone());
            }
        }

        let jwks = self.fetch_jwks()?;
        *self.cache.write().expect("rwlock poisoned") = Some(CachedJwks {
            fetched_at: Instant::now(),
            jwks: jwks.clone(),
        });
        Ok(jwks)
    }

    fn fetch_jwks(&self) -> AppResult<JwksDocument> {
        let res = self
            .client
            .get(&self.jwks_url)
            .send()
            .map_err(|e| AppError::External(format!("jwks request failed: {e}")))?;
        let res = res
            .error_for_status()
            .map_err(|e| AppError::External(format!("jwks returned error status: {e}")))?;
        res.json::<JwksDocument>()
            .map_err(|e| AppError::External(format!("jwks parse failed: {e}")))
    }

    fn select_key<'a>(&self, jwks: &'a JwksDocument, kid: Option<&str>) -> Option<&'a Jwk> {
        if let Some(kid) = kid {
            return jwks.keys.iter().find(|k| k.kid.as_deref() == Some(kid));
        }
        jwks.keys.first()
    }
}

fn map_algorithm(alg: Algorithm) -> AppResult<Algorithm> {
    match alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::HS256
        | Algorithm::HS384
        | Algorithm::HS512 => Ok(alg),
        _ => Err(AppError::Unauthorized),
    }
}

fn decoding_key_from_jwk(jwk: &Jwk) -> AppResult<DecodingKey> {
    match jwk.kty.as_str() {
        "RSA" => {
            let n = jwk
                .n
                .as_ref()
                .ok_or_else(|| AppError::InvalidInput("jwks key missing rsa n".to_string()))?;
            let e = jwk
                .e
                .as_ref()
                .ok_or_else(|| AppError::InvalidInput("jwks key missing rsa e".to_string()))?;
            DecodingKey::from_rsa_components(n, e)
                .map_err(|e| AppError::InvalidInput(format!("invalid jwks rsa key: {e}")))
        }
        "oct" => {
            let k = jwk.k.as_ref().ok_or_else(|| {
                AppError::InvalidInput("jwks key missing symmetric k".to_string())
            })?;
            let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(k)
                .map_err(|e| AppError::InvalidInput(format!("invalid jwks symmetric key: {e}")))?;
            Ok(DecodingKey::from_secret(&secret))
        }
        other => Err(AppError::InvalidInput(format!(
            "unsupported jwks kty: {other}"
        ))),
    }
}

fn audience_matches(aud: &Value, expected: &str) -> bool {
    match aud {
        Value::String(s) => s == expected,
        Value::Array(values) => values.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use base64::Engine as _;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use mockito::Server;
    use serde_json::json;

    use super::ItaVerifier;

    fn now_unix() -> usize {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs() as usize
    }

    fn hs256_token(secret: &[u8], kid: &str, iss: &str, aud: &str, exp: usize) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(kid.to_string());
        encode(
            &header,
            &json!({
                "iss": iss,
                "aud": aud,
                "exp": exp,
                "nbf": now_unix() - 1,
                "tdx_mrtd": "a".repeat(96),
                "attester_tcb_status": "UpToDate"
            }),
            &EncodingKey::from_secret(secret),
        )
        .expect("token")
    }

    #[test]
    fn verifies_valid_token_with_mock_jwks() {
        let mut server = Server::new();
        let secret = b"super-secret-value";
        let k = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);

        let _jwks_mock = server
            .mock("GET", "/jwks")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "keys": [{
                        "kty": "oct",
                        "kid": "test-kid",
                        "alg": "HS256",
                        "use": "sig",
                        "k": k
                    }]
                })
                .to_string(),
            )
            .create();

        let verifier = ItaVerifier::new(
            format!("{}/jwks", server.url()),
            "https://issuer.example".to_string(),
            "expected-aud".to_string(),
            Duration::from_secs(300),
        );

        let token = hs256_token(
            secret,
            "test-kid",
            "https://issuer.example",
            "expected-aud",
            now_unix() + 300,
        );
        let claims = verifier.verify_attestation_token(&token).expect("claims");

        assert_eq!(claims.iss, "https://issuer.example");
        assert_eq!(claims.tdx_mrtd.expect("mrtd").len(), 96);
    }

    #[test]
    fn rejects_expired_token() {
        let mut server = Server::new();
        let secret = b"exp-test-secret";
        let k = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);

        let _jwks_mock = server
            .mock("GET", "/jwks")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({"keys": [{"kty": "oct", "kid": "kid-1", "k": k}]}).to_string())
            .create();

        let verifier = ItaVerifier::new(
            format!("{}/jwks", server.url()),
            "https://issuer.example".to_string(),
            "expected-aud".to_string(),
            Duration::from_secs(300),
        );

        let token = hs256_token(
            secret,
            "kid-1",
            "https://issuer.example",
            "expected-aud",
            now_unix().saturating_sub(120),
        );

        let err = verifier
            .verify_attestation_token(&token)
            .expect_err("expired");
        assert!(err.to_string().contains("unauthorized"));
    }

    #[test]
    fn rejects_wrong_audience() {
        let mut server = Server::new();
        let secret = b"aud-test-secret";
        let k = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);

        let _jwks_mock = server
            .mock("GET", "/jwks")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({"keys": [{"kty": "oct", "kid": "kid-aud", "k": k}]}).to_string())
            .create();

        let verifier = ItaVerifier::new(
            format!("{}/jwks", server.url()),
            "https://issuer.example".to_string(),
            "expected-aud".to_string(),
            Duration::from_secs(300),
        );

        let token = hs256_token(
            secret,
            "kid-aud",
            "https://issuer.example",
            "wrong-aud",
            now_unix() + 300,
        );

        let err = verifier
            .verify_attestation_token(&token)
            .expect_err("aud mismatch");
        assert!(err.to_string().contains("unauthorized"));
    }

    #[test]
    fn uses_jwks_cache_until_ttl() {
        let mut server = Server::new();
        let secret = b"cache-test-secret";
        let k = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);

        let jwks_mock = server
            .mock("GET", "/jwks")
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({"keys": [{"kty": "oct", "kid": "kid-cache", "k": k}]}).to_string())
            .create();

        let verifier = ItaVerifier::new(
            format!("{}/jwks", server.url()),
            "https://issuer.example".to_string(),
            "expected-aud".to_string(),
            Duration::from_secs(300),
        );

        let token = hs256_token(
            secret,
            "kid-cache",
            "https://issuer.example",
            "expected-aud",
            now_unix() + 300,
        );

        verifier.verify_attestation_token(&token).expect("first");
        verifier.verify_attestation_token(&token).expect("second");
        jwks_mock.assert();
    }
}
