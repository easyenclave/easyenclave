use std::env;
use std::sync::Arc;
use std::time::Duration;

use ee_attestation::ita::ItaVerifier;
use ee_common::error::{AppError, AppResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubOidcIdentity {
    pub owner: String,
    pub repository: Option<String>,
}

#[derive(Clone)]
pub struct GithubOidcService {
    verifier: Option<Arc<ItaVerifier>>,
    #[cfg(test)]
    forced_owner: Option<String>,
}

impl GithubOidcService {
    pub fn from_env() -> Self {
        let audience = env::var("CP_GITHUB_OIDC_AUDIENCE").ok();
        let verifier = audience.map(|aud| {
            let jwks_url = env::var("CP_GITHUB_OIDC_JWKS_URL").unwrap_or_else(|_| {
                "https://token.actions.githubusercontent.com/.well-known/jwks".to_string()
            });
            let issuer = env::var("CP_GITHUB_OIDC_ISSUER")
                .unwrap_or_else(|_| "https://token.actions.githubusercontent.com".to_string());
            let ttl_seconds = env::var("CP_GITHUB_OIDC_JWKS_TTL_SECONDS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(300);
            Arc::new(ItaVerifier::new(
                jwks_url,
                issuer,
                aud,
                Duration::from_secs(ttl_seconds),
            ))
        });
        Self {
            verifier,
            #[cfg(test)]
            forced_owner: None,
        }
    }

    pub fn disabled_for_tests() -> Self {
        Self {
            verifier: None,
            #[cfg(test)]
            forced_owner: None,
        }
    }

    #[cfg(test)]
    pub fn with_verifier_for_tests(verifier: ItaVerifier) -> Self {
        Self {
            verifier: Some(Arc::new(verifier)),
            forced_owner: None,
        }
    }

    #[cfg(test)]
    pub fn with_forced_owner_for_tests(owner: &str) -> Self {
        Self {
            verifier: None,
            forced_owner: Some(owner.to_string()),
        }
    }

    pub fn is_enabled(&self) -> bool {
        if self.verifier.is_some() {
            return true;
        }
        #[cfg(test)]
        if self.forced_owner.is_some() {
            return true;
        }
        false
    }

    pub fn verify_owner_token(&self, token: &str) -> AppResult<GithubOidcIdentity> {
        #[cfg(test)]
        if let Some(owner) = &self.forced_owner {
            if token.trim().is_empty() {
                return Err(AppError::Unauthorized);
            }
            return Ok(GithubOidcIdentity {
                owner: owner.clone(),
                repository: None,
            });
        }

        let verifier = self.verifier.as_ref().ok_or_else(|| {
            AppError::Config("github oidc verifier is not configured".to_string())
        })?;
        let claims = verifier.verify_attestation_token(token)?;

        let owner = claims
            .extra
            .get("repository_owner")
            .and_then(|v| v.as_str())
            .filter(|v| !v.trim().is_empty())
            .map(ToString::to_string)
            .ok_or(AppError::Unauthorized)?;
        let repository = claims
            .extra
            .get("repository")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);

        Ok(GithubOidcIdentity { owner, repository })
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::Engine as _;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use mockito::Server;
    use serde_json::json;

    use super::GithubOidcService;

    fn now_unix() -> usize {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs() as usize
    }

    fn hs256_token(secret: &[u8], kid: &str, iss: &str, aud: &str, owner: &str) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(kid.to_string());
        encode(
            &header,
            &json!({
                "iss": iss,
                "aud": aud,
                "exp": now_unix() + 300,
                "nbf": now_unix() - 1,
                "repository_owner": owner,
                "repository": format!("{owner}/example-repo")
            }),
            &EncodingKey::from_secret(secret),
        )
        .expect("token")
    }

    #[test]
    fn verifies_owner_claim_from_github_oidc_token() {
        let mut server = Server::new();
        let secret = b"github-oidc-secret";
        let k = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);

        let _jwks_mock = server
            .mock("GET", "/jwks")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "keys": [{
                        "kty": "oct",
                        "kid": "gha-kid",
                        "alg": "HS256",
                        "use": "sig",
                        "k": k
                    }]
                })
                .to_string(),
            )
            .create();

        let verifier = ee_attestation::ita::ItaVerifier::new(
            format!("{}/jwks", server.url()),
            "https://token.actions.githubusercontent.com".to_string(),
            "easyenclave".to_string(),
            std::time::Duration::from_secs(300),
        );
        let service = GithubOidcService {
            verifier: Some(std::sync::Arc::new(verifier)),
            forced_owner: None,
        };

        let token = hs256_token(
            secret,
            "gha-kid",
            "https://token.actions.githubusercontent.com",
            "easyenclave",
            "example-org",
        );

        let identity = service.verify_owner_token(&token).expect("verify");
        assert_eq!(identity.owner, "example-org");
        assert_eq!(
            identity.repository.as_deref(),
            Some("example-org/example-repo")
        );
    }
}
