use ee_common::{
    config::CpConfig,
    error::{AppError, AppResult},
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct GithubIdentity {
    pub repository_owner: String,
    pub repository: Option<String>,
    pub subject: String,
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    n: Option<String>,
    e: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct GithubClaims {
    sub: String,
    repository_owner: Option<String>,
    repository: Option<String>,
    iss: Option<String>,
    aud: Option<serde_json::Value>,
    exp: Option<u64>,
}

pub async fn verify_bearer(config: &CpConfig, auth_header: &str) -> AppResult<GithubIdentity> {
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("missing Bearer token".to_owned()))?
        .trim();

    if config.allow_insecure_test_oidc {
        if let Some(owner) = token.strip_prefix("test-owner:") {
            return Ok(GithubIdentity {
                repository_owner: owner.to_owned(),
                repository: Some(format!("{owner}/demo")),
                subject: "repo:test/demo".to_owned(),
            });
        }
    }

    let header = decode_header(token)
        .map_err(|e| AppError::Unauthorized(format!("invalid JWT header: {e}")))?;
    if header.alg != Algorithm::RS256 {
        return Err(AppError::Unauthorized(
            "unsupported JWT algorithm; expected RS256".to_owned(),
        ));
    }

    let kid = header
        .kid
        .ok_or_else(|| AppError::Unauthorized("missing JWT kid".to_owned()))?;

    let jwks = reqwest::Client::new()
        .get(&config.github_oidc_jwks_url)
        .send()
        .await
        .map_err(|e| AppError::External(format!("failed to fetch GitHub OIDC JWKS: {e}")))?
        .error_for_status()
        .map_err(|e| AppError::External(format!("GitHub OIDC JWKS error: {e}")))?
        .json::<JwksResponse>()
        .await
        .map_err(|e| AppError::External(format!("failed to parse GitHub OIDC JWKS: {e}")))?;

    let jwk = jwks
        .keys
        .into_iter()
        .find(|jwk| jwk.kid.as_deref() == Some(kid.as_str()))
        .ok_or_else(|| AppError::Unauthorized("no matching JWK for token kid".to_owned()))?;

    if jwk.kty != "RSA" {
        return Err(AppError::Unauthorized(
            "unsupported JWK key type".to_owned(),
        ));
    }

    let modulus = jwk
        .n
        .ok_or_else(|| AppError::Unauthorized("missing JWK modulus".to_owned()))?;
    let exponent = jwk
        .e
        .ok_or_else(|| AppError::Unauthorized("missing JWK exponent".to_owned()))?;

    let decoding_key = DecodingKey::from_rsa_components(&modulus, &exponent)
        .map_err(|e| AppError::Unauthorized(format!("invalid JWK RSA components: {e}")))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[config.github_oidc_issuer.as_str()]);
    if let Some(expected_aud) = &config.github_oidc_audience {
        validation.set_audience(&[expected_aud.as_str()]);
    } else {
        validation.validate_aud = false;
    }

    let claims = decode::<GithubClaims>(token, &decoding_key, &validation)
        .map_err(|e| AppError::Unauthorized(format!("GitHub OIDC JWT validation failed: {e}")))?
        .claims;

    if claims.exp.is_none() {
        return Err(AppError::Unauthorized("missing exp claim".to_owned()));
    }
    if claims.iss.as_deref() != Some(config.github_oidc_issuer.as_str()) {
        return Err(AppError::Unauthorized("invalid iss claim".to_owned()));
    }
    if let Some(expected_aud) = &config.github_oidc_audience {
        let aud_ok = claims
            .aud
            .as_ref()
            .map(|aud| audience_contains(aud, expected_aud))
            .unwrap_or(false);
        if !aud_ok {
            return Err(AppError::Unauthorized("invalid aud claim".to_owned()));
        }
    }

    let repository_owner = claims
        .repository_owner
        .clone()
        .or_else(|| {
            claims
                .repository
                .as_ref()
                .and_then(|repo| repo.split('/').next().map(|s| s.to_owned()))
        })
        .ok_or_else(|| AppError::Unauthorized("missing repository_owner claim".to_owned()))?;

    if repository_owner.trim().is_empty() {
        return Err(AppError::Unauthorized(
            "empty repository_owner claim".to_owned(),
        ));
    }

    Ok(GithubIdentity {
        repository_owner,
        repository: claims.repository,
        subject: claims.sub,
    })
}

fn audience_contains(value: &serde_json::Value, expected: &str) -> bool {
    match value {
        serde_json::Value::String(s) => s == expected,
        serde_json::Value::Array(values) => values.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::audience_contains;

    #[test]
    fn audience_contains_handles_string_and_array() {
        assert!(audience_contains(&serde_json::json!("cp"), "cp"));
        assert!(audience_contains(&serde_json::json!(["x", "cp"]), "cp"));
        assert!(!audience_contains(&serde_json::json!(["x", "y"]), "cp"));
    }
}
