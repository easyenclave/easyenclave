use ee_common::error::{AppError, AppResult};

#[derive(Debug, Clone)]
pub struct GithubIdentity {
    pub repository_owner: String,
    pub repository: Option<String>,
    pub subject: String,
}

pub fn verify_bearer(auth_header: &str) -> AppResult<GithubIdentity> {
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("missing Bearer token".to_owned()))?
        .trim();

    // Test-only shortcut for local and CI integration tests.
    if let Some(owner) = token.strip_prefix("test-owner:") {
        return Ok(GithubIdentity {
            repository_owner: owner.to_owned(),
            repository: Some(format!("{owner}/demo")),
            subject: "repo:test/demo".to_owned(),
        });
    }

    Err(AppError::Unauthorized(
        "GitHub OIDC verification for production JWTs is not yet implemented".to_owned(),
    ))
}
