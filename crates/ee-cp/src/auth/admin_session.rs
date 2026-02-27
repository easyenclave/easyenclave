use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use ee_common::error::{AppError, AppResult};
use uuid::Uuid;

pub const SESSION_TOKEN_PREFIX: &str = "ees_";
const SESSION_VISIBLE_PREFIX_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedSessionToken {
    pub raw_token: String,
    pub token_prefix: String,
    pub token_hash: String,
}

pub fn issue_session_token() -> AppResult<IssuedSessionToken> {
    let suffix = Uuid::new_v4().simple().to_string();
    let raw_token = format!("{SESSION_TOKEN_PREFIX}{suffix}");
    let token_prefix = raw_token.chars().take(SESSION_VISIBLE_PREFIX_LEN).collect();
    let token_hash = hash_session_token(&raw_token)?;

    Ok(IssuedSessionToken {
        raw_token,
        token_prefix,
        token_hash,
    })
}

pub fn hash_session_token(token: &str) -> AppResult<String> {
    validate_token_format(token)?;

    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(token.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| AppError::Internal)
}

pub fn verify_session_token(stored_hash: &str, candidate_token: &str) -> AppResult<bool> {
    validate_token_format(candidate_token)?;

    let parsed = PasswordHash::new(stored_hash)
        .map_err(|e| AppError::InvalidInput(format!("invalid stored session hash: {e}")))?;

    Ok(Argon2::default()
        .verify_password(candidate_token.as_bytes(), &parsed)
        .is_ok())
}

pub fn token_prefix_from_raw(token: &str) -> Option<String> {
    if token.len() < SESSION_VISIBLE_PREFIX_LEN {
        return None;
    }
    Some(token.chars().take(SESSION_VISIBLE_PREFIX_LEN).collect())
}

fn validate_token_format(token: &str) -> AppResult<()> {
    if !token.starts_with(SESSION_TOKEN_PREFIX) {
        return Err(AppError::InvalidInput(
            "session token must start with ees_".to_string(),
        ));
    }
    if token.len() < SESSION_TOKEN_PREFIX.len() + 8 {
        return Err(AppError::InvalidInput(
            "session token is too short".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        issue_session_token, token_prefix_from_raw, verify_session_token, SESSION_TOKEN_PREFIX,
    };

    #[test]
    fn issues_session_token() {
        let issued = issue_session_token().expect("issue token");
        assert!(issued.raw_token.starts_with(SESSION_TOKEN_PREFIX));
        assert!(issued.token_prefix.starts_with(SESSION_TOKEN_PREFIX));
        assert!(!issued.token_hash.is_empty());
    }

    #[test]
    fn verifies_session_token_hash() {
        let issued = issue_session_token().expect("issue token");
        assert!(verify_session_token(&issued.token_hash, &issued.raw_token).expect("verify"));
        assert!(!verify_session_token(&issued.token_hash, "ees_badbadbad").expect("verify bad"));
    }

    #[test]
    fn extracts_session_prefix() {
        let issued = issue_session_token().expect("issue token");
        let prefix = token_prefix_from_raw(&issued.raw_token).expect("prefix");
        assert_eq!(prefix, issued.token_prefix);
    }
}
