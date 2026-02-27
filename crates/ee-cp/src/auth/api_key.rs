use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use ee_common::error::{AppError, AppResult};
use uuid::Uuid;

pub const API_KEY_PREFIX: &str = "ee_live_";
const API_KEY_VISIBLE_PREFIX_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedApiKey {
    pub raw_key: String,
    pub key_prefix: String,
    pub key_hash: String,
}

pub fn issue_api_key() -> AppResult<IssuedApiKey> {
    let suffix = Uuid::new_v4().simple().to_string();
    let raw_key = format!("{API_KEY_PREFIX}{suffix}");
    let key_prefix = raw_key.chars().take(API_KEY_VISIBLE_PREFIX_LEN).collect();
    let key_hash = hash_api_key(&raw_key)?;

    Ok(IssuedApiKey {
        raw_key,
        key_prefix,
        key_hash,
    })
}

pub fn key_prefix_from_raw(raw_key: &str) -> Option<String> {
    if raw_key.len() < API_KEY_VISIBLE_PREFIX_LEN {
        return None;
    }
    Some(raw_key.chars().take(API_KEY_VISIBLE_PREFIX_LEN).collect())
}

pub fn hash_api_key(raw_key: &str) -> AppResult<String> {
    validate_key_format(raw_key)?;

    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(raw_key.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| AppError::Internal)
}

pub fn verify_api_key(stored_hash: &str, candidate_key: &str) -> AppResult<bool> {
    validate_key_format(candidate_key)?;

    let parsed = PasswordHash::new(stored_hash)
        .map_err(|e| AppError::InvalidInput(format!("invalid stored api key hash: {e}")))?;

    Ok(Argon2::default()
        .verify_password(candidate_key.as_bytes(), &parsed)
        .is_ok())
}

fn validate_key_format(raw_key: &str) -> AppResult<()> {
    if !raw_key.starts_with(API_KEY_PREFIX) {
        return Err(AppError::InvalidInput(
            "api key must start with ee_live_".to_string(),
        ));
    }
    if raw_key.len() < API_KEY_PREFIX.len() + 8 {
        return Err(AppError::InvalidInput("api key is too short".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{issue_api_key, key_prefix_from_raw, verify_api_key, API_KEY_PREFIX};

    #[test]
    fn issues_prefixed_key_and_hash() {
        let issued = issue_api_key().expect("issue key");
        assert!(issued.raw_key.starts_with(API_KEY_PREFIX));
        assert!(issued.key_prefix.starts_with(API_KEY_PREFIX));
        assert!(!issued.key_hash.is_empty());
    }

    #[test]
    fn verifies_hash() {
        let issued = issue_api_key().expect("issue key");
        let ok = verify_api_key(&issued.key_hash, &issued.raw_key).expect("verify");
        assert!(ok);

        let bad = verify_api_key(&issued.key_hash, "ee_live_badbadbadbad").expect("verify bad");
        assert!(!bad);
    }

    #[test]
    fn extracts_visible_prefix() {
        let issued = issue_api_key().expect("issue key");
        let prefix = key_prefix_from_raw(&issued.raw_key).expect("prefix");
        assert_eq!(prefix, issued.key_prefix);
    }
}
