use std::env;
use std::sync::Arc;
use std::time::Duration;

use ee_attestation::ita::ItaVerifier;
use ee_common::error::{AppError, AppResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    pub mrtd: Option<String>,
    pub tcb_status: Option<String>,
}

#[derive(Clone)]
pub struct AttestationService {
    verifier: Option<Arc<ItaVerifier>>,
    allow_insecure: bool,
    runtime_env: RuntimeEnv,
}

impl AttestationService {
    pub fn from_env() -> Self {
        let runtime_env = RuntimeEnv::from_env();
        let allow_insecure = env_bool("CP_ATTESTATION_ALLOW_INSECURE", false);
        let jwks_url = env::var("CP_ITA_JWKS_URL").ok();
        let issuer = env::var("CP_ITA_ISSUER").ok();
        let audience = env::var("CP_ITA_AUDIENCE").ok();

        let verifier =
            if let (Some(jwks_url), Some(issuer), Some(audience)) = (jwks_url, issuer, audience) {
                let ttl_seconds = env::var("CP_ITA_JWKS_TTL_SECONDS")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(300);
                Some(Arc::new(ItaVerifier::new(
                    jwks_url,
                    issuer,
                    audience,
                    Duration::from_secs(ttl_seconds),
                )))
            } else {
                None
            };

        Self {
            verifier,
            allow_insecure,
            runtime_env,
        }
    }

    pub fn insecure_for_tests() -> Self {
        Self {
            verifier: None,
            allow_insecure: true,
            runtime_env: RuntimeEnv::Local,
        }
    }

    pub fn validate_runtime_requirements(&self) -> AppResult<()> {
        if self.runtime_env.is_protected() && self.allow_insecure {
            return Err(AppError::Config(
                "CP_ATTESTATION_ALLOW_INSECURE must not be enabled in staging/production"
                    .to_string(),
            ));
        }
        if self.runtime_env.is_protected() && self.verifier.is_none() {
            return Err(AppError::Config(
                "attestation verifier is required in staging/production; set CP_ITA_JWKS_URL, CP_ITA_ISSUER, and CP_ITA_AUDIENCE".to_string(),
            ));
        }
        Ok(())
    }

    pub fn verify_registration_token(&self, token: &str) -> AppResult<VerifiedAttestation> {
        if token.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "intel_ta_token is required".to_string(),
            ));
        }

        if let Some(verifier) = &self.verifier {
            let claims = verifier.verify_attestation_token(token)?;
            return Ok(VerifiedAttestation {
                mrtd: claims.tdx_mrtd,
                tcb_status: claims.attester_tcb_status,
            });
        }

        if self.allow_insecure {
            return Ok(VerifiedAttestation {
                mrtd: None,
                tcb_status: None,
            });
        }

        Err(AppError::Config(
            "attestation verifier is not configured (set CP_ITA_JWKS_URL, CP_ITA_ISSUER, CP_ITA_AUDIENCE or enable CP_ATTESTATION_ALLOW_INSECURE=true for local testing)".to_string(),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeEnv {
    Local,
    Staging,
    Production,
}

impl RuntimeEnv {
    fn from_env() -> Self {
        let value = env::var("EASYENCLAVE_ENV")
            .or_else(|_| env::var("CP_ENV"))
            .unwrap_or_else(|_| "local".to_string())
            .to_ascii_lowercase();
        match value.as_str() {
            "staging" => Self::Staging,
            "production" | "prod" => Self::Production,
            _ => Self::Local,
        }
    }

    fn is_protected(self) -> bool {
        matches!(self, Self::Staging | Self::Production)
    }
}

fn env_bool(key: &str, default: bool) -> bool {
    env::var(key)
        .ok()
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::sync::Mutex;

    use ee_common::error::AppError;

    use super::AttestationService;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn insecure_mode_allows_placeholder_tokens() {
        let svc = AttestationService::insecure_for_tests();
        let verified = svc
            .verify_registration_token("fake.jwt.token")
            .expect("verify");
        assert!(verified.mrtd.is_none());
    }

    #[test]
    fn staging_rejects_insecure_mode() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let old_env = env::var("EASYENCLAVE_ENV").ok();
        let old_allow = env::var("CP_ATTESTATION_ALLOW_INSECURE").ok();
        let old_jwks = env::var("CP_ITA_JWKS_URL").ok();
        let old_issuer = env::var("CP_ITA_ISSUER").ok();
        let old_audience = env::var("CP_ITA_AUDIENCE").ok();

        env::set_var("EASYENCLAVE_ENV", "staging");
        env::set_var("CP_ATTESTATION_ALLOW_INSECURE", "true");
        env::remove_var("CP_ITA_JWKS_URL");
        env::remove_var("CP_ITA_ISSUER");
        env::remove_var("CP_ITA_AUDIENCE");

        let svc = AttestationService::from_env();
        let err = svc
            .validate_runtime_requirements()
            .expect_err("should reject insecure");
        match err {
            AppError::Config(message) => assert!(message.contains("must not be enabled")),
            other => panic!("expected config error, got {other}"),
        }

        restore("EASYENCLAVE_ENV", old_env);
        restore("CP_ATTESTATION_ALLOW_INSECURE", old_allow);
        restore("CP_ITA_JWKS_URL", old_jwks);
        restore("CP_ITA_ISSUER", old_issuer);
        restore("CP_ITA_AUDIENCE", old_audience);
    }

    #[test]
    fn production_requires_verifier() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let old_env = env::var("EASYENCLAVE_ENV").ok();
        let old_allow = env::var("CP_ATTESTATION_ALLOW_INSECURE").ok();
        let old_jwks = env::var("CP_ITA_JWKS_URL").ok();
        let old_issuer = env::var("CP_ITA_ISSUER").ok();
        let old_audience = env::var("CP_ITA_AUDIENCE").ok();

        env::set_var("EASYENCLAVE_ENV", "production");
        env::set_var("CP_ATTESTATION_ALLOW_INSECURE", "false");
        env::remove_var("CP_ITA_JWKS_URL");
        env::remove_var("CP_ITA_ISSUER");
        env::remove_var("CP_ITA_AUDIENCE");

        let svc = AttestationService::from_env();
        let err = svc
            .validate_runtime_requirements()
            .expect_err("should require verifier");
        match err {
            AppError::Config(message) => {
                assert!(message.contains("attestation verifier is required"))
            }
            other => panic!("expected config error, got {other}"),
        }

        restore("EASYENCLAVE_ENV", old_env);
        restore("CP_ATTESTATION_ALLOW_INSECURE", old_allow);
        restore("CP_ITA_JWKS_URL", old_jwks);
        restore("CP_ITA_ISSUER", old_issuer);
        restore("CP_ITA_AUDIENCE", old_audience);
    }

    fn restore(key: &str, value: Option<String>) {
        if let Some(value) = value {
            env::set_var(key, value);
        } else {
            env::remove_var(key);
        }
    }
}
