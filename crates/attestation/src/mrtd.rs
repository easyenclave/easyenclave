//! MRTD extraction and comparison.
//!
//! MRTD (Measurement of the Trust Domain) is a SHA-384 hash computed by TDX
//! at build time. It uniquely identifies a VM image configuration.

use crate::error::AttestationError;
use crate::ita::ItaClaims;

/// Extract the MRTD from verified ITA claims.
pub fn extract_mrtd(claims: &ItaClaims) -> Result<String, AttestationError> {
    claims
        .mrtd()
        .ok_or_else(|| AttestationError::MrtdExtraction("no tdx_mrtd in token claims".into()))
}

/// Check whether a given MRTD matches any in the trusted set.
pub fn is_trusted(mrtd: &str, trusted: &[String]) -> bool {
    trusted.iter().any(|t| t == mrtd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_trusted() {
        let trusted = vec!["abc123".to_string(), "def456".to_string()];
        assert!(is_trusted("abc123", &trusted));
        assert!(is_trusted("def456", &trusted));
        assert!(!is_trusted("unknown", &trusted));
        assert!(!is_trusted("", &trusted));
    }

    #[test]
    fn test_is_trusted_empty() {
        let trusted: Vec<String> = vec![];
        assert!(!is_trusted("abc123", &trusted));
    }
}
