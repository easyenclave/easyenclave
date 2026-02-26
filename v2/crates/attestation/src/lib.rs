use anyhow::{anyhow, Result};
use ee_common::{api::AttestationEvidence, now_epoch_seconds};
use std::collections::HashSet;

pub fn parse_trusted_mrtds(value: &str) -> HashSet<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub fn generate_mock_attestation(agent_id: &str) -> AttestationEvidence {
    let ts = now_epoch_seconds();
    AttestationEvidence {
        quote: format!("mock-quote-{agent_id}-{ts}"),
        token: format!("mock-token-{agent_id}-{ts}"),
        mrtd: format!("mock-mrtd-{agent_id}"),
        generated_at: ts,
    }
}

pub fn verify_attestation(
    evidence: &AttestationEvidence,
    trusted_mrtds: &HashSet<String>,
) -> Result<()> {
    if evidence.quote.is_empty() || evidence.token.is_empty() {
        return Err(anyhow!("attestation evidence is missing quote or token"));
    }
    if !trusted_mrtds.is_empty() && !trusted_mrtds.contains(&evidence.mrtd) {
        return Err(anyhow!("mrtd '{}' is not trusted", evidence.mrtd));
    }
    Ok(())
}
