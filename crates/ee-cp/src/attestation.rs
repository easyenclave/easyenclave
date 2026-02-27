use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ee_attestation::{ita::ItaVerifier, tsm::parse_quote_blob};
use ee_common::{
    api::RegisterRequest,
    error::{AppError, AppResult},
};

use crate::state::SharedState;

pub async fn verify_registration(
    state: &SharedState,
    request: &RegisterRequest,
) -> AppResult<String> {
    let quote_bytes = B64
        .decode(&request.quote_b64)
        .map_err(|e| AppError::BadRequest(format!("invalid quote_b64 payload: {e}")))?;

    let parsed = parse_quote_blob(&quote_bytes)?;

    if parsed.nonce_hex != request.nonce {
        return Err(AppError::Unauthorized(
            "quote report_data nonce does not match challenge nonce".to_owned(),
        ));
    }

    let nonce_ok = state.nonces.consume(&request.nonce);
    if !nonce_ok {
        return Err(AppError::Unauthorized(
            "invalid or expired nonce".to_owned(),
        ));
    }

    let verifier = ItaVerifier::new(
        state.config.ita_appraisal_url.clone(),
        state.config.ita_api_key.clone(),
        state.config.allow_insecure_test_attestation,
    );
    let claims = verifier
        .appraise_quote(&request.quote_b64, &parsed.mrtd_hex)
        .await?;

    if claims.mrtd != parsed.mrtd_hex {
        return Err(AppError::Unauthorized(
            "ITA appraisal MRTD does not match quote MRTD".to_owned(),
        ));
    }

    if claims.tcb_status != "UpToDate" {
        return Err(AppError::Unauthorized(format!(
            "TCB status {} is not allowed",
            claims.tcb_status
        )));
    }

    Ok(parsed.mrtd_hex)
}
