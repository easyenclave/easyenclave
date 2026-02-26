use ee_attestation::ita::ItaVerifier;
use ee_common::{
    api::RegisterRequest,
    error::{AppError, AppResult},
};

use crate::state::SharedState;

pub async fn verify_registration(
    state: &SharedState,
    request: &RegisterRequest,
) -> AppResult<String> {
    let nonce_ok = state.nonces.consume(&request.nonce);
    if !nonce_ok {
        return Err(AppError::Unauthorized(
            "invalid or expired nonce".to_owned(),
        ));
    }

    let verifier = ItaVerifier::new(state.config.ita_jwks_url.clone());
    let claims = verifier
        .verify_attestation_jwt(&request.attestation_jwt)
        .await?;

    if claims.mrtd != request.mrtd {
        return Err(AppError::Unauthorized(
            "ITA JWT MRTD does not match requested MRTD".to_owned(),
        ));
    }

    if claims.tcb_status != "UpToDate" {
        return Err(AppError::Unauthorized(format!(
            "TCB status {} is not allowed",
            claims.tcb_status
        )));
    }

    Ok(claims.mrtd)
}
