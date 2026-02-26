pub mod attestation;
pub mod background;
pub mod db;
pub mod github_oidc;
pub mod mrtd;
pub mod nonce;
pub mod ownership;
pub mod routes;
pub mod state;
pub mod tunnel;

use std::{net::SocketAddr, sync::Arc};

use axum::Router;
use ee_common::{config::CpConfig, error::AppResult};
use state::AppState;

pub async fn app_from_config(config: CpConfig) -> AppResult<Router> {
    let state = Arc::new(AppState::new(config)?);
    background::spawn(state.clone());
    Ok(routes::router(state))
}

pub async fn serve(config: CpConfig) -> AppResult<()> {
    let app = app_from_config(config.clone()).await?;
    let addr: SocketAddr = config.bind_addr.parse().map_err(|e| {
        ee_common::error::AppError::BadRequest(format!("invalid CP_BIND_ADDR: {e}"))
    })?;

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| ee_common::error::AppError::Internal(format!("bind failed: {e}")))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| ee_common::error::AppError::Internal(format!("server error: {e}")))
}
