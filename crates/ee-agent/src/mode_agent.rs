use std::sync::Arc;

use axum::Router;
use ee_common::{
    api::HeartbeatRequest,
    config::AgentConfig,
    error::{AppError, AppResult},
    types::HealthStatus,
};
use reqwest::Client;

use crate::{registration, server, tunnel};

pub async fn run(config: AgentConfig) -> AppResult<()> {
    let client = Client::new();
    let registration = registration::register_with_retry(&client, &config).await?;
    tunnel::start_cloudflared(&registration.tunnel_token).await?;

    let server_state = Arc::new(server::AgentHttpState::default());
    let router: Router = server::router(server_state);

    let cp_url = config.cp_url.clone();
    let heartbeat_agent_id = registration.agent_id.clone();
    let heartbeat_seconds = config.heartbeat_seconds;
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(heartbeat_seconds)).await;
            let payload = HeartbeatRequest {
                mrtd: "00".repeat(48),
                health_status: HealthStatus::Healthy,
                tcb_status: Some("UpToDate".to_owned()),
            };
            let _ = client
                .post(format!(
                    "{cp_url}/api/v1/agents/{heartbeat_agent_id}/heartbeat"
                ))
                .json(&payload)
                .send()
                .await;
        }
    });

    let addr = config
        .bind_addr
        .parse::<std::net::SocketAddr>()
        .map_err(|e| AppError::BadRequest(format!("invalid AGENT_BIND_ADDR: {e}")))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| AppError::Internal(format!("bind failed: {e}")))?;

    axum::serve(listener, router)
        .await
        .map_err(|e| AppError::Internal(format!("agent server failed: {e}")))
}
