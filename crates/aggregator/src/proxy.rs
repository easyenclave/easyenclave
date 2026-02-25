//! Reverse proxy to healthy agents.
//!
//! Routes `/{app-name}/{path}` to a healthy agent running that app.

use crate::error::AggregatorError;
use crate::registry::AgentRegistry;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use ee_common::error::ApiError;
use std::sync::Arc;
use tracing::{debug, warn};

/// Proxy state shared with route handlers.
#[derive(Clone)]
pub struct ProxyState {
    pub registry: AgentRegistry,
    pub client: reqwest::Client,
}

/// Proxy handler: route to a healthy agent.
pub async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    Path((app_name, path)): Path<(String, String)>,
    req: Request<Body>,
) -> Result<Response, ApiError> {
    let agents = state.registry.all_agents().await;

    // Find an agent running this app
    let agent = agents
        .iter()
        .find(|a| {
            a.deployment
                .as_ref()
                .map(|d| d.app_name == app_name)
                .unwrap_or(false)
        })
        .ok_or_else(|| ApiError::not_found(format!("no agent found for app {app_name}")))?;

    // In a full implementation, we'd forward the request to the agent's URL.
    // For now, return a placeholder indicating where we'd route.
    debug!(
        app = %app_name,
        agent_id = %agent.id,
        "would proxy to agent"
    );

    Ok((
        StatusCode::BAD_GATEWAY,
        format!("proxy: would route {app_name}/{path} to agent {}", agent.id),
    )
        .into_response())
}
