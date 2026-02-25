//! Reverse proxy to healthy agents.
//!
//! Routes `/{app-name}/{path}` to a healthy agent running that app.

use crate::registry::AgentRegistry;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, Request, StatusCode};
use axum::response::Response;
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

    let target_url = format!("{}/{path}", agent.url.trim_end_matches('/'),);
    debug!(
        app = %app_name,
        agent_id = %agent.id,
        %target_url,
        "proxying request to agent"
    );

    // Build the outgoing request, preserving method and headers
    let method = req.method().clone();
    let mut builder = state.client.request(method, &target_url);

    // Forward relevant headers
    for (name, value) in req.headers() {
        if name != header::HOST && name != header::TRANSFER_ENCODING {
            builder = builder.header(name, value);
        }
    }

    // Forward body
    let body_bytes = axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024)
        .await
        .map_err(|e| ApiError::internal(format!("read request body: {e}")))?;
    if !body_bytes.is_empty() {
        builder = builder.body(body_bytes.to_vec());
    }

    let resp = builder
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| {
            warn!(app = %app_name, ?e, "proxy request failed");
            ApiError::bad_gateway(format!("upstream error: {e}"))
        })?;

    // Convert reqwest response back to axum response
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut response_builder = axum::http::Response::builder().status(status);

    for (name, value) in resp.headers() {
        if name != header::TRANSFER_ENCODING {
            response_builder = response_builder.header(name, value);
        }
    }

    let resp_bytes = resp
        .bytes()
        .await
        .map_err(|e| ApiError::bad_gateway(format!("read upstream response: {e}")))?;

    response_builder
        .body(Body::from(resp_bytes))
        .map_err(|e| ApiError::internal(format!("build response: {e}")))
}
