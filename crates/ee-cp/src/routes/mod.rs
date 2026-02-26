use axum::{
    routing::{get, post},
    Router,
};

use crate::{
    routes::{agents::*, apps::*, deploy::*, health::health},
    state::SharedState,
};

pub mod agents;
pub mod apps;
pub mod deploy;
pub mod health;

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/agents/challenge", get(challenge))
        .route("/api/v1/agents/register", post(register))
        .route("/api/v1/agents/{id}/heartbeat", post(heartbeat))
        .route("/api/v1/agents", get(list_agents))
        .route("/api/v1/agents/{id}", get(get_agent))
        .route("/api/v1/agents/{id}/logs", get(get_agent_logs))
        .route("/api/v1/agents/{id}/undeploy", post(undeploy_agent))
        .route("/api/v1/apps", post(publish_app).get(list_apps))
        .route("/api/v1/apps/{name}", get(get_app))
        .route("/api/v1/apps/{name}/versions", post(publish_app_version))
        .route("/api/v1/deploy", post(deploy_app))
        .with_state(state)
}
