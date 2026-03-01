pub mod accounts;
pub mod agents;
pub mod auth;
pub mod deploy;
pub mod health;
pub mod stats;
pub mod ui;

use axum::Router;

use crate::state::AppState;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", axum::routing::get(ui::root))
        .route("/health", axum::routing::get(health::health))
        .route(
            "/api/agents/challenge",
            axum::routing::get(agents::challenge),
        )
        .route(
            "/api/agents/register",
            axum::routing::post(agents::register),
        )
        .route("/api/agents", axum::routing::get(agents::list))
        .route(
            "/api/agents/{agent_id}",
            axum::routing::get(agents::get).delete(agents::delete),
        )
        .route(
            "/api/agents/{agent_id}/reset",
            axum::routing::post(agents::reset),
        )
        .route(
            "/api/agents/{agent_id}/checks",
            axum::routing::post(agents::ingest_check),
        )
        .route("/api/deploy", axum::routing::post(deploy::deploy))
        .route(
            "/api/deployments",
            axum::routing::get(deploy::list_deployments),
        )
        .route(
            "/api/deployments/{deployment_id}",
            axum::routing::get(deploy::get_deployment),
        )
        .route(
            "/api/stats/apps/recent",
            axum::routing::get(stats::recent_app_stats),
        )
        .route(
            "/api/stats/agents/recent",
            axum::routing::get(stats::recent_agent_stats),
        )
        .route(
            "/api/accounts",
            axum::routing::post(accounts::create_account),
        )
        .route("/api/accounts", axum::routing::get(accounts::list_accounts))
        .route(
            "/api/accounts/{account_id}",
            axum::routing::get(accounts::get_account),
        )
        .route("/admin/login", axum::routing::post(auth::admin_login))
        .route("/admin/logout", axum::routing::post(auth::admin_logout))
        .route("/auth/methods", axum::routing::get(auth::auth_methods))
        .route("/auth/github", axum::routing::get(auth::github_oauth_start))
        .route(
            "/auth/github/callback",
            axum::routing::get(auth::github_oauth_callback),
        )
        .route("/auth/me", axum::routing::get(auth::auth_me))
        .with_state(state)
}
