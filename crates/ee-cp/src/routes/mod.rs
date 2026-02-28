pub mod accounts;
pub mod agents;
pub mod auth;
pub mod deploy;
pub mod health;
pub mod ui;

use axum::Router;

use crate::state::AppState;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", axum::routing::get(ui::root))
        .route("/health", axum::routing::get(health::health))
        .route(
            "/api/v1/agents/challenge",
            axum::routing::get(agents::challenge),
        )
        .route(
            "/api/v1/agents/register",
            axum::routing::post(agents::register),
        )
        .route("/api/v1/agents", axum::routing::get(agents::list))
        .route(
            "/api/v1/agents/{agent_id}",
            axum::routing::get(agents::get).delete(agents::delete),
        )
        .route(
            "/api/v1/agents/{agent_id}/reset",
            axum::routing::post(agents::reset),
        )
        .route("/api/v1/deploy", axum::routing::post(deploy::deploy))
        .route(
            "/api/v1/deployments",
            axum::routing::get(deploy::list_deployments),
        )
        .route(
            "/api/v1/deployments/{deployment_id}",
            axum::routing::get(deploy::get_deployment),
        )
        .route(
            "/api/v1/accounts",
            axum::routing::post(accounts::create_account),
        )
        .route(
            "/api/v1/accounts",
            axum::routing::get(accounts::list_accounts),
        )
        .route(
            "/api/v1/accounts/{account_id}",
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
