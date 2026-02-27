use axum::extract::State;
use axum::Json;
use ee_common::api::HealthResponse;

use crate::state::AppState;

pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        boot_id: Some(state.boot_id.clone()),
        git_sha: state.git_sha.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sqlx::sqlite::SqlitePoolOptions;
    use tower::ServiceExt;

    use crate::routes::build_router;
    use crate::services::attestation::AttestationService;
    use crate::services::github_oidc::GithubOidcService;
    use crate::services::nonce::NonceService;
    use crate::services::tunnel::TunnelService;
    use crate::state::AppState;
    use crate::stores::setting::SettingsStore;

    #[tokio::test]
    async fn health_route_returns_200() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("pool");

        let settings = SettingsStore::new_with_ttl(pool.clone(), Duration::from_secs(5));
        let nonce = NonceService::new(Duration::from_secs(300));
        let attestation = AttestationService::insecure_for_tests();
        let github_oidc = GithubOidcService::disabled_for_tests();
        let tunnel = TunnelService::disabled_for_tests();
        let state = AppState::new(
            "boot-test".to_string(),
            Some("sha-test".to_string()),
            None,
            pool,
            settings,
            nonce,
            attestation,
            github_oidc,
            tunnel,
        );
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
    }
}
