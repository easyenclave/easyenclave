use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use ee_common::api::{AdminLoginRequest, AdminLoginResponse, ApiErrorResponse, AuthMeResponse};
use serde::Serialize;

use crate::auth::admin_session::{
    issue_session_token, token_prefix_from_raw, verify_session_token,
};
use crate::state::AppState;
use crate::stores::session::SessionStore;

pub async fn admin_login(
    State(state): State<AppState>,
    Json(payload): Json<AdminLoginRequest>,
) -> Result<Json<AdminLoginResponse>, (StatusCode, Json<ApiErrorResponse>)> {
    let expected = state.admin_password.as_deref().ok_or_else(|| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "admin_auth_unavailable",
            "admin password auth is not configured",
        )
    })?;

    if payload.password != expected {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "invalid admin credentials",
        ));
    }

    let issued = issue_session_token().map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "session_issue_failed",
            "failed to issue admin session token",
        )
    })?;

    let store = SessionStore::new(state.db_pool.clone());
    let session = store
        .create_password_session(&issued.token_hash, &issued.token_prefix)
        .await
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "session_store_failed",
                "failed to store admin session",
            )
        })?;

    Ok(Json(AdminLoginResponse {
        token: issued.raw_token,
        expires_at: session.expires_at,
    }))
}

pub async fn auth_me(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<AuthMeResponse>, StatusCode> {
    let token = bearer_token(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let token_prefix = token_prefix_from_raw(token).ok_or(StatusCode::UNAUTHORIZED)?;

    let store = SessionStore::new(state.db_pool.clone());
    let session = store
        .lookup_by_prefix(&token_prefix)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let verified =
        verify_session_token(&session.token_hash, token).map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !verified {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(Json(AuthMeResponse {
        auth_method: session.auth_method,
        github_login: session.github_login,
        expires_at: session.expires_at,
    }))
}

pub async fn admin_logout(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<StatusCode, StatusCode> {
    let token = bearer_token(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let token_prefix = token_prefix_from_raw(token).ok_or(StatusCode::UNAUTHORIZED)?;

    let store = SessionStore::new(state.db_pool.clone());
    let session = store
        .lookup_by_prefix(&token_prefix)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let verified =
        verify_session_token(&session.token_hash, token).map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !verified {
        return Err(StatusCode::UNAUTHORIZED);
    }

    store
        .delete_by_prefix(&token_prefix)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
pub struct AuthMethodsResponse {
    methods: Vec<&'static str>,
}

pub async fn auth_methods() -> Json<AuthMethodsResponse> {
    Json(AuthMethodsResponse {
        methods: vec!["password"],
    })
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ")
}

fn error_response(
    status: StatusCode,
    code: &str,
    message: &str,
) -> (StatusCode, Json<ApiErrorResponse>) {
    (
        status,
        Json(ApiErrorResponse {
            code: code.to_string(),
            message: message.to_string(),
            request_id: None,
        }),
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::{json, Value};
    use sqlx::sqlite::SqlitePoolOptions;
    use tower::ServiceExt;

    use crate::routes::build_router;
    use crate::services::attestation::AttestationService;
    use crate::services::github_oidc::GithubOidcService;
    use crate::services::nonce::NonceService;
    use crate::services::tunnel::TunnelService;
    use crate::state::AppState;
    use crate::stores::setting::SettingsStore;

    async fn test_app(admin_password: Option<&str>) -> axum::Router {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("pool");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrate");

        let settings = SettingsStore::new_with_ttl(pool.clone(), Duration::from_secs(5));
        let nonce = NonceService::new(Duration::from_secs(300));
        let attestation = AttestationService::insecure_for_tests();
        let github_oidc = GithubOidcService::disabled_for_tests();
        let tunnel = TunnelService::disabled_for_tests();
        let state = AppState::new(
            "boot-test".to_string(),
            None,
            admin_password.map(ToString::to_string),
            pool,
            settings,
            nonce,
            attestation,
            github_oidc,
            tunnel,
        );
        build_router(state)
    }

    #[tokio::test]
    async fn login_and_auth_me() {
        let app = test_app(Some("s3cret")).await;

        let login_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/login")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"password": "s3cret"}).to_string()))
                    .expect("request"),
            )
            .await
            .expect("login response");
        assert_eq!(login_response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(login_response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: Value = serde_json::from_slice(&body).expect("json");
        let token = json["token"].as_str().expect("token");

        let me_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/me")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("me response");

        assert_eq!(me_response.status(), StatusCode::OK);

        let logout_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/logout")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("logout response");
        assert_eq!(logout_response.status(), StatusCode::NO_CONTENT);

        let me_after_logout = app
            .oneshot(
                Request::builder()
                    .uri("/auth/me")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("me after logout");
        assert_eq!(me_after_logout.status(), StatusCode::UNAUTHORIZED);
    }
}
