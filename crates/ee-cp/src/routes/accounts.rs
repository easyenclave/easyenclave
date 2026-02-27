use axum::extract::{Path, State};
use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::Json;
use ee_common::api::{ApiErrorResponse, CreateAccountRequest, CreateAccountResponse};
use ee_common::types::AccountType;
use uuid::Uuid;

use crate::auth::admin_session::{
    token_prefix_from_raw as session_prefix_from_raw, verify_session_token,
};
use crate::auth::api_key::{issue_api_key, key_prefix_from_raw, verify_api_key};
use crate::state::AppState;
use crate::stores::account::AccountStore;
use crate::stores::session::SessionStore;

pub async fn create_account(
    State(state): State<AppState>,
    Json(payload): Json<CreateAccountRequest>,
) -> Result<Json<CreateAccountResponse>, (StatusCode, Json<ApiErrorResponse>)> {
    let account_type = parse_account_type(&payload.account_type).ok_or_else(|| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_account_type",
            "account_type must be deployer|agent|contributor|launcher|platform",
        )
    })?;

    let store = AccountStore::new(state.db_pool.clone());
    let issued_key = issue_api_key().map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "api_key_issue_failed",
            "failed to issue account api key",
        )
    })?;

    let account = store
        .create_with_api_key(
            &payload.name,
            account_type,
            Some(&issued_key.key_hash),
            Some(&issued_key.key_prefix),
            payload.github_login.as_deref(),
            payload.github_org.as_deref(),
        )
        .await
        .map_err(|e| {
            let text = e.to_string();
            if text.contains("UNIQUE") {
                error_response(
                    StatusCode::CONFLICT,
                    "account_conflict",
                    "account name or github owner mapping already exists",
                )
            } else {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "account_create_failed",
                    "failed to create account",
                )
            }
        })?;

    Ok(Json(CreateAccountResponse {
        account_id: account.account_id,
        api_key: issued_key.raw_key,
    }))
}

pub async fn list_accounts(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::stores::account::AccountRecord>>, StatusCode> {
    let token = bearer_token(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let token_prefix = session_prefix_from_raw(token).ok_or(StatusCode::UNAUTHORIZED)?;
    let sessions = SessionStore::new(state.db_pool.clone());
    let session = sessions
        .lookup_by_prefix(&token_prefix)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let verified =
        verify_session_token(&session.token_hash, token).map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !verified {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let store = AccountStore::new(state.db_pool.clone());
    let items = store
        .list()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(items))
}

pub async fn get_account(
    Path(account_id): Path<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<crate::stores::account::AccountRecord>, StatusCode> {
    let account_id = Uuid::parse_str(&account_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let store = AccountStore::new(state.db_pool.clone());

    let token = bearer_token(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let hash = store
        .api_hash_for_account(account_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let prefix = key_prefix_from_raw(token).ok_or(StatusCode::UNAUTHORIZED)?;
    let expected_prefix = store
        .lookup_api_hash_by_prefix(&prefix)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if expected_prefix.as_deref() != Some(hash.as_str()) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let verified = verify_api_key(&hash, token).map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !verified {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let maybe = store
        .get(account_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    match maybe {
        Some(account) => Ok(Json(account)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ")
}

fn parse_account_type(raw: &str) -> Option<AccountType> {
    match raw {
        "deployer" => Some(AccountType::Deployer),
        "agent" => Some(AccountType::Agent),
        "contributor" => Some(AccountType::Contributor),
        "launcher" => Some(AccountType::Launcher),
        "platform" => Some(AccountType::Platform),
        _ => None,
    }
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

    async fn test_app() -> axum::Router {
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
            Some("s3cret".to_string()),
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
    async fn create_and_get_account() {
        let app = test_app().await;

        let payload = json!({"name": "acct-alice", "account_type": "deployer"});
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/accounts")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("create response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: Value = serde_json::from_slice(&body).expect("json");
        let account_id = json["account_id"].as_str().expect("account_id");
        let api_key = json["api_key"].as_str().expect("api_key");
        assert!(api_key.starts_with("ee_live_"));

        let get_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/accounts/{account_id}"))
                    .header("authorization", format!("Bearer {api_key}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("get response");

        assert_eq!(get_response.status(), StatusCode::OK);

        let unauthorized_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/accounts/{account_id}"))
                    .header("authorization", "Bearer ee_live_badbadbadbad")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("unauthorized response");

        assert_eq!(unauthorized_response.status(), StatusCode::UNAUTHORIZED);

        let list_unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/accounts")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("list unauthorized");
        assert_eq!(list_unauthorized.status(), StatusCode::UNAUTHORIZED);

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
        let login_body = axum::body::to_bytes(login_response.into_body(), usize::MAX)
            .await
            .expect("login body");
        let login_json: Value = serde_json::from_slice(&login_body).expect("login json");
        let admin_token = login_json["token"].as_str().expect("admin token");

        let list_authorized = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/accounts")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("list authorized");
        assert_eq!(list_authorized.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn create_account_conflicts_on_duplicate_github_owner() {
        let app = test_app().await;

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/accounts")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "name": "acct-github-1",
                            "account_type": "deployer",
                            "github_org": "Example-Org"
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("first response");
        assert_eq!(first.status(), StatusCode::OK);

        let second = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/accounts")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "name": "acct-github-2",
                            "account_type": "deployer",
                            "github_org": "example-org"
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("second response");
        assert_eq!(second.status(), StatusCode::CONFLICT);
    }
}
