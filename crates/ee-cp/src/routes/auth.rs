use std::collections::HashSet;
use std::env;

use axum::extract::{Query, State};
use axum::http::header::{AUTHORIZATION, COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect};
use axum::Json;
use ee_common::api::{AdminLoginRequest, AdminLoginResponse, ApiErrorResponse, AuthMeResponse};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::admin_session::{
    issue_session_token, token_prefix_from_raw, verify_session_token,
};
use crate::state::AppState;
use crate::stores::session::SessionStore;

const GITHUB_AUTHORIZE_URL: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const GITHUB_USER_URL: &str = "https://api.github.com/user";
const OAUTH_STATE_COOKIE: &str = "ee_gh_oauth_state";
const OAUTH_COOKIE_MAX_AGE_SECONDS: i64 = 300;

#[derive(Debug, Clone)]
struct GithubOauthConfig {
    client_id: Option<String>,
    client_secret: Option<String>,
    redirect_uri: Option<String>,
    admin_logins: HashSet<String>,
}

impl GithubOauthConfig {
    fn from_env() -> Self {
        let admin_logins = env::var("ADMIN_GITHUB_LOGINS")
            .ok()
            .map(|v| {
                v.split(',')
                    .map(|item| item.trim().to_ascii_lowercase())
                    .filter(|item| !item.is_empty())
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();
        Self {
            client_id: env::var("GITHUB_OAUTH_CLIENT_ID")
                .ok()
                .filter(|v| !v.trim().is_empty()),
            client_secret: env::var("GITHUB_OAUTH_CLIENT_SECRET")
                .ok()
                .filter(|v| !v.trim().is_empty()),
            redirect_uri: env::var("GITHUB_OAUTH_REDIRECT_URI")
                .ok()
                .filter(|v| !v.trim().is_empty()),
            admin_logins,
        }
    }

    fn enabled(&self) -> bool {
        self.client_id.is_some() && self.client_secret.is_some() && self.redirect_uri.is_some()
    }

    fn is_admin_login(&self, login: &str) -> bool {
        if self.admin_logins.is_empty() {
            return false;
        }
        self.admin_logins
            .contains(&login.trim().to_ascii_lowercase())
    }

    fn require_enabled(&self) -> Result<(), (StatusCode, Json<ApiErrorResponse>)> {
        if self.enabled() {
            Ok(())
        } else {
            Err(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "github_oauth_unavailable",
                "github oauth is not configured",
            ))
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AuthMethodsResponse {
    methods: Vec<&'static str>,
    password: bool,
    github: bool,
}

#[derive(Debug, Serialize)]
pub struct GithubOauthStartResponse {
    pub auth_url: String,
}

#[derive(Debug, Deserialize)]
pub struct GithubOauthCallbackQuery {
    pub code: String,
    pub state: String,
}

#[derive(Debug, Deserialize)]
struct GithubTokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GithubUserResponse {
    login: String,
}

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

pub async fn auth_methods(State(state): State<AppState>) -> Json<AuthMethodsResponse> {
    let oauth = GithubOauthConfig::from_env();
    let password_enabled = state
        .admin_password
        .as_deref()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    let github_enabled = oauth.enabled();

    let mut methods = Vec::new();
    if password_enabled {
        methods.push("password");
    }
    if github_enabled {
        methods.push("github");
    }

    Json(AuthMethodsResponse {
        methods,
        password: password_enabled,
        github: github_enabled,
    })
}

pub async fn github_oauth_start() -> Result<impl IntoResponse, (StatusCode, Json<ApiErrorResponse>)>
{
    let oauth = GithubOauthConfig::from_env();
    oauth.require_enabled()?;

    let state = format!("gh_{}", Uuid::new_v4().simple());
    let mut auth_url = reqwest::Url::parse(GITHUB_AUTHORIZE_URL).map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "github_oauth_url_invalid",
            "failed to build github oauth url",
        )
    })?;
    auth_url
        .query_pairs_mut()
        .append_pair(
            "client_id",
            oauth
                .client_id
                .as_deref()
                .expect("github oauth enabled must include client id"),
        )
        .append_pair(
            "redirect_uri",
            oauth.redirect_uri.as_deref().expect("redirect uri"),
        )
        .append_pair("scope", "read:user user:email read:org")
        .append_pair("state", &state);

    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&oauth_state_cookie(&state)).map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "cookie_error",
                "failed to set oauth state cookie",
            )
        })?,
    );

    Ok((
        headers,
        Json(GithubOauthStartResponse {
            auth_url: auth_url.to_string(),
        }),
    ))
}

pub async fn github_oauth_callback(
    Query(query): Query<GithubOauthCallbackQuery>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiErrorResponse>)> {
    let oauth = GithubOauthConfig::from_env();
    oauth.require_enabled()?;

    let cookie_state = cookie_value(&headers, OAUTH_STATE_COOKIE).ok_or_else(|| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_oauth_state",
            "missing oauth state cookie",
        )
    })?;
    if cookie_state != query.state {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_oauth_state",
            "oauth state validation failed",
        ));
    }

    let client = reqwest::Client::new();
    let token_response = client
        .post(GITHUB_TOKEN_URL)
        .header("Accept", "application/json")
        .header("User-Agent", "easyenclave-ee-cp")
        .form(&[
            (
                "client_id",
                oauth.client_id.as_deref().expect("client id").to_string(),
            ),
            (
                "client_secret",
                oauth
                    .client_secret
                    .as_deref()
                    .expect("client secret")
                    .to_string(),
            ),
            ("code", query.code),
            (
                "redirect_uri",
                oauth
                    .redirect_uri
                    .as_deref()
                    .expect("redirect uri")
                    .to_string(),
            ),
            ("state", query.state),
        ])
        .send()
        .await
        .map_err(|_| {
            error_response(
                StatusCode::BAD_GATEWAY,
                "github_oauth_exchange_failed",
                "failed to exchange github oauth code",
            )
        })?;

    let token_status = token_response.status();
    let token_body: GithubTokenResponse = token_response.json().await.map_err(|_| {
        error_response(
            StatusCode::BAD_GATEWAY,
            "github_oauth_exchange_failed",
            "invalid github oauth token response",
        )
    })?;
    if !token_status.is_success() {
        return Err(error_response(
            StatusCode::BAD_GATEWAY,
            "github_oauth_exchange_failed",
            token_body
                .error_description
                .as_deref()
                .unwrap_or("github oauth rejected"),
        ));
    }
    if let Some(err) = token_body.error.as_deref() {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "github_oauth_exchange_failed",
            err,
        ));
    }
    let access_token = token_body.access_token.ok_or_else(|| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "github_oauth_exchange_failed",
            "github oauth did not return an access token",
        )
    })?;

    let user_response = client
        .get(GITHUB_USER_URL)
        .header("Accept", "application/json")
        .header("User-Agent", "easyenclave-ee-cp")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|_| {
            error_response(
                StatusCode::BAD_GATEWAY,
                "github_user_lookup_failed",
                "failed to fetch github user profile",
            )
        })?;
    if !user_response.status().is_success() {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "github_user_lookup_failed",
            "github user lookup failed",
        ));
    }

    let user: GithubUserResponse = user_response.json().await.map_err(|_| {
        error_response(
            StatusCode::BAD_GATEWAY,
            "github_user_lookup_failed",
            "invalid github user response",
        )
    })?;
    if user.login.trim().is_empty() {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "github_user_lookup_failed",
            "github user login is empty",
        ));
    }

    if !oauth.is_admin_login(&user.login) {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "github_admin_forbidden",
            "github login is not authorized for admin access",
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
    store
        .create_github_session(&issued.token_hash, &issued.token_prefix, &user.login)
        .await
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "session_store_failed",
                "failed to store admin session",
            )
        })?;

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&clear_oauth_state_cookie()).map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "cookie_error",
                "failed to clear oauth state cookie",
            )
        })?,
    );
    Ok((
        response_headers,
        Redirect::to(&format!("/?token={}", issued.raw_token)),
    ))
}

fn oauth_state_cookie(state: &str) -> String {
    format!(
        "{OAUTH_STATE_COOKIE}={state}; Max-Age={OAUTH_COOKIE_MAX_AGE_SECONDS}; Path=/; HttpOnly; Secure; SameSite=Lax"
    )
}

fn clear_oauth_state_cookie() -> String {
    format!("{OAUTH_STATE_COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax")
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let trimmed = part.trim();
        if let Some((cookie_name, cookie_value)) = trimmed.split_once('=') {
            if cookie_name == name {
                return Some(cookie_value.to_string());
            }
        }
    }
    None
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

    #[tokio::test]
    async fn auth_methods_reflect_password_config() {
        let app_with_password = test_app(Some("s3cret")).await;
        let with_password = app_with_password
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/methods")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("methods with password");
        assert_eq!(with_password.status(), StatusCode::OK);
        let with_password_body = axum::body::to_bytes(with_password.into_body(), usize::MAX)
            .await
            .expect("body");
        let with_password_json: Value = serde_json::from_slice(&with_password_body).expect("json");
        assert_eq!(with_password_json["password"].as_bool(), Some(true));

        let app_without_password = test_app(None).await;
        let without_password = app_without_password
            .oneshot(
                Request::builder()
                    .uri("/auth/methods")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("methods without password");
        assert_eq!(without_password.status(), StatusCode::OK);
        let without_password_body = axum::body::to_bytes(without_password.into_body(), usize::MAX)
            .await
            .expect("body");
        let without_password_json: Value =
            serde_json::from_slice(&without_password_body).expect("json");
        assert_eq!(without_password_json["password"].as_bool(), Some(false));
    }
}
