use axum::extract::{Path, State};
use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::Json;
use ee_common::api::{
    AgentChallengeResponse, AgentRegisterRequest, AgentRegisterResponse, ApiErrorResponse,
};
use ee_common::types::AgentStatus;

use crate::services::nonce::ConsumeResult;
use crate::state::AppState;
use crate::stores::account::AccountStore;
use crate::stores::agent::AgentStore;
use crate::{auth::api_key::key_prefix_from_raw, auth::api_key::verify_api_key};
use uuid::Uuid;

pub async fn challenge(State(state): State<AppState>) -> Json<AgentChallengeResponse> {
    let nonce = state.nonce.issue();
    Json(AgentChallengeResponse {
        nonce,
        expires_in_seconds: state.nonce.ttl_seconds(),
    })
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<AgentRegisterRequest>,
) -> Result<Json<AgentRegisterResponse>, (StatusCode, Json<ApiErrorResponse>)> {
    if payload.intel_ta_token.trim().is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_attestation",
            "intel_ta_token is required",
        ));
    }

    match state.nonce.consume(&payload.nonce) {
        ConsumeResult::Ok => {}
        ConsumeResult::Missing | ConsumeResult::Expired => {
            return Err(error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_nonce",
                "nonce is missing, expired, or already consumed",
            ));
        }
    }

    let _verified = state
        .attestation
        .verify_registration_token(&payload.intel_ta_token)
        .map_err(|_| {
            error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_attestation",
                "attestation verification failed",
            )
        })?;

    let store = AgentStore::new(state.db_pool.clone());
    let created = store
        .create(
            &payload.vm_name,
            AgentStatus::Undeployed,
            payload.node_size.as_deref(),
            payload.datacenter.as_deref(),
            None,
        )
        .await
        .map_err(|e| {
            let text = e.to_string();
            if text.contains("UNIQUE") {
                error_response(
                    StatusCode::CONFLICT,
                    "vm_name_conflict",
                    "vm_name already registered",
                )
            } else {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "registration_failed",
                    "failed to persist agent",
                )
            }
        })?;

    let tunnel = match state
        .tunnel
        .create_tunnel_for_agent(created.agent_id, Some(&payload.vm_name))
        .await
    {
        Ok(tunnel) => tunnel,
        Err(_) => {
            let _ = store.delete(created.agent_id).await;
            return Err(error_response(
                StatusCode::BAD_GATEWAY,
                "tunnel_provision_failed",
                "failed to provision Cloudflare tunnel",
            ));
        }
    };
    if store
        .set_tunnel(
            created.agent_id,
            &tunnel.tunnel_id,
            &tunnel.hostname,
            &tunnel.tunnel_token,
        )
        .await
        .is_err()
    {
        let _ = state
            .tunnel
            .delete_tunnel_for_agent(&tunnel.tunnel_id, &tunnel.hostname)
            .await;
        let _ = store.delete(created.agent_id).await;
        return Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "registration_failed",
            "failed to persist agent tunnel data",
        ));
    }

    Ok(Json(AgentRegisterResponse {
        agent_id: created.agent_id,
        tunnel_token: tunnel.tunnel_token,
        hostname: tunnel.hostname,
    }))
}

pub async fn list(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::stores::agent::AgentRecord>>, StatusCode> {
    let store = AgentStore::new(state.db_pool.clone());
    let items = store
        .list(None)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(items))
}

pub async fn get(
    Path(agent_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<crate::stores::agent::AgentRecord>, StatusCode> {
    let agent_id = Uuid::parse_str(&agent_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let store = AgentStore::new(state.db_pool.clone());
    let maybe = store
        .get(agent_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    match maybe {
        Some(agent) => Ok(Json(agent)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

pub async fn reset(
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<StatusCode, (StatusCode, Json<ApiErrorResponse>)> {
    let agent_id = Uuid::parse_str(&agent_id).map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_agent_id",
            "invalid agent id",
        )
    })?;
    let owner = authenticate_owner_account(&headers, &state).await?;

    let store = AgentStore::new(state.db_pool.clone());
    let maybe = store.get(agent_id).await.map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "store_error",
            "failed to read agent",
        )
    })?;
    let agent = maybe.ok_or_else(|| {
        error_response(StatusCode::NOT_FOUND, "agent_not_found", "agent not found")
    })?;

    if agent.account_id != Some(owner.account_id) {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "agent is owned by a different account",
        ));
    }

    store
        .update_status(agent_id, AgentStatus::Undeployed)
        .await
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_error",
                "failed to reset agent",
            )
        })?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete(
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<StatusCode, (StatusCode, Json<ApiErrorResponse>)> {
    let agent_id = Uuid::parse_str(&agent_id).map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_agent_id",
            "invalid agent id",
        )
    })?;
    let owner = authenticate_owner_account(&headers, &state).await?;

    let store = AgentStore::new(state.db_pool.clone());
    let maybe = store.get(agent_id).await.map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "store_error",
            "failed to read agent",
        )
    })?;
    let agent = maybe.ok_or_else(|| {
        error_response(StatusCode::NOT_FOUND, "agent_not_found", "agent not found")
    })?;

    if agent.account_id != Some(owner.account_id) {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "agent is owned by a different account",
        ));
    }

    if let Some(tunnel) = store.tunnel_info(agent_id).await.map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "store_error",
            "failed to read agent tunnel info",
        )
    })? {
        state
            .tunnel
            .delete_tunnel_for_agent(&tunnel.tunnel_id, &tunnel.hostname)
            .await
            .map_err(|_| {
                error_response(
                    StatusCode::BAD_GATEWAY,
                    "tunnel_cleanup_failed",
                    "failed to clean up Cloudflare tunnel",
                )
            })?;
    }

    store.delete(agent_id).await.map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "store_error",
            "failed to delete agent",
        )
    })?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Clone)]
struct AuthenticatedOwner {
    account_id: Uuid,
}

async fn authenticate_owner_account(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<AuthenticatedOwner, (StatusCode, Json<ApiErrorResponse>)> {
    let token = bearer_token(headers).ok_or_else(|| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "missing_auth",
            "bearer token is required",
        )
    })?;

    let accounts = AccountStore::new(state.db_pool.clone());

    if token_is_jwt(token) && state.github_oidc.is_enabled() {
        let identity = state.github_oidc.verify_owner_token(token).map_err(|_| {
            error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_github_oidc",
                "invalid GitHub Actions OIDC token",
            )
        })?;
        let account_id = accounts
            .lookup_account_id_by_github_owner(&identity.owner)
            .await
            .map_err(|_| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "auth_lookup_failed",
                    "failed to resolve GitHub owner",
                )
            })?
            .ok_or_else(|| {
                error_response(
                    StatusCode::UNAUTHORIZED,
                    "unknown_github_owner",
                    "GitHub owner is not linked to an account",
                )
            })?;
        return Ok(AuthenticatedOwner { account_id });
    }

    let key_prefix = key_prefix_from_raw(token).ok_or_else(|| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_api_key",
            "invalid api key format",
        )
    })?;
    let (account_id, hash) = accounts
        .lookup_account_auth_by_prefix(&key_prefix)
        .await
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "auth_lookup_failed",
                "failed to validate api key",
            )
        })?
        .ok_or_else(|| {
            error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_api_key",
                "unknown api key",
            )
        })?;
    let verified = verify_api_key(&hash, token).map_err(|_| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_api_key",
            "invalid api key",
        )
    })?;
    if !verified {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_api_key",
            "invalid api key",
        ));
    }

    Ok(AuthenticatedOwner { account_id })
}

fn token_is_jwt(token: &str) -> bool {
    token.split('.').count() == 3
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
            None,
            pool,
            settings,
            nonce,
            attestation,
            github_oidc,
            tunnel,
        );
        build_router(state)
    }

    async fn create_account(app: &axum::Router, name: &str) -> String {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/accounts")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"name": name, "account_type": "deployer"}).to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("account response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let payload: Value = serde_json::from_slice(&body).expect("json");
        payload["api_key"].as_str().expect("api key").to_string()
    }

    async fn register_agent(app: &axum::Router, vm_name: &str) -> String {
        let challenge = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/challenge")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("challenge");
        let challenge_body = axum::body::to_bytes(challenge.into_body(), usize::MAX)
            .await
            .expect("challenge body");
        let challenge_json: Value = serde_json::from_slice(&challenge_body).expect("json");
        let nonce = challenge_json["nonce"].as_str().expect("nonce").to_string();

        let register_payload = json!({
            "intel_ta_token": "fake.jwt.token",
            "vm_name": vm_name,
            "nonce": nonce,
            "node_size": "standard",
            "datacenter": "gcp:us-central1-a"
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agents/register")
                    .header("content-type", "application/json")
                    .body(Body::from(register_payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("register response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let payload: Value = serde_json::from_slice(&body).expect("json");
        payload["agent_id"].as_str().expect("agent id").to_string()
    }

    #[tokio::test]
    async fn challenge_returns_nonce() {
        let app = test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/challenge")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let payload: Value = serde_json::from_slice(&body).expect("json");

        let nonce = payload["nonce"].as_str().expect("nonce str");
        let ttl = payload["expires_in_seconds"].as_u64().expect("ttl");
        assert!(!nonce.is_empty());
        assert_eq!(ttl, 300);
    }

    #[tokio::test]
    async fn register_consumes_nonce() {
        let app = test_app().await;

        let challenge_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/challenge")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("challenge response");
        let challenge_body = axum::body::to_bytes(challenge_response.into_body(), usize::MAX)
            .await
            .expect("challenge body");
        let challenge_payload: Value =
            serde_json::from_slice(&challenge_body).expect("challenge json");
        let nonce = challenge_payload["nonce"]
            .as_str()
            .expect("nonce str")
            .to_string();

        let register_payload = json!({
            "intel_ta_token": "fake.jwt.token",
            "vm_name": "tdx-agent-001",
            "nonce": nonce,
            "node_size": "standard",
            "datacenter": "gcp:us-central1-a",
            "github_owner": "example-org"
        });

        let register_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agents/register")
                    .header("content-type", "application/json")
                    .body(Body::from(register_payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("register response");

        assert_eq!(register_response.status(), StatusCode::OK);

        let reuse_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agents/register")
                    .header("content-type", "application/json")
                    .body(Body::from(register_payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("reuse response");

        assert_eq!(reuse_response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_and_get_agents() {
        let app = test_app().await;

        let challenge_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/challenge")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("challenge response");
        let challenge_body = axum::body::to_bytes(challenge_response.into_body(), usize::MAX)
            .await
            .expect("challenge body");
        let challenge_payload: Value =
            serde_json::from_slice(&challenge_body).expect("challenge json");
        let nonce = challenge_payload["nonce"]
            .as_str()
            .expect("nonce str")
            .to_string();

        let register_payload = json!({
            "intel_ta_token": "fake.jwt.token",
            "vm_name": "tdx-agent-002",
            "nonce": nonce,
            "node_size": "standard",
            "datacenter": "gcp:us-central1-a"
        });

        let register_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agents/register")
                    .header("content-type", "application/json")
                    .body(Body::from(register_payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("register response");
        assert_eq!(register_response.status(), StatusCode::OK);
        let register_body = axum::body::to_bytes(register_response.into_body(), usize::MAX)
            .await
            .expect("register body");
        let register_json: Value = serde_json::from_slice(&register_body).expect("register json");
        let agent_id = register_json["agent_id"].as_str().expect("agent_id");

        let list_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("list response");
        assert_eq!(list_response.status(), StatusCode::OK);

        let get_response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/agents/{agent_id}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("get response");
        assert_eq!(get_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn reset_requires_owner_account() {
        let app = test_app().await;
        let owner_key = create_account(&app, "owner-acct").await;
        let other_key = create_account(&app, "other-acct").await;
        let agent_id = register_agent(&app, "tdx-agent-reset-owner").await;

        let deploy_payload = json!({
            "compose": "services: {}",
            "agent_name": "tdx-agent-reset-owner",
            "dry_run": true
        });
        let deploy_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/deploy")
                    .header("authorization", format!("Bearer {owner_key}"))
                    .header("content-type", "application/json")
                    .body(Body::from(deploy_payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("deploy");
        assert_eq!(deploy_response.status(), StatusCode::OK);

        let forbidden = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/agents/{agent_id}/reset"))
                    .header("authorization", format!("Bearer {other_key}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("forbidden");
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let ok = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/agents/{agent_id}/reset"))
                    .header("authorization", format!("Bearer {owner_key}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("ok");
        assert_eq!(ok.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn delete_allows_owner_and_removes_agent() {
        let app = test_app().await;
        let owner_key = create_account(&app, "owner-acct-delete").await;
        let agent_id = register_agent(&app, "tdx-agent-delete-owner").await;

        let deploy_payload = json!({
            "compose": "services: {}",
            "agent_name": "tdx-agent-delete-owner",
            "dry_run": true
        });
        let deploy_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/deploy")
                    .header("authorization", format!("Bearer {owner_key}"))
                    .header("content-type", "application/json")
                    .body(Body::from(deploy_payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("deploy");
        assert_eq!(deploy_response.status(), StatusCode::OK);

        let delete_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/v1/agents/{agent_id}"))
                    .header("authorization", format!("Bearer {owner_key}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("delete");
        assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

        let get_after_delete = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/agents/{agent_id}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("get");
        assert_eq!(get_after_delete.status(), StatusCode::NOT_FOUND);
    }
}
