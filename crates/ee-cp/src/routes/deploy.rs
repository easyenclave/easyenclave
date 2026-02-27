use axum::extract::{Path, Query, State};
use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::Json;
use ee_common::api::{ApiErrorResponse, DeployRequest, DeployResponse};
use ee_common::types::{AgentStatus, DeploymentStatus};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::api_key::{key_prefix_from_raw, verify_api_key};
use crate::state::AppState;
use crate::stores::account::AccountStore;
use crate::stores::agent::AgentStore;
use crate::stores::deployment::{DeploymentStore, NewDeployment};

#[derive(Debug, Clone, Deserialize)]
pub struct DeploymentsQuery {
    pub status: Option<String>,
}

pub async fn deploy(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<DeployRequest>,
) -> Result<Json<DeployResponse>, (StatusCode, Json<ApiErrorResponse>)> {
    if payload.compose.trim().is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_deploy",
            "compose is required",
        ));
    }

    let deployer = authenticate_deployer_account(&headers, &state).await?;

    let agent_store = AgentStore::new(state.db_pool.clone());
    let deployment_store = DeploymentStore::new(state.db_pool.clone());

    let candidates = agent_store
        .list(Some(AgentStatus::Undeployed))
        .await
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_error",
                "failed to list agents",
            )
        })?;

    let selected = candidates
        .into_iter()
        .find(|a| {
            payload
                .agent_name
                .as_deref()
                .map(|name| a.vm_name == name)
                .unwrap_or(true)
                && (a.account_id.is_none() || a.account_id == Some(deployer.account_id))
                && payload
                    .node_size
                    .as_deref()
                    .map(|size| a.node_size.as_deref() == Some(size))
                    .unwrap_or(true)
                && payload
                    .datacenter
                    .as_deref()
                    .map(|dc| a.datacenter.as_deref() == Some(dc))
                    .unwrap_or(true)
        })
        .ok_or_else(|| {
            error_response(
                StatusCode::CONFLICT,
                "no_capacity",
                "no eligible undeployed agents available",
            )
        })?;

    let claimed = agent_store
        .claim_owner(selected.agent_id, deployer.account_id)
        .await
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_error",
                "failed to claim agent ownership",
            )
        })?;
    if !claimed {
        return Err(error_response(
            StatusCode::CONFLICT,
            "agent_owned",
            "selected agent is owned by a different account",
        ));
    }

    let deployment = deployment_store
        .create(NewDeployment {
            compose: payload.compose.clone(),
            agent_id: selected.agent_id,
            account_id: deployer.account_id,
            auth_method: deployer.auth_method.to_string(),
            status: if payload.dry_run.unwrap_or(false) {
                DeploymentStatus::Pending
            } else {
                DeploymentStatus::Deploying
            },
            cpu_vcpus: 4,
            memory_gb: 8.0,
            gpu_count: 0,
        })
        .await
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "deploy_create_failed",
                "failed to create deployment",
            )
        })?;

    if !payload.dry_run.unwrap_or(false) {
        let _ = agent_store
            .update_status(selected.agent_id, AgentStatus::Deploying)
            .await;
    }

    Ok(Json(DeployResponse {
        deployment_id: deployment.deployment_id,
        agent_id: deployment.agent_id,
        status: status_to_string(deployment.status),
    }))
}

async fn authenticate_deployer_account(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<AuthenticatedDeployer, (StatusCode, Json<ApiErrorResponse>)> {
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
        return Ok(AuthenticatedDeployer {
            account_id,
            auth_method: "github_oidc",
        });
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
    Ok(AuthenticatedDeployer {
        account_id,
        auth_method: "api_key",
    })
}

struct AuthenticatedDeployer {
    account_id: Uuid,
    auth_method: &'static str,
}

pub async fn list_deployments(
    State(state): State<AppState>,
    Query(query): Query<DeploymentsQuery>,
) -> Result<Json<Vec<crate::stores::deployment::DeploymentRecord>>, StatusCode> {
    let store = DeploymentStore::new(state.db_pool.clone());
    let status = query.status.as_deref().and_then(status_from_string);
    let items = store
        .list(status)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(items))
}

pub async fn get_deployment(
    Path(deployment_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<crate::stores::deployment::DeploymentRecord>, StatusCode> {
    let deployment_id = Uuid::parse_str(&deployment_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let store = DeploymentStore::new(state.db_pool.clone());
    let maybe = store
        .get(deployment_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    match maybe {
        Some(dep) => Ok(Json(dep)),
        None => Err(StatusCode::NOT_FOUND),
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

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ")
}

fn token_is_jwt(token: &str) -> bool {
    token.split('.').count() == 3
}

fn status_to_string(status: DeploymentStatus) -> String {
    match status {
        DeploymentStatus::Pending => "pending",
        DeploymentStatus::Deploying => "deploying",
        DeploymentStatus::Running => "running",
        DeploymentStatus::Failed => "failed",
        DeploymentStatus::Stopped => "stopped",
        DeploymentStatus::InsufficientFunds => "insufficient_funds",
    }
    .to_string()
}

fn status_from_string(raw: &str) -> Option<DeploymentStatus> {
    match raw {
        "pending" => Some(DeploymentStatus::Pending),
        "deploying" => Some(DeploymentStatus::Deploying),
        "running" => Some(DeploymentStatus::Running),
        "failed" => Some(DeploymentStatus::Failed),
        "stopped" => Some(DeploymentStatus::Stopped),
        "insufficient_funds" => Some(DeploymentStatus::InsufficientFunds),
        _ => None,
    }
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
    use crate::stores::agent::AgentStore;
    use crate::stores::setting::SettingsStore;
    use ee_common::types::AgentStatus;

    async fn test_app_with_oidc(github_oidc: GithubOidcService) -> axum::Router {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("pool");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrate");

        let agent_store = AgentStore::new(pool.clone());
        agent_store
            .create(
                "tdx-agent-deploy-1",
                AgentStatus::Undeployed,
                Some("standard"),
                Some("gcp:us-central1-a"),
                None,
            )
            .await
            .expect("seed agent");

        let settings = SettingsStore::new_with_ttl(pool.clone(), Duration::from_secs(5));
        let nonce = NonceService::new(Duration::from_secs(300));
        let attestation = AttestationService::insecure_for_tests();
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

    async fn test_app() -> axum::Router {
        test_app_with_oidc(GithubOidcService::disabled_for_tests()).await
    }

    #[tokio::test]
    async fn deploy_creates_record() {
        let app = test_app().await;

        let account_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/accounts")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"name": "deployer-1", "account_type": "deployer"}).to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("account response");
        assert_eq!(account_response.status(), StatusCode::OK);
        let account_body = axum::body::to_bytes(account_response.into_body(), usize::MAX)
            .await
            .expect("account body");
        let account_json: Value = serde_json::from_slice(&account_body).expect("account json");
        let api_key = account_json["api_key"].as_str().expect("api_key");

        let payload = json!({
            "compose": "services: {}",
            "node_size": "standard",
            "datacenter": "gcp:us-central1-a",
            "dry_run": false
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/deploy")
                    .header("authorization", format!("Bearer {api_key}"))
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("deploy response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: Value = serde_json::from_slice(&body).expect("json");
        let deployment_id = json["deployment_id"].as_str().expect("deployment_id");

        let get_response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/deployments/{deployment_id}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("get response");

        assert_eq!(get_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn deploy_with_unknown_agent_name_conflicts() {
        let app = test_app().await;

        let account_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/accounts")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"name": "deployer-2", "account_type": "deployer"}).to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("account response");
        assert_eq!(account_response.status(), StatusCode::OK);
        let account_body = axum::body::to_bytes(account_response.into_body(), usize::MAX)
            .await
            .expect("account body");
        let account_json: Value = serde_json::from_slice(&account_body).expect("account json");
        let api_key = account_json["api_key"].as_str().expect("api_key");

        let payload = json!({
            "compose": "services: {}",
            "agent_name": "does-not-exist",
            "node_size": "standard",
            "datacenter": "gcp:us-central1-a",
            "dry_run": false
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/deploy")
                    .header("authorization", format!("Bearer {api_key}"))
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("deploy response");

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn dry_run_claims_agent_owner_and_blocks_other_account() {
        let app = test_app().await;

        let account1_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/accounts")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"name": "deployer-a", "account_type": "deployer"}).to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("account response");
        assert_eq!(account1_response.status(), StatusCode::OK);
        let account1_body = axum::body::to_bytes(account1_response.into_body(), usize::MAX)
            .await
            .expect("account body");
        let account1_json: Value = serde_json::from_slice(&account1_body).expect("account json");
        let api_key_1 = account1_json["api_key"].as_str().expect("api_key");

        let dry_run_payload = json!({
            "compose": "services: {}",
            "node_size": "standard",
            "datacenter": "gcp:us-central1-a",
            "dry_run": true
        });
        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/deploy")
                    .header("authorization", format!("Bearer {api_key_1}"))
                    .header("content-type", "application/json")
                    .body(Body::from(dry_run_payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("first deploy");
        assert_eq!(first.status(), StatusCode::OK);

        let account2_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/accounts")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"name": "deployer-b", "account_type": "deployer"}).to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("account response");
        assert_eq!(account2_response.status(), StatusCode::OK);
        let account2_body = axum::body::to_bytes(account2_response.into_body(), usize::MAX)
            .await
            .expect("account body");
        let account2_json: Value = serde_json::from_slice(&account2_body).expect("account json");
        let api_key_2 = account2_json["api_key"].as_str().expect("api_key");

        let second = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/deploy")
                    .header("authorization", format!("Bearer {api_key_2}"))
                    .header("content-type", "application/json")
                    .body(Body::from(dry_run_payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("second deploy");
        assert_eq!(second.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn deploy_accepts_oidc_owner_token_via_route() {
        let app = test_app_with_oidc(GithubOidcService::with_forced_owner_for_tests(
            "example-org",
        ))
        .await;

        let account_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/accounts")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "name": "deployer-oidc",
                            "account_type": "deployer",
                            "github_org": "example-org"
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("account response");
        assert_eq!(account_response.status(), StatusCode::OK);

        let payload = json!({
            "compose": "services: {}",
            "node_size": "standard",
            "datacenter": "gcp:us-central1-a",
            "dry_run": false
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/deploy")
                    .header("authorization", "Bearer aaa.bbb.ccc")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("deploy response");
        assert_eq!(response.status(), StatusCode::OK);
    }
}
