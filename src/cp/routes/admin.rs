use crate::cp_api::ApiErrorResponse;
use axum::extract::{Query, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::auth::admin_session::{
    token_prefix_from_raw as session_prefix_from_raw, verify_session_token,
};
use crate::state::AppState;
use crate::stores::agent::AgentStore;
use crate::stores::session::SessionStore;

#[derive(Debug, Clone, Deserialize)]
pub struct ObservedMeasurementsQuery {
    pub node_size: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpsertTrustedAgentMeasurementRequest {
    pub node_size: String,
    pub mrtd: String,
    pub rtmrs: Option<Value>,
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrustedAgentMeasurementsResponse {
    pub trusted_agent_mrtds: String,
    pub trusted_agent_mrtds_by_size: Value,
    pub trusted_agent_rtmrs_by_size: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpsertTrustedAgentMeasurementResponse {
    pub updated: bool,
    pub node_size: String,
    pub mrtd: String,
    pub source: Option<String>,
    pub trusted: TrustedAgentMeasurementsResponse,
}

pub async fn list_observed_agent_measurements(
    headers: HeaderMap,
    Query(query): Query<ObservedMeasurementsQuery>,
    State(state): State<AppState>,
) -> Result<
    Json<Vec<crate::stores::agent::AgentMeasurementRecord>>,
    (StatusCode, Json<ApiErrorResponse>),
> {
    authenticate_admin_session(&headers, &state).await?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let node_size = query.node_size.as_deref();
    let store = AgentStore::new(state.db_pool.clone());
    let rows = store
        .list_observed_measurements(node_size, limit)
        .await
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_error",
                "failed to list observed measurements",
            )
        })?;
    Ok(Json(rows))
}

pub async fn get_trusted_agent_measurements(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<TrustedAgentMeasurementsResponse>, (StatusCode, Json<ApiErrorResponse>)> {
    authenticate_admin_session(&headers, &state).await?;
    let payload = trusted_agent_measurements_snapshot(&state).await?;
    Ok(Json(payload))
}

pub async fn upsert_trusted_agent_measurement(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<UpsertTrustedAgentMeasurementRequest>,
) -> Result<Json<UpsertTrustedAgentMeasurementResponse>, (StatusCode, Json<ApiErrorResponse>)> {
    authenticate_admin_session(&headers, &state).await?;

    let node_size = normalize_node_size(&payload.node_size).ok_or_else(|| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_node_size",
            "node_size must be tiny|standard|llm",
        )
    })?;

    let mrtd = payload.mrtd.trim().to_ascii_lowercase();
    if mrtd.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_mrtd",
            "mrtd must be non-empty",
        ));
    }

    let rtmrs = payload.rtmrs.as_ref().map(validate_rtmrs).transpose()?;

    let mut mrtds_csv = load_setting_string(&state, "trusted_agent_mrtds").await?;
    if !mrtds_csv
        .split(',')
        .map(str::trim)
        .any(|v| !v.is_empty() && v.eq_ignore_ascii_case(&mrtd))
    {
        mrtds_csv = if mrtds_csv.trim().is_empty() {
            mrtd.clone()
        } else {
            format!("{mrtds_csv},{mrtd}")
        };
    }

    let mut mrtds_by_size = load_setting_object(&state, "trusted_agent_mrtds_by_size").await?;
    mrtds_by_size.insert(node_size.clone(), Value::String(mrtd.clone()));

    let mut rtmrs_by_size = load_setting_object(&state, "trusted_agent_rtmrs_by_size").await?;
    if let Some(rtmrs) = rtmrs {
        rtmrs_by_size.insert(node_size.clone(), rtmrs);
    }

    state
        .settings
        .put(
            "trusted_agent_mrtds",
            &Value::String(mrtds_csv.clone()),
            false,
        )
        .await
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "setting_write_failed",
                "failed to write trusted_agent_mrtds",
            )
        })?;
    state
        .settings
        .put(
            "trusted_agent_mrtds_by_size",
            &Value::Object(mrtds_by_size.clone()),
            false,
        )
        .await
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "setting_write_failed",
                "failed to write trusted_agent_mrtds_by_size",
            )
        })?;
    state
        .settings
        .put(
            "trusted_agent_rtmrs_by_size",
            &Value::Object(rtmrs_by_size.clone()),
            false,
        )
        .await
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "setting_write_failed",
                "failed to write trusted_agent_rtmrs_by_size",
            )
        })?;

    Ok(Json(UpsertTrustedAgentMeasurementResponse {
        updated: true,
        node_size,
        mrtd,
        source: payload.source,
        trusted: TrustedAgentMeasurementsResponse {
            trusted_agent_mrtds: mrtds_csv,
            trusted_agent_mrtds_by_size: Value::Object(mrtds_by_size),
            trusted_agent_rtmrs_by_size: Value::Object(rtmrs_by_size),
        },
    }))
}

async fn trusted_agent_measurements_snapshot(
    state: &AppState,
) -> Result<TrustedAgentMeasurementsResponse, (StatusCode, Json<ApiErrorResponse>)> {
    let trusted_agent_mrtds = load_setting_string(state, "trusted_agent_mrtds").await?;
    let trusted_agent_mrtds_by_size =
        Value::Object(load_setting_object(state, "trusted_agent_mrtds_by_size").await?);
    let trusted_agent_rtmrs_by_size =
        Value::Object(load_setting_object(state, "trusted_agent_rtmrs_by_size").await?);

    Ok(TrustedAgentMeasurementsResponse {
        trusted_agent_mrtds,
        trusted_agent_mrtds_by_size,
        trusted_agent_rtmrs_by_size,
    })
}

async fn load_setting_string(
    state: &AppState,
    key: &str,
) -> Result<String, (StatusCode, Json<ApiErrorResponse>)> {
    match state.settings.get(key).await {
        Ok(Value::String(text)) => Ok(text),
        Ok(other) => Ok(other.to_string()),
        Err(crate::common::error::AppError::NotFound) => Ok(String::new()),
        Err(_) => Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "setting_read_failed",
            "failed to load setting",
        )),
    }
}

async fn load_setting_object(
    state: &AppState,
    key: &str,
) -> Result<Map<String, Value>, (StatusCode, Json<ApiErrorResponse>)> {
    match state.settings.get(key).await {
        Ok(Value::Object(map)) => Ok(map),
        Ok(Value::Null) => Ok(Map::new()),
        Ok(Value::String(text)) => {
            let parsed = serde_json::from_str::<Value>(&text).unwrap_or(Value::Null);
            if let Value::Object(map) = parsed {
                Ok(map)
            } else {
                Ok(Map::new())
            }
        }
        Ok(_) => Ok(Map::new()),
        Err(crate::common::error::AppError::NotFound) => Ok(Map::new()),
        Err(_) => Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "setting_read_failed",
            "failed to load setting",
        )),
    }
}

fn validate_rtmrs(input: &Value) -> Result<Value, (StatusCode, Json<ApiErrorResponse>)> {
    let obj = input.as_object().ok_or_else(|| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_rtmrs",
            "rtmrs must be a JSON object with rtmr0..rtmr3",
        )
    })?;

    let get = |k: &str| -> Result<String, (StatusCode, Json<ApiErrorResponse>)> {
        let value = obj
            .get(k)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_rtmrs",
                    "rtmrs must include non-empty rtmr0..rtmr3 strings",
                )
            })?;
        Ok(value.to_ascii_lowercase())
    };

    Ok(json!({
        "rtmr0": get("rtmr0")?,
        "rtmr1": get("rtmr1")?,
        "rtmr2": get("rtmr2")?,
        "rtmr3": get("rtmr3")?,
    }))
}

async fn authenticate_admin_session(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<(), (StatusCode, Json<ApiErrorResponse>)> {
    let token = bearer_token(headers).ok_or_else(|| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "missing_auth",
            "bearer token is required",
        )
    })?;
    let token_prefix = session_prefix_from_raw(token).ok_or_else(|| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_session",
            "invalid admin session token format",
        )
    })?;

    let sessions = SessionStore::new(state.db_pool.clone());
    let session = sessions
        .lookup_by_prefix(&token_prefix)
        .await
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "auth_lookup_failed",
                "failed to validate admin session",
            )
        })?
        .ok_or_else(|| {
            error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_session",
                "unknown admin session",
            )
        })?;
    let verified = verify_session_token(&session.token_hash, token).map_err(|_| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_session",
            "invalid admin session token",
        )
    })?;
    if !verified {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_session",
            "invalid admin session token",
        ));
    }

    Ok(())
}

fn normalize_node_size(raw: &str) -> Option<String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "tiny" => Some("tiny".to_string()),
        "standard" => Some("standard".to_string()),
        "llm" => Some("llm".to_string()),
        _ => None,
    }
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

    use crate::types::{AgentRegistrationState, AgentStatus};
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

    async fn test_app(seed_observed_agent: bool) -> axum::Router {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("pool");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrate");

        if seed_observed_agent {
            let store = AgentStore::new(pool.clone());
            store
                .create(
                    "admin-observed-agent-1",
                    AgentStatus::Undeployed,
                    AgentRegistrationState::Ready,
                    true,
                    Some("tiny"),
                    Some("gcp:test"),
                    None,
                    None,
                    Some("tdx_mrtd_observed_1"),
                    Some(r#"{"rtmr0":"a0","rtmr1":"a1","rtmr2":"a2","rtmr3":"a3"}"#),
                    Some("UpToDate"),
                )
                .await
                .expect("seed observed agent");
        }

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

    async fn admin_token(app: &axum::Router) -> String {
        let response = app
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
            .expect("admin login response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let payload: Value = serde_json::from_slice(&body).expect("json");
        payload["token"].as_str().expect("token").to_string()
    }

    #[tokio::test]
    async fn observed_measurements_requires_admin_session() {
        let app = test_app(true).await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/admin/measurements/agents")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn upsert_and_get_trusted_measurements() {
        let app = test_app(true).await;
        let token = admin_token(&app).await;

        let observed_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/admin/measurements/agents?node_size=tiny&limit=5")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("observed response");
        assert_eq!(observed_response.status(), StatusCode::OK);
        let observed_body = axum::body::to_bytes(observed_response.into_body(), usize::MAX)
            .await
            .expect("observed body");
        let observed_json: Value = serde_json::from_slice(&observed_body).expect("observed json");
        let mrtd = observed_json[0]["mrtd"].as_str().expect("mrtd").to_string();
        let rtmrs = observed_json[0]["rtmrs"].clone();

        let upsert_payload = json!({
            "node_size": "tiny",
            "mrtd": mrtd,
            "rtmrs": rtmrs,
            "source": "test"
        });
        let upsert_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/trusted-measurements/agent")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(upsert_payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("upsert response");
        assert_eq!(upsert_response.status(), StatusCode::OK);

        let trusted_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/admin/trusted-measurements/agent")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("trusted response");
        assert_eq!(trusted_response.status(), StatusCode::OK);
        let trusted_body = axum::body::to_bytes(trusted_response.into_body(), usize::MAX)
            .await
            .expect("trusted body");
        let trusted_json: Value = serde_json::from_slice(&trusted_body).expect("trusted json");
        assert_eq!(
            trusted_json["trusted_agent_mrtds_by_size"]["tiny"]
                .as_str()
                .expect("tiny mrtd"),
            observed_json[0]["mrtd"].as_str().expect("observed mrtd")
        );
        assert!(trusted_json["trusted_agent_mrtds"]
            .as_str()
            .expect("mrtd csv")
            .contains(observed_json[0]["mrtd"].as_str().expect("observed mrtd")));
    }
}
