use std::collections::HashSet;

use crate::common::error::{AppError, AppResult};
use crate::types::DeploymentStatus;
use serde::Serialize;
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DeploymentRecord {
    pub deployment_id: Uuid,
    pub agent_id: Uuid,
    pub account_id: Uuid,
    pub auth_method: String,
    pub compose: String,
    pub status: DeploymentStatus,
    pub cpu_vcpus: i32,
    pub memory_gb: f64,
    pub gpu_count: i32,
}

#[derive(Clone)]
pub struct DeploymentStore {
    pool: SqlitePool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveDeploymentTarget {
    pub agent_id: Uuid,
    pub app_name: String,
    pub status: DeploymentStatus,
    pub created_at_unix: i64,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewDeployment {
    pub compose: String,
    pub app_name: Option<String>,
    pub app_version: Option<String>,
    pub agent_id: Uuid,
    pub account_id: Uuid,
    pub auth_method: String,
    pub status: DeploymentStatus,
    pub cpu_vcpus: i32,
    pub memory_gb: f64,
    pub gpu_count: i32,
}

impl DeploymentStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, input: NewDeployment) -> AppResult<DeploymentRecord> {
        let deployment_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO deployments (deployment_id, compose, app_name, app_version, agent_id, status, cpu_vcpus, memory_gb, gpu_count, account_id, auth_method) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )
        .bind(deployment_id.to_string())
        .bind(input.compose)
        .bind(input.app_name)
        .bind(input.app_version)
        .bind(input.agent_id.to_string())
        .bind(status_to_db(input.status))
        .bind(input.cpu_vcpus)
        .bind(input.memory_gb)
        .bind(input.gpu_count)
        .bind(input.account_id.to_string())
        .bind(input.auth_method)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to create deployment: {e}")))?;

        self.get(deployment_id).await?.ok_or(AppError::NotFound)
    }

    pub async fn get(&self, deployment_id: Uuid) -> AppResult<Option<DeploymentRecord>> {
        let row = sqlx::query(
            "SELECT deployment_id, agent_id, account_id, auth_method, compose, status, cpu_vcpus, memory_gb, gpu_count \
             FROM deployments WHERE deployment_id = ?1",
        )
        .bind(deployment_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to fetch deployment: {e}")))?;

        row.map(row_to_deployment).transpose()
    }

    pub async fn list(&self, status: Option<DeploymentStatus>) -> AppResult<Vec<DeploymentRecord>> {
        let rows = if let Some(status) = status {
            sqlx::query(
                "SELECT deployment_id, agent_id, account_id, auth_method, compose, status, cpu_vcpus, memory_gb, gpu_count \
                 FROM deployments WHERE status = ?1 ORDER BY created_at DESC",
            )
            .bind(status_to_db(status))
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::External(format!("failed to list deployments: {e}")))?
        } else {
            sqlx::query(
                "SELECT deployment_id, agent_id, account_id, auth_method, compose, status, cpu_vcpus, memory_gb, gpu_count \
                 FROM deployments ORDER BY created_at DESC",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::External(format!("failed to list deployments: {e}")))?
        };

        rows.into_iter().map(row_to_deployment).collect()
    }

    pub async fn update_status(
        &self,
        deployment_id: Uuid,
        status: DeploymentStatus,
    ) -> AppResult<()> {
        sqlx::query("UPDATE deployments SET status = ?1, updated_at = CURRENT_TIMESTAMP WHERE deployment_id = ?2")
            .bind(status_to_db(status))
            .bind(deployment_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::External(format!("failed to update deployment status: {e}")))?;
        Ok(())
    }

    pub async fn agent_has_deploying(&self, agent_id: Uuid) -> AppResult<bool> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(1) FROM deployments WHERE agent_id = ?1 AND status = ?2",
        )
        .bind(agent_id.to_string())
        .bind(status_to_db(DeploymentStatus::Deploying))
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to read deploying status: {e}")))?;
        Ok(count > 0)
    }

    pub async fn promote_deploying_to_running_for_agent(&self, agent_id: Uuid) -> AppResult<u64> {
        let result = sqlx::query(
            "UPDATE deployments
             SET status = ?1, updated_at = CURRENT_TIMESTAMP
             WHERE agent_id = ?2 AND status = ?3",
        )
        .bind(status_to_db(DeploymentStatus::Running))
        .bind(agent_id.to_string())
        .bind(status_to_db(DeploymentStatus::Deploying))
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to promote deployment to running: {e}")))?;
        Ok(result.rows_affected())
    }

    pub async fn latest_app_name_for_agent(&self, agent_id: Uuid) -> AppResult<Option<String>> {
        let row = sqlx::query(
            "SELECT app_name
             FROM deployments
             WHERE agent_id = ?1 AND app_name IS NOT NULL AND app_name <> ''
             ORDER BY created_at DESC
             LIMIT 1",
        )
        .bind(agent_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to lookup latest app name: {e}")))?;
        let app_name = row
            .map(|r| {
                r.try_get("app_name")
                    .map_err(|e| AppError::External(format!("read app_name failed: {e}")))
            })
            .transpose()?;
        Ok(app_name)
    }

    pub async fn list_active_targets(&self) -> AppResult<Vec<ActiveDeploymentTarget>> {
        let rows = sqlx::query(
            "SELECT
                d.agent_id,
                COALESCE(NULLIF(d.app_name, ''), 'unknown') AS app_name,
                d.status,
                CAST(strftime('%s', d.created_at) AS INTEGER) AS created_at_unix,
                a.hostname AS hostname
             FROM deployments d
             LEFT JOIN agents a ON a.agent_id = d.agent_id
             WHERE d.status IN (?1, ?2)
             ORDER BY d.created_at DESC",
        )
        .bind(status_to_db(DeploymentStatus::Running))
        .bind(status_to_db(DeploymentStatus::Deploying))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            AppError::External(format!("failed to list active deployment targets: {e}"))
        })?;

        let mut seen_agents: HashSet<Uuid> = HashSet::new();
        let mut out = Vec::new();
        for row in rows {
            let agent_id_raw: String = row
                .try_get("agent_id")
                .map_err(|e| AppError::External(format!("read agent_id failed: {e}")))?;
            let agent_id = Uuid::parse_str(&agent_id_raw)
                .map_err(|e| AppError::External(format!("invalid agent_id uuid: {e}")))?;
            if seen_agents.contains(&agent_id) {
                continue;
            }
            seen_agents.insert(agent_id);
            let app_name: String = row
                .try_get("app_name")
                .map_err(|e| AppError::External(format!("read app_name failed: {e}")))?;
            let status_raw: String = row
                .try_get("status")
                .map_err(|e| AppError::External(format!("read status failed: {e}")))?;
            let created_at_unix: i64 = row
                .try_get("created_at_unix")
                .map_err(|e| AppError::External(format!("read created_at_unix failed: {e}")))?;
            let hostname: Option<String> = row
                .try_get("hostname")
                .map_err(|e| AppError::External(format!("read hostname failed: {e}")))?;
            out.push(ActiveDeploymentTarget {
                agent_id,
                app_name,
                status: status_from_db(&status_raw)?,
                created_at_unix,
                hostname,
            });
        }
        Ok(out)
    }
}

fn row_to_deployment(row: sqlx::sqlite::SqliteRow) -> AppResult<DeploymentRecord> {
    let deployment_id: String = row
        .try_get("deployment_id")
        .map_err(|e| AppError::External(format!("read deployment_id failed: {e}")))?;
    let agent_id: String = row
        .try_get("agent_id")
        .map_err(|e| AppError::External(format!("read agent_id failed: {e}")))?;
    let account_id: String = row
        .try_get("account_id")
        .map_err(|e| AppError::External(format!("read account_id failed: {e}")))?;
    let auth_method: String = row
        .try_get("auth_method")
        .map_err(|e| AppError::External(format!("read auth_method failed: {e}")))?;
    let compose: String = row
        .try_get("compose")
        .map_err(|e| AppError::External(format!("read compose failed: {e}")))?;
    let status: String = row
        .try_get("status")
        .map_err(|e| AppError::External(format!("read status failed: {e}")))?;
    let cpu_vcpus: i32 = row
        .try_get("cpu_vcpus")
        .map_err(|e| AppError::External(format!("read cpu_vcpus failed: {e}")))?;
    let memory_gb: f64 = row
        .try_get("memory_gb")
        .map_err(|e| AppError::External(format!("read memory_gb failed: {e}")))?;
    let gpu_count: i32 = row
        .try_get("gpu_count")
        .map_err(|e| AppError::External(format!("read gpu_count failed: {e}")))?;

    Ok(DeploymentRecord {
        deployment_id: Uuid::parse_str(&deployment_id)
            .map_err(|e| AppError::External(format!("invalid deployment_id uuid: {e}")))?,
        agent_id: Uuid::parse_str(&agent_id)
            .map_err(|e| AppError::External(format!("invalid agent_id uuid: {e}")))?,
        account_id: Uuid::parse_str(&account_id)
            .map_err(|e| AppError::External(format!("invalid account_id uuid: {e}")))?,
        auth_method,
        compose,
        status: status_from_db(&status)?,
        cpu_vcpus,
        memory_gb,
        gpu_count,
    })
}

fn status_to_db(status: DeploymentStatus) -> &'static str {
    match status {
        DeploymentStatus::Pending => "pending",
        DeploymentStatus::Deploying => "deploying",
        DeploymentStatus::Running => "running",
        DeploymentStatus::Failed => "failed",
        DeploymentStatus::Stopped => "stopped",
    }
}

fn status_from_db(raw: &str) -> AppResult<DeploymentStatus> {
    match raw {
        "pending" => Ok(DeploymentStatus::Pending),
        "deploying" => Ok(DeploymentStatus::Deploying),
        "running" => Ok(DeploymentStatus::Running),
        "failed" => Ok(DeploymentStatus::Failed),
        "stopped" => Ok(DeploymentStatus::Stopped),
        _ => Err(AppError::External(format!(
            "invalid deployment status: {raw}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use crate::types::DeploymentStatus;
    use sqlx::sqlite::SqlitePoolOptions;
    use uuid::Uuid;

    use super::{DeploymentStore, NewDeployment};

    #[tokio::test]
    async fn deployment_status_transition() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("pool");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrate");

        let store = DeploymentStore::new(pool);

        let created = store
            .create(NewDeployment {
                compose: "services: {}".to_string(),
                app_name: Some("demo".to_string()),
                app_version: Some("v1".to_string()),
                agent_id: Uuid::new_v4(),
                account_id: Uuid::new_v4(),
                auth_method: "api_key".to_string(),
                status: DeploymentStatus::Pending,
                cpu_vcpus: 4,
                memory_gb: 8.0,
                gpu_count: 0,
            })
            .await
            .expect("create");

        assert_eq!(created.status, DeploymentStatus::Pending);

        store
            .update_status(created.deployment_id, DeploymentStatus::Running)
            .await
            .expect("update status");

        let fetched = store
            .get(created.deployment_id)
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(fetched.status, DeploymentStatus::Running);
    }
}
