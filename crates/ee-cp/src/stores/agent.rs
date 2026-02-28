use ee_common::error::{AppError, AppResult};
use ee_common::types::AgentStatus;
use serde::Serialize;
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentRecord {
    pub agent_id: Uuid,
    pub vm_name: String,
    pub status: AgentStatus,
    pub verified: bool,
    pub node_size: Option<String>,
    pub datacenter: Option<String>,
    pub account_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentTunnelInfo {
    pub tunnel_id: String,
    pub hostname: String,
}

#[derive(Clone)]
pub struct AgentStore {
    pool: SqlitePool,
}

impl AgentStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        vm_name: &str,
        status: AgentStatus,
        verified: bool,
        node_size: Option<&str>,
        datacenter: Option<&str>,
        account_id: Option<Uuid>,
    ) -> AppResult<AgentRecord> {
        let agent_id = Uuid::new_v4();
        let status_text = status_to_db(status);

        sqlx::query(
            "INSERT INTO agents (agent_id, vm_name, status, verified, node_size, datacenter, account_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(agent_id.to_string())
        .bind(vm_name)
        .bind(status_text)
        .bind(if verified { 1_i64 } else { 0_i64 })
        .bind(node_size)
        .bind(datacenter)
        .bind(account_id.map(|v| v.to_string()))
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to create agent: {e}")))?;

        self.get(agent_id).await?.ok_or(AppError::NotFound)
    }

    pub async fn get(&self, agent_id: Uuid) -> AppResult<Option<AgentRecord>> {
        let row = sqlx::query(
            "SELECT agent_id, vm_name, status, verified, node_size, datacenter, account_id \
             FROM agents WHERE agent_id = ?1",
        )
        .bind(agent_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to fetch agent: {e}")))?;

        row.map(row_to_agent).transpose()
    }

    pub async fn list(&self, status: Option<AgentStatus>) -> AppResult<Vec<AgentRecord>> {
        let rows = if let Some(status) = status {
            sqlx::query(
                "SELECT agent_id, vm_name, status, verified, node_size, datacenter, account_id \
                 FROM agents WHERE status = ?1 ORDER BY created_at DESC",
            )
            .bind(status_to_db(status))
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::External(format!("failed to list agents: {e}")))?
        } else {
            sqlx::query(
                "SELECT agent_id, vm_name, status, verified, node_size, datacenter, account_id \
                 FROM agents ORDER BY created_at DESC",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::External(format!("failed to list agents: {e}")))?
        };

        rows.into_iter().map(row_to_agent).collect()
    }

    pub async fn update_status(&self, agent_id: Uuid, status: AgentStatus) -> AppResult<()> {
        sqlx::query(
            "UPDATE agents SET status = ?1, updated_at = CURRENT_TIMESTAMP WHERE agent_id = ?2",
        )
        .bind(status_to_db(status))
        .bind(agent_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to update agent status: {e}")))?;
        Ok(())
    }

    pub async fn set_tunnel(
        &self,
        agent_id: Uuid,
        tunnel_id: &str,
        hostname: &str,
        tunnel_token: &str,
    ) -> AppResult<()> {
        sqlx::query(
            "UPDATE agents
             SET tunnel_id = ?1,
                 hostname = ?2,
                 tunnel_token = ?3,
                 updated_at = CURRENT_TIMESTAMP
             WHERE agent_id = ?4",
        )
        .bind(tunnel_id)
        .bind(hostname)
        .bind(tunnel_token)
        .bind(agent_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to persist agent tunnel fields: {e}")))?;
        Ok(())
    }

    pub async fn claim_owner(&self, agent_id: Uuid, account_id: Uuid) -> AppResult<bool> {
        let result = sqlx::query(
            "UPDATE agents
             SET account_id = ?1, updated_at = CURRENT_TIMESTAMP
             WHERE agent_id = ?2 AND (account_id IS NULL OR account_id = ?1)",
        )
        .bind(account_id.to_string())
        .bind(agent_id.to_string())
        .bind(account_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to claim agent owner: {e}")))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn tunnel_info(&self, agent_id: Uuid) -> AppResult<Option<AgentTunnelInfo>> {
        let row = sqlx::query("SELECT tunnel_id, hostname FROM agents WHERE agent_id = ?1")
            .bind(agent_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::External(format!("failed to read agent tunnel info: {e}")))?;

        row.map(|r| {
            let tunnel_id: Option<String> = r
                .try_get("tunnel_id")
                .map_err(|e| AppError::External(format!("read tunnel_id failed: {e}")))?;
            let hostname: Option<String> = r
                .try_get("hostname")
                .map_err(|e| AppError::External(format!("read hostname failed: {e}")))?;
            Ok(match (tunnel_id, hostname) {
                (Some(tunnel_id), Some(hostname))
                    if !tunnel_id.is_empty() && !hostname.is_empty() =>
                {
                    Some(AgentTunnelInfo {
                        tunnel_id,
                        hostname,
                    })
                }
                _ => None,
            })
        })
        .transpose()
        .map(Option::flatten)
    }

    pub async fn delete(&self, agent_id: Uuid) -> AppResult<()> {
        sqlx::query("DELETE FROM agents WHERE agent_id = ?1")
            .bind(agent_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::External(format!("failed to delete agent: {e}")))?;
        Ok(())
    }
}

fn row_to_agent(row: sqlx::sqlite::SqliteRow) -> AppResult<AgentRecord> {
    let agent_id: String = row
        .try_get("agent_id")
        .map_err(|e| AppError::External(format!("read agent_id failed: {e}")))?;
    let vm_name: String = row
        .try_get("vm_name")
        .map_err(|e| AppError::External(format!("read vm_name failed: {e}")))?;
    let status_text: String = row
        .try_get("status")
        .map_err(|e| AppError::External(format!("read status failed: {e}")))?;
    let verified: i64 = row
        .try_get("verified")
        .map_err(|e| AppError::External(format!("read verified failed: {e}")))?;
    let node_size: Option<String> = row
        .try_get("node_size")
        .map_err(|e| AppError::External(format!("read node_size failed: {e}")))?;
    let datacenter: Option<String> = row
        .try_get("datacenter")
        .map_err(|e| AppError::External(format!("read datacenter failed: {e}")))?;
    let account_id_text: Option<String> = row
        .try_get("account_id")
        .map_err(|e| AppError::External(format!("read account_id failed: {e}")))?;

    let account_id = account_id_text
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|e| AppError::External(format!("invalid account_id uuid: {e}")))?;

    Ok(AgentRecord {
        agent_id: Uuid::parse_str(&agent_id)
            .map_err(|e| AppError::External(format!("invalid agent_id uuid: {e}")))?,
        vm_name,
        status: status_from_db(&status_text)?,
        verified: verified != 0,
        node_size,
        datacenter,
        account_id,
    })
}

fn status_to_db(status: AgentStatus) -> &'static str {
    match status {
        AgentStatus::Undeployed => "undeployed",
        AgentStatus::Deploying => "deploying",
        AgentStatus::Deployed => "deployed",
    }
}

fn status_from_db(raw: &str) -> AppResult<AgentStatus> {
    match raw {
        "undeployed" => Ok(AgentStatus::Undeployed),
        "deploying" => Ok(AgentStatus::Deploying),
        "deployed" => Ok(AgentStatus::Deployed),
        _ => Err(AppError::External(format!("invalid agent status: {raw}"))),
    }
}

#[cfg(test)]
mod tests {
    use ee_common::types::AgentStatus;
    use sqlx::sqlite::SqlitePoolOptions;
    use sqlx::Row;
    use uuid::Uuid;

    use super::AgentStore;

    #[tokio::test]
    async fn agent_crud_round_trip() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("pool");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrate");

        let store = AgentStore::new(pool);
        let created = store
            .create(
                "tdx-agent-001",
                AgentStatus::Undeployed,
                false,
                Some("standard"),
                Some("gcp:us-central1-a"),
                None,
            )
            .await
            .expect("create");

        let fetched = store
            .get(created.agent_id)
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(fetched.vm_name, "tdx-agent-001");
        assert_eq!(fetched.status, AgentStatus::Undeployed);

        store
            .update_status(created.agent_id, AgentStatus::Deploying)
            .await
            .expect("update");
        let updated = store
            .get(created.agent_id)
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(updated.status, AgentStatus::Deploying);

        let listed = store
            .list(Some(AgentStatus::Deploying))
            .await
            .expect("list");
        assert_eq!(listed.len(), 1);

        let owner_id = Uuid::new_v4();
        let claimed = store
            .claim_owner(created.agent_id, owner_id)
            .await
            .expect("claim owner");
        assert!(claimed);
        let same_owner_claim = store
            .claim_owner(created.agent_id, owner_id)
            .await
            .expect("claim same owner");
        assert!(same_owner_claim);
        let different_owner_claim = store
            .claim_owner(created.agent_id, Uuid::new_v4())
            .await
            .expect("claim different owner");
        assert!(!different_owner_claim);

        store
            .set_tunnel(
                created.agent_id,
                "tunnel-123",
                "agent-abc.example.com",
                "token-abc",
            )
            .await
            .expect("set tunnel");
        let tunnel_row =
            sqlx::query("SELECT tunnel_id, hostname, tunnel_token FROM agents WHERE agent_id = ?1")
                .bind(created.agent_id.to_string())
                .fetch_one(&store.pool)
                .await
                .expect("read tunnel row");
        let tunnel_id: Option<String> = tunnel_row.try_get("tunnel_id").expect("tunnel_id");
        let hostname: Option<String> = tunnel_row.try_get("hostname").expect("hostname");
        let tunnel_token: Option<String> =
            tunnel_row.try_get("tunnel_token").expect("tunnel_token");
        assert_eq!(tunnel_id.as_deref(), Some("tunnel-123"));
        assert_eq!(hostname.as_deref(), Some("agent-abc.example.com"));
        assert_eq!(tunnel_token.as_deref(), Some("token-abc"));
        let tunnel_info = store
            .tunnel_info(created.agent_id)
            .await
            .expect("tunnel info")
            .expect("exists");
        assert_eq!(tunnel_info.tunnel_id, "tunnel-123");
        assert_eq!(tunnel_info.hostname, "agent-abc.example.com");

        store.delete(created.agent_id).await.expect("delete");
        let after_delete = store.get(created.agent_id).await.expect("get");
        assert!(after_delete.is_none());
    }
}
