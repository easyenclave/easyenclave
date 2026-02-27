use chrono::{Duration, Utc};
use ee_common::error::{AppError, AppResult};
use serde::Serialize;
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SessionRecord {
    pub session_id: Uuid,
    pub token_hash: String,
    pub token_prefix: String,
    pub expires_at: String,
    pub auth_method: String,
    pub github_login: Option<String>,
}

#[derive(Clone)]
pub struct SessionStore {
    pool: SqlitePool,
}

impl SessionStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create_password_session(
        &self,
        token_hash: &str,
        token_prefix: &str,
    ) -> AppResult<SessionRecord> {
        let session_id = Uuid::new_v4();
        let expires_at = (Utc::now() + Duration::hours(24)).to_rfc3339();

        sqlx::query(
            "INSERT INTO admin_sessions (session_id, token_hash, token_prefix, expires_at, auth_method) \
             VALUES (?1, ?2, ?3, ?4, 'password')",
        )
        .bind(session_id.to_string())
        .bind(token_hash)
        .bind(token_prefix)
        .bind(&expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to create session: {e}")))?;

        self.lookup_by_prefix(token_prefix)
            .await?
            .ok_or(AppError::NotFound)
    }

    pub async fn lookup_by_prefix(&self, prefix: &str) -> AppResult<Option<SessionRecord>> {
        let row = sqlx::query(
            "SELECT session_id, token_hash, token_prefix, expires_at, auth_method, github_login \
             FROM admin_sessions WHERE token_prefix = ?1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(prefix)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to lookup session: {e}")))?;

        row.map(row_to_session).transpose()
    }

    pub async fn delete_by_prefix(&self, prefix: &str) -> AppResult<()> {
        sqlx::query("DELETE FROM admin_sessions WHERE token_prefix = ?1")
            .bind(prefix)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::External(format!("failed to delete session: {e}")))?;
        Ok(())
    }
}

fn row_to_session(row: sqlx::sqlite::SqliteRow) -> AppResult<SessionRecord> {
    let session_id: String = row
        .try_get("session_id")
        .map_err(|e| AppError::External(format!("read session_id failed: {e}")))?;
    let token_hash: String = row
        .try_get("token_hash")
        .map_err(|e| AppError::External(format!("read token_hash failed: {e}")))?;
    let token_prefix: String = row
        .try_get("token_prefix")
        .map_err(|e| AppError::External(format!("read token_prefix failed: {e}")))?;
    let expires_at: String = row
        .try_get("expires_at")
        .map_err(|e| AppError::External(format!("read expires_at failed: {e}")))?;
    let auth_method: String = row
        .try_get("auth_method")
        .map_err(|e| AppError::External(format!("read auth_method failed: {e}")))?;
    let github_login: Option<String> = row
        .try_get("github_login")
        .map_err(|e| AppError::External(format!("read github_login failed: {e}")))?;

    Ok(SessionRecord {
        session_id: Uuid::parse_str(&session_id)
            .map_err(|e| AppError::External(format!("invalid session_id uuid: {e}")))?,
        token_hash,
        token_prefix,
        expires_at,
        auth_method,
        github_login,
    })
}

#[cfg(test)]
mod tests {
    use sqlx::sqlite::SqlitePoolOptions;

    use super::SessionStore;

    #[tokio::test]
    async fn create_lookup_delete_session() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("pool");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrate");

        let store = SessionStore::new(pool);
        let created = store
            .create_password_session("hash", "ees_abcdef123")
            .await
            .expect("create");
        assert_eq!(created.token_prefix, "ees_abcdef123");

        let found = store
            .lookup_by_prefix("ees_abcdef123")
            .await
            .expect("lookup")
            .expect("exists");
        assert_eq!(found.auth_method, "password");

        store
            .delete_by_prefix("ees_abcdef123")
            .await
            .expect("delete");
        let missing = store
            .lookup_by_prefix("ees_abcdef123")
            .await
            .expect("lookup");
        assert!(missing.is_none());
    }
}
