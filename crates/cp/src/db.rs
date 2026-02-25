//! SQLite database (cache layer — all tables are reconstructable).

use crate::error::CpError;
use ee_common::types::{
    AgentInfo, AggregatorId, Cloud, MeasurementSubmission, TrustedMrtd, VmSize,
};
use rusqlite::{params, Connection};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

/// Database handle (SQLite).
#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    /// Open or create the database at the given path.
    /// Use ":memory:" for in-memory (tests).
    pub fn open(path: &str) -> Result<Self, CpError> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            Connection::open(path)?
        };

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.migrate_sync()?;
        Ok(db)
    }

    fn migrate_sync(&self) -> Result<(), CpError> {
        // We need to block on the lock for migration at startup
        // This is safe because we're single-threaded at this point
        let conn = self
            .conn
            .try_lock()
            .map_err(|_| CpError::Database("could not lock database for migration".to_string()))?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                size TEXT NOT NULL,
                cloud TEXT NOT NULL,
                region TEXT NOT NULL,
                tags TEXT NOT NULL DEFAULT '[]',
                registered_at TEXT NOT NULL,
                last_health_check TEXT,
                aggregator_id TEXT
            );

            CREATE TABLE IF NOT EXISTS aggregators (
                id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                region TEXT NOT NULL,
                registered_at TEXT NOT NULL,
                last_scrape TEXT
            );

            CREATE TABLE IF NOT EXISTS trusted_aggregators (
                id TEXT PRIMARY KEY,
                added_at TEXT NOT NULL,
                added_by TEXT
            );

            CREATE TABLE IF NOT EXISTS trusted_mrtds (
                mrtd TEXT PRIMARY KEY,
                size TEXT NOT NULL,
                cloud TEXT NOT NULL,
                release_tag TEXT,
                submitted_by TEXT NOT NULL,
                submitted_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS deployments (
                app_name TEXT PRIMARY KEY,
                image TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                owner TEXT NOT NULL,
                status TEXT NOT NULL,
                tunnel_url TEXT,
                deployed_at TEXT NOT NULL
            );
            ",
        )?;

        info!("database migrated");
        Ok(())
    }

    // --- Trusted MRTDs ---

    pub async fn insert_mrtd(
        &self,
        submission: &MeasurementSubmission,
        submitted_by: &str,
    ) -> Result<(), CpError> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR REPLACE INTO trusted_mrtds (mrtd, size, cloud, release_tag, submitted_by, submitted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                submission.mrtd,
                serde_json::to_string(&submission.size).unwrap_or_default(),
                serde_json::to_string(&submission.cloud).unwrap_or_default(),
                submission.release_tag,
                submitted_by,
                chrono::Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub async fn get_all_mrtds(&self) -> Result<Vec<TrustedMrtd>, CpError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT mrtd, size, cloud, release_tag, submitted_by, submitted_at FROM trusted_mrtds",
        )?;

        let rows = stmt
            .query_map([], |row| {
                let size_str: String = row.get(1)?;
                let cloud_str: String = row.get(2)?;
                Ok(TrustedMrtd {
                    mrtd: row.get(0)?,
                    size: serde_json::from_str(&size_str).unwrap_or(VmSize::Medium),
                    cloud: serde_json::from_str(&cloud_str).unwrap_or(Cloud::Gcp),
                    release_tag: row.get(3)?,
                    submitted_by: AggregatorId(
                        row.get::<_, String>(4)?
                            .parse()
                            .unwrap_or(uuid::Uuid::nil()),
                    ),
                    submitted_at: row
                        .get::<_, String>(5)?
                        .parse()
                        .unwrap_or(chrono::Utc::now()),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rows)
    }

    pub async fn is_mrtd_known(&self, mrtd: &str) -> Result<bool, CpError> {
        let conn = self.conn.lock().await;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM trusted_mrtds WHERE mrtd = ?1",
            params![mrtd],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    // --- Trusted Aggregators ---

    pub async fn add_trusted_aggregator(&self, id: &str, added_by: &str) -> Result<(), CpError> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR REPLACE INTO trusted_aggregators (id, added_at, added_by) VALUES (?1, ?2, ?3)",
            params![id, chrono::Utc::now().to_rfc3339(), added_by],
        )?;
        Ok(())
    }

    pub async fn remove_trusted_aggregator(&self, id: &str) -> Result<(), CpError> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM trusted_aggregators WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub async fn is_trusted_aggregator(&self, id: &str) -> Result<bool, CpError> {
        let conn = self.conn.lock().await;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM trusted_aggregators WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub async fn list_trusted_aggregators(&self) -> Result<Vec<String>, CpError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare("SELECT id FROM trusted_aggregators")?;
        let rows = stmt
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        Ok(rows)
    }

    // --- Agents (cache) ---

    pub async fn upsert_agent(
        &self,
        agent: &AgentInfo,
        aggregator_id: Option<&str>,
    ) -> Result<(), CpError> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR REPLACE INTO agents (id, status, size, cloud, region, tags, registered_at, last_health_check, aggregator_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                agent.id.to_string(),
                serde_json::to_string(&agent.status).unwrap_or_default(),
                serde_json::to_string(&agent.size).unwrap_or_default(),
                serde_json::to_string(&agent.cloud).unwrap_or_default(),
                agent.region,
                serde_json::to_string(&agent.tags).unwrap_or_default(),
                agent.registered_at.to_rfc3339(),
                agent.last_health_check.map(|t| t.to_rfc3339()),
                aggregator_id,
            ],
        )?;
        Ok(())
    }
}
