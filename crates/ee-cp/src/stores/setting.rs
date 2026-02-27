use std::collections::HashMap;
use std::env;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use ee_common::error::{AppError, AppResult};
use serde_json::Value;
use sqlx::{Row, SqlitePool};

#[derive(Clone)]
pub struct SettingsStore {
    pool: SqlitePool,
    ttl: Duration,
    cache: Arc<RwLock<Option<CachedSettings>>>,
}

#[derive(Clone)]
struct CachedSettings {
    loaded_at: Instant,
    by_key: HashMap<String, Value>,
}

impl SettingsStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self::new_with_ttl(pool, Duration::from_secs(5))
    }

    pub fn new_with_ttl(pool: SqlitePool, ttl: Duration) -> Self {
        Self {
            pool,
            ttl,
            cache: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn get(&self, key: &str) -> AppResult<Value> {
        let db_values = self.cached_db_values().await?;
        resolve_value(key, &db_values, &|env_key| env::var(env_key).ok()).ok_or(AppError::NotFound)
    }

    pub async fn put(&self, key: &str, value: &Value, is_secret: bool) -> AppResult<()> {
        let value_text = serde_json::to_string(value)
            .map_err(|e| AppError::InvalidInput(format!("setting value serialize failed: {e}")))?;

        sqlx::query(
            "INSERT INTO settings (key, value, is_secret, updated_at) \
             VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, is_secret = excluded.is_secret, updated_at = CURRENT_TIMESTAMP",
        )
        .bind(key)
        .bind(value_text)
        .bind(if is_secret { 1_i64 } else { 0_i64 })
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to write setting: {e}")))?;

        self.invalidate_cache();
        Ok(())
    }

    fn invalidate_cache(&self) {
        *self.cache.write().expect("rwlock poisoned") = None;
    }

    async fn cached_db_values(&self) -> AppResult<HashMap<String, Value>> {
        if let Some(snapshot) = self.cache.read().expect("rwlock poisoned").as_ref() {
            if snapshot.loaded_at.elapsed() < self.ttl {
                return Ok(snapshot.by_key.clone());
            }
        }

        let values = self.load_all_db_values().await?;
        *self.cache.write().expect("rwlock poisoned") = Some(CachedSettings {
            loaded_at: Instant::now(),
            by_key: values.clone(),
        });
        Ok(values)
    }

    async fn load_all_db_values(&self) -> AppResult<HashMap<String, Value>> {
        let rows = sqlx::query("SELECT key, value FROM settings")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::External(format!("failed to load settings: {e}")))?;

        let mut by_key = HashMap::new();
        for row in rows {
            let key: String = row
                .try_get("key")
                .map_err(|e| AppError::External(format!("failed to read settings.key: {e}")))?;
            let raw_value: String = row
                .try_get("value")
                .map_err(|e| AppError::External(format!("failed to read settings.value: {e}")))?;
            let parsed =
                serde_json::from_str::<Value>(&raw_value).unwrap_or(Value::String(raw_value));
            by_key.insert(key, parsed);
        }

        Ok(by_key)
    }
}

fn resolve_value<F>(key: &str, db_values: &HashMap<String, Value>, env_get: &F) -> Option<Value>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(v) = db_values.get(key) {
        return Some(v.clone());
    }

    if let Some(env_key) = env_key_for(key) {
        if let Some(raw) = env_get(env_key) {
            if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                return Some(v);
            }
            return Some(Value::String(raw));
        }
    }

    default_value_for(key)
}

fn env_key_for(key: &str) -> Option<&'static str> {
    match key {
        "tcb_enforcement_mode" => Some("CP_TCB_ENFORCEMENT_MODE"),
        "rtmr_enforcement_mode" => Some("CP_RTMR_ENFORCEMENT_MODE"),
        "nonce_enforcement_mode" => Some("CP_NONCE_ENFORCEMENT_MODE"),
        "billing.enabled" => Some("CP_BILLING_ENABLED"),
        "billing.contributor_pool_bps" => Some("CP_BILLING_CONTRIBUTOR_POOL_BPS"),
        "agent_stale_hours" => Some("CP_AGENT_STALE_HOURS"),
        _ => None,
    }
}

fn default_value_for(key: &str) -> Option<Value> {
    match key {
        "tcb_enforcement_mode" => Some(Value::String("strict".to_string())),
        "rtmr_enforcement_mode" => Some(Value::String("strict".to_string())),
        "nonce_enforcement_mode" => Some(Value::String("required".to_string())),
        "billing.enabled" => Some(Value::Bool(true)),
        "billing.contributor_pool_bps" => Some(Value::Number(5000.into())),
        "agent_stale_hours" => Some(Value::Number(24.into())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use serde_json::{json, Value};
    use sqlx::sqlite::SqlitePoolOptions;

    use super::{resolve_value, SettingsStore};

    #[tokio::test]
    async fn resolves_default_when_db_and_env_missing() {
        let db_values = HashMap::new();
        let resolved = resolve_value("tcb_enforcement_mode", &db_values, &|_| None);
        assert_eq!(resolved, Some(Value::String("strict".to_string())));
    }

    #[tokio::test]
    async fn resolves_env_when_db_missing() {
        let db_values = HashMap::new();
        let resolved = resolve_value("billing.enabled", &db_values, &|k| {
            if k == "CP_BILLING_ENABLED" {
                Some("false".to_string())
            } else {
                None
            }
        });
        assert_eq!(resolved, Some(Value::Bool(false)));
    }

    #[tokio::test]
    async fn resolves_db_over_env() {
        let mut db_values = HashMap::new();
        db_values.insert(
            "nonce_enforcement_mode".to_string(),
            Value::String("required".to_string()),
        );

        let resolved = resolve_value("nonce_enforcement_mode", &db_values, &|_| {
            Some("\"disabled\"".to_string())
        });
        assert_eq!(resolved, Some(Value::String("required".to_string())));
    }

    #[tokio::test]
    async fn cache_ttl_expires_and_reloads_db_values() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("pool");

        sqlx::query("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, is_secret INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
            .execute(&pool)
            .await
            .expect("create table");

        let store = SettingsStore::new_with_ttl(pool.clone(), Duration::from_millis(50));
        store
            .put("agent_stale_hours", &json!(24), false)
            .await
            .expect("put initial");

        let first = store.get("agent_stale_hours").await.expect("first");
        assert_eq!(first, json!(24));

        sqlx::query("UPDATE settings SET value = ?1 WHERE key = 'agent_stale_hours'")
            .bind("36")
            .execute(&pool)
            .await
            .expect("update");

        let cached = store.get("agent_stale_hours").await.expect("cached");
        assert_eq!(cached, json!(24));

        tokio::time::sleep(Duration::from_millis(60)).await;
        let refreshed = store.get("agent_stale_hours").await.expect("refreshed");
        assert_eq!(refreshed, json!(36));
    }
}
