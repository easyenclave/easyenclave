use std::collections::HashMap;

use chrono::Utc;
use ee_common::api::{
    RecentAgentStat, RecentAgentStatsResponse, RecentAppStat, RecentAppStatsResponse,
};
use ee_common::error::{AppError, AppResult};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

#[derive(Clone)]
pub struct HealthStore {
    pool: SqlitePool,
}

impl HealthStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert_check(
        &self,
        agent_id: Uuid,
        app_name: &str,
        check_ok: bool,
        deployment_exempt: bool,
        failure_reason: Option<&str>,
    ) -> AppResult<()> {
        sqlx::query(
            "INSERT INTO app_health_checks (check_id, agent_id, app_name, check_ok, deployment_exempt, failure_reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(agent_id.to_string())
        .bind(app_name)
        .bind(if check_ok { 1_i64 } else { 0_i64 })
        .bind(if deployment_exempt { 1_i64 } else { 0_i64 })
        .bind(failure_reason)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to insert app health check: {e}")))?;
        Ok(())
    }

    pub async fn recent_app_stats(
        &self,
        window_hours: u32,
        heartbeat_interval_seconds: u64,
    ) -> AppResult<RecentAppStatsResponse> {
        let now_unix = Utc::now().timestamp();
        let window_hours = window_hours.clamp(1, 168);
        let window_start_unix = now_unix - (window_hours as i64 * 3600);
        let sqlite_window = format!("-{} hours", window_hours);

        let rollup_rows = sqlx::query(
            "SELECT
                app_name,
                COUNT(1) AS checks_total,
                SUM(CASE WHEN check_ok = 0 AND deployment_exempt = 0 THEN 1 ELSE 0 END) AS failed_checks,
                SUM(CASE WHEN check_ok = 0 AND deployment_exempt = 1 THEN 1 ELSE 0 END) AS exempt_failures,
                MAX(CASE WHEN check_ok = 0 AND deployment_exempt = 0 THEN CAST(strftime('%s', checked_at) AS INTEGER) END) AS last_imperfect_unix
             FROM app_health_checks
             WHERE checked_at >= datetime('now', ?1)
             GROUP BY app_name
             ORDER BY app_name ASC",
        )
        .bind(sqlite_window)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to query app health rollups: {e}")))?;

        let latest_rows = sqlx::query(
            "WITH latest AS (
                SELECT app_name, agent_id, MAX(checked_at) AS max_checked
                FROM app_health_checks
                WHERE deployment_exempt = 0
                GROUP BY app_name, agent_id
             )
             SELECT
                c.app_name AS app_name,
                SUM(CASE WHEN c.check_ok = 0 THEN 1 ELSE 0 END) AS imperfect_now
             FROM app_health_checks c
             JOIN latest l
               ON l.app_name = c.app_name
              AND l.agent_id = c.agent_id
              AND l.max_checked = c.checked_at
             GROUP BY c.app_name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            AppError::External(format!("failed to query latest app health states: {e}"))
        })?;

        let mut imperfect_now_by_app: HashMap<String, u64> = HashMap::new();
        for row in latest_rows {
            let app_name: String = row
                .try_get("app_name")
                .map_err(|e| AppError::External(format!("read app_name failed: {e}")))?;
            let imperfect_now: i64 = row
                .try_get("imperfect_now")
                .map_err(|e| AppError::External(format!("read imperfect_now failed: {e}")))?;
            imperfect_now_by_app.insert(app_name, imperfect_now.max(0) as u64);
        }

        let mut apps = Vec::with_capacity(rollup_rows.len());
        for row in rollup_rows {
            let app_name: String = row
                .try_get("app_name")
                .map_err(|e| AppError::External(format!("read app_name failed: {e}")))?;
            let checks_total: i64 = row
                .try_get("checks_total")
                .map_err(|e| AppError::External(format!("read checks_total failed: {e}")))?;
            let failed_checks: i64 = row
                .try_get("failed_checks")
                .map_err(|e| AppError::External(format!("read failed_checks failed: {e}")))?;
            let exempt_failures: i64 = row
                .try_get("exempt_failures")
                .map_err(|e| AppError::External(format!("read exempt_failures failed: {e}")))?;
            let last_imperfect_unix: Option<i64> = row
                .try_get("last_imperfect_unix")
                .map_err(|e| AppError::External(format!("read last_imperfect_unix failed: {e}")))?;

            let total_checks = checks_total.max(0) as u64;
            let failed_checks = failed_checks.max(0) as u64;
            let exempt_failures = exempt_failures.max(0) as u64;
            let considered_checks = total_checks.saturating_sub(exempt_failures);
            let successful_checks = considered_checks.saturating_sub(failed_checks);
            let uptime_ratio = if considered_checks > 0 {
                successful_checks as f64 / considered_checks as f64
            } else {
                1.0
            };
            let downtime_seconds_estimate =
                failed_checks.saturating_mul(heartbeat_interval_seconds);
            let imperfect_now = *imperfect_now_by_app.get(&app_name).unwrap_or(&0);
            let perfect_now = imperfect_now == 0;
            let seconds_since_last_imperfect = last_imperfect_unix.and_then(|ts| {
                if now_unix >= ts {
                    Some((now_unix - ts) as u64)
                } else {
                    None
                }
            });

            apps.push(RecentAppStat {
                app_name,
                checks_total: total_checks,
                failed_checks,
                exempt_failures,
                imperfect_now,
                perfect_now,
                last_imperfect_unix,
                seconds_since_last_imperfect,
                downtime_seconds_estimate,
                uptime_ratio,
            });
        }

        Ok(RecentAppStatsResponse {
            window_hours,
            window_start_unix,
            window_end_unix: now_unix,
            total_apps: apps.len() as u64,
            apps,
        })
    }

    pub async fn recent_agent_stats(
        &self,
        window_hours: u32,
        heartbeat_interval_seconds: u64,
    ) -> AppResult<RecentAgentStatsResponse> {
        let now_unix = Utc::now().timestamp();
        let window_hours = window_hours.clamp(1, 168);
        let window_start_unix = now_unix - (window_hours as i64 * 3600);
        let sqlite_window = format!("-{} hours", window_hours);

        let rollup_rows = sqlx::query(
            "SELECT
                c.agent_id AS agent_id,
                a.vm_name AS vm_name,
                a.hostname AS hostname,
                COUNT(1) AS checks_total,
                SUM(CASE WHEN c.check_ok = 0 AND c.deployment_exempt = 0 THEN 1 ELSE 0 END) AS failed_checks,
                SUM(CASE WHEN c.check_ok = 0 AND c.deployment_exempt = 1 THEN 1 ELSE 0 END) AS exempt_failures,
                MAX(CASE WHEN c.check_ok = 0 AND c.deployment_exempt = 0 THEN CAST(strftime('%s', c.checked_at) AS INTEGER) END) AS last_imperfect_unix
             FROM app_health_checks c
             LEFT JOIN agents a ON a.agent_id = c.agent_id
             WHERE c.checked_at >= datetime('now', ?1)
             GROUP BY c.agent_id, a.vm_name, a.hostname
             ORDER BY c.agent_id ASC",
        )
        .bind(sqlite_window)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to query agent health rollups: {e}")))?;

        let latest_non_exempt_rows = sqlx::query(
            "WITH latest AS (
                SELECT agent_id, MAX(checked_at) AS max_checked
                FROM app_health_checks
                WHERE deployment_exempt = 0
                GROUP BY agent_id
             )
             SELECT c.agent_id AS agent_id, c.check_ok AS check_ok
             FROM app_health_checks c
             JOIN latest l
               ON l.agent_id = c.agent_id
              AND l.max_checked = c.checked_at",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            AppError::External(format!(
                "failed to query latest non-exempt agent states: {e}"
            ))
        })?;

        let latest_any_rows = sqlx::query(
            "WITH latest AS (
                SELECT agent_id, MAX(checked_at) AS max_checked
                FROM app_health_checks
                GROUP BY agent_id
             )
             SELECT c.agent_id AS agent_id, c.app_name AS app_name
             FROM app_health_checks c
             JOIN latest l
               ON l.agent_id = c.agent_id
              AND l.max_checked = c.checked_at",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to query latest agent app names: {e}")))?;

        let mut imperfect_now_by_agent: HashMap<String, bool> = HashMap::new();
        for row in latest_non_exempt_rows {
            let agent_id: String = row
                .try_get("agent_id")
                .map_err(|e| AppError::External(format!("read agent_id failed: {e}")))?;
            let check_ok: i64 = row
                .try_get("check_ok")
                .map_err(|e| AppError::External(format!("read check_ok failed: {e}")))?;
            imperfect_now_by_agent.insert(agent_id, check_ok == 0);
        }

        let mut latest_app_by_agent: HashMap<String, String> = HashMap::new();
        for row in latest_any_rows {
            let agent_id: String = row
                .try_get("agent_id")
                .map_err(|e| AppError::External(format!("read agent_id failed: {e}")))?;
            let app_name: String = row
                .try_get("app_name")
                .map_err(|e| AppError::External(format!("read app_name failed: {e}")))?;
            latest_app_by_agent.insert(agent_id, app_name);
        }

        let mut agents = Vec::with_capacity(rollup_rows.len());
        for row in rollup_rows {
            let agent_id_raw: String = row
                .try_get("agent_id")
                .map_err(|e| AppError::External(format!("read agent_id failed: {e}")))?;
            let agent_id = Uuid::parse_str(&agent_id_raw)
                .map_err(|e| AppError::External(format!("invalid agent_id uuid: {e}")))?;
            let vm_name: Option<String> = row
                .try_get("vm_name")
                .map_err(|e| AppError::External(format!("read vm_name failed: {e}")))?;
            let hostname: Option<String> = row
                .try_get("hostname")
                .map_err(|e| AppError::External(format!("read hostname failed: {e}")))?;
            let checks_total: i64 = row
                .try_get("checks_total")
                .map_err(|e| AppError::External(format!("read checks_total failed: {e}")))?;
            let failed_checks: i64 = row
                .try_get("failed_checks")
                .map_err(|e| AppError::External(format!("read failed_checks failed: {e}")))?;
            let exempt_failures: i64 = row
                .try_get("exempt_failures")
                .map_err(|e| AppError::External(format!("read exempt_failures failed: {e}")))?;
            let last_imperfect_unix: Option<i64> = row
                .try_get("last_imperfect_unix")
                .map_err(|e| AppError::External(format!("read last_imperfect_unix failed: {e}")))?;

            let total_checks = checks_total.max(0) as u64;
            let failed_checks = failed_checks.max(0) as u64;
            let exempt_failures = exempt_failures.max(0) as u64;
            let considered_checks = total_checks.saturating_sub(exempt_failures);
            let successful_checks = considered_checks.saturating_sub(failed_checks);
            let uptime_ratio = if considered_checks > 0 {
                successful_checks as f64 / considered_checks as f64
            } else {
                1.0
            };
            let downtime_seconds_estimate =
                failed_checks.saturating_mul(heartbeat_interval_seconds);
            let imperfect_now = *imperfect_now_by_agent.get(&agent_id_raw).unwrap_or(&false);
            let perfect_now = !imperfect_now;
            let seconds_since_last_imperfect = last_imperfect_unix.and_then(|ts| {
                if now_unix >= ts {
                    Some((now_unix - ts) as u64)
                } else {
                    None
                }
            });
            let app_name = latest_app_by_agent.get(&agent_id_raw).cloned();

            agents.push(RecentAgentStat {
                agent_id,
                vm_name,
                hostname,
                app_name,
                checks_total: total_checks,
                failed_checks,
                exempt_failures,
                imperfect_now,
                perfect_now,
                last_imperfect_unix,
                seconds_since_last_imperfect,
                downtime_seconds_estimate,
                uptime_ratio,
            });
        }

        Ok(RecentAgentStatsResponse {
            window_hours,
            window_start_unix,
            window_end_unix: now_unix,
            total_agents: agents.len() as u64,
            agents,
        })
    }

    pub async fn last_check_unix_for_agent(&self, agent_id: Uuid) -> AppResult<Option<i64>> {
        let ts: Option<i64> = sqlx::query_scalar(
            "SELECT CAST(strftime('%s', MAX(checked_at)) AS INTEGER)
             FROM app_health_checks
             WHERE agent_id = ?1",
        )
        .bind(agent_id.to_string())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to query last check timestamp: {e}")))?;
        Ok(ts)
    }
}
