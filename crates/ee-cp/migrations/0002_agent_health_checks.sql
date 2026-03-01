ALTER TABLE agents ADD COLUMN last_heartbeat_at TEXT;
ALTER TABLE agents ADD COLUMN last_attestation_ok_at TEXT;
ALTER TABLE agents ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0;
ALTER TABLE agents ADD COLUMN consecutive_successes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE agents ADD COLUMN imperfect_since TEXT;
ALTER TABLE agents ADD COLUMN last_imperfect_at TEXT;

CREATE TABLE IF NOT EXISTS app_health_checks (
    check_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    app_name TEXT NOT NULL,
    check_ok INTEGER NOT NULL,
    deployment_exempt INTEGER NOT NULL DEFAULT 0,
    failure_reason TEXT,
    checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_app_health_checks_checked_at
ON app_health_checks(checked_at);

CREATE INDEX IF NOT EXISTS idx_app_health_checks_app_checked_at
ON app_health_checks(app_name, checked_at);

CREATE INDEX IF NOT EXISTS idx_app_health_checks_app_agent_checked_at
ON app_health_checks(app_name, agent_id, checked_at);
