CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    vm_name TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    mrtd TEXT,
    rtmrs TEXT,
    attestation TEXT,
    tunnel_id TEXT,
    hostname TEXT,
    tunnel_token TEXT,
    health_status TEXT,
    last_heartbeat_at TEXT,
    last_attestation_ok_at TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    consecutive_successes INTEGER NOT NULL DEFAULT 0,
    imperfect_since TEXT,
    last_imperfect_at TEXT,
    registration_state TEXT NOT NULL DEFAULT "pending",
    attestation_verified INTEGER NOT NULL DEFAULT 0,
    tcb_status TEXT,
    node_size TEXT,
    datacenter TEXT,
    github_owner TEXT,
    deployed_app TEXT,
    account_id TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS agent_control_credentials (
    agent_id TEXT PRIMARY KEY,
    api_secret_hash TEXT NOT NULL,
    api_secret_prefix TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS deployments (
    deployment_id TEXT PRIMARY KEY,
    compose TEXT NOT NULL,
    config TEXT,
    agent_id TEXT NOT NULL,
    status TEXT NOT NULL,
    app_name TEXT,
    app_version TEXT,
    cpu_vcpus INTEGER NOT NULL,
    memory_gb REAL NOT NULL,
    gpu_count INTEGER NOT NULL DEFAULT 0,
    auth_method TEXT NOT NULL DEFAULT 'api_key',
    account_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS app_health_checks (
    check_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    app_name TEXT NOT NULL,
    check_ok INTEGER NOT NULL,
    deployment_exempt INTEGER NOT NULL DEFAULT 0,
    failure_reason TEXT,
    checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS services (
    service_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    compose_hash TEXT NOT NULL,
    mrtd TEXT,
    endpoints TEXT,
    health_status TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS apps (
    app_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    source_repo TEXT,
    maintainers TEXT,
    tags TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS app_versions (
    version_id TEXT PRIMARY KEY,
    app_name TEXT NOT NULL,
    version TEXT NOT NULL,
    node_size TEXT,
    compose TEXT NOT NULL,
    image_digest TEXT,
    mrtd TEXT,
    status TEXT NOT NULL,
    ingress TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(app_name, version)
);

CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    account_type TEXT NOT NULL,
    api_key_hash TEXT,
    api_key_prefix TEXT,
    github_id TEXT,
    github_login TEXT,
    github_org TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    is_secret INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    session_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL,
    token_prefix TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    auth_method TEXT NOT NULL,
    github_login TEXT,
    github_orgs TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS trusted_mrtds (
    mrtd TEXT PRIMARY KEY,
    mrtd_type TEXT NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_github_login_unique
ON accounts(github_login COLLATE NOCASE)
WHERE github_login IS NOT NULL AND github_login <> '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_github_org_unique
ON accounts(github_org COLLATE NOCASE)
WHERE github_org IS NOT NULL AND github_org <> '';

CREATE INDEX IF NOT EXISTS idx_app_health_checks_checked_at
ON app_health_checks(checked_at);

CREATE INDEX IF NOT EXISTS idx_app_health_checks_app_checked_at
ON app_health_checks(app_name, checked_at);

CREATE INDEX IF NOT EXISTS idx_app_health_checks_app_agent_checked_at
ON app_health_checks(app_name, agent_id, checked_at);
