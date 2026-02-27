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
    verified INTEGER NOT NULL DEFAULT 0,
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
    sla_class TEXT,
    machine_size TEXT,
    cpu_vcpus INTEGER NOT NULL,
    memory_gb REAL NOT NULL,
    gpu_count INTEGER NOT NULL DEFAULT 0,
    account_id TEXT NOT NULL,
    last_charge_time TEXT,
    total_charged_cents INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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

CREATE TABLE IF NOT EXISTS app_revenue_shares (
    share_id TEXT PRIMARY KEY,
    app_name TEXT NOT NULL,
    account_id TEXT NOT NULL,
    share_bps INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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

CREATE TABLE IF NOT EXISTS transactions (
    transaction_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    balance_after_cents INTEGER NOT NULL,
    tx_type TEXT NOT NULL,
    reference_id TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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

CREATE TABLE IF NOT EXISTS capacity_pool_targets (
    target_id TEXT PRIMARY KEY,
    datacenter TEXT NOT NULL,
    node_size TEXT NOT NULL,
    min_warm_count INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    require_verified INTEGER NOT NULL DEFAULT 1,
    require_healthy INTEGER NOT NULL DEFAULT 1,
    require_hostname INTEGER NOT NULL DEFAULT 1,
    dispatch TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(datacenter, node_size)
);

CREATE TABLE IF NOT EXISTS capacity_reservations (
    reservation_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    datacenter TEXT NOT NULL,
    node_size TEXT NOT NULL,
    status TEXT NOT NULL,
    deployment_id TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS capacity_launch_orders (
    order_id TEXT PRIMARY KEY,
    datacenter TEXT NOT NULL,
    node_size TEXT NOT NULL,
    status TEXT NOT NULL,
    account_id TEXT,
    claimed_by_account_id TEXT,
    bootstrap_token_hash TEXT,
    vm_name TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
