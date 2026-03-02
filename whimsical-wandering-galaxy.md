# easyenclave v2: Full-Scope Rust Rewrite

## Context

easyenclave v1 is a production Python/FastAPI system (~25k LOC) for deploying confidential workloads on Intel TDX VMs. It includes billing (Stripe), user accounts, GCP capacity management, image measurement, admin tooling, and more. This plan rewrites the entire system in Rust — all functionality ported, fresh architecture, no feature cuts. Python code stays alongside during development and is deleted at the end.

---

## Program Specification

### Overview

easyenclave is a control plane for confidential compute. It manages a fleet of Intel TDX virtual machines ("agents") that run user workloads inside hardware-attested enclaves. The system provides:

- **Agent lifecycle** — VMs self-register with cryptographic attestation, get Cloudflare tunnels for public access, send periodic heartbeats
- **Deployment** — Users deploy OCI container images to agents via GitHub Actions OIDC or API keys
- **Attestation** — TDX hardware quotes verified through Intel Trust Authority; MRTD/RTMR trust baselines enforced
- **Billing** — Hourly charging per deployment, revenue distribution to agent operators and app contributors, Stripe payments
- **Capacity** — Warm-pool targets, launch orders claimed by launcher workers, CP-native GCP provisioning
- **App catalog** — Versioned apps with OCI image measurement (digest resolution + cosign signature verification)
- **Admin** — Settings management, cloud resource cleanup, trust baseline management

### Data Model (15 tables)

| Table | PK | Purpose |
|-------|-----|---------|
| `agents` | agent_id (uuid) | Registered TDX VMs. Fields: vm_name (unique), status (undeployed/deployed/deploying), mrtd, rtmrs, attestation (JSON), tunnel_id, hostname, tunnel_token, health_status, verified, tcb_status, node_size, datacenter, github_owner, deployed_app, account_id |
| `agent_control_credentials` | agent_id | Per-agent API secret for control-channel auth |
| `deployments` | deployment_id (uuid) | Workload deployments. Fields: compose, config (JSON), agent_id, status (pending/deploying/running/failed/stopped), app_name, app_version, sla_class, machine_size, cpu_vcpus, memory_gb, gpu_count, account_id, last_charge_time, total_charged |
| `services` | service_id (uuid) | Service registry. Fields: name (unique), compose_hash, mrtd, endpoints (JSON), health_status |
| `apps` | app_id (uuid) | App catalog entries. Fields: name (unique), description, source_repo, maintainers (JSON), tags (JSON) |
| `app_versions` | version_id (uuid) | Published app versions. Fields: app_name, version, node_size, compose, image_digest, mrtd, status (pending/measured/published/rejected), ingress (JSON) |
| `app_revenue_shares` | share_id (uuid) | Revenue split rules per app. Fields: app_name, account_id, share_bps (basis points out of 10000) |
| `accounts` | account_id (uuid) | Billing accounts. Fields: name (unique), account_type (deployer/agent/contributor/launcher), api_key_hash, api_key_prefix, github_id, github_login, github_org |
| `transactions` | transaction_id (uuid) | Immutable ledger. Fields: account_id, amount, balance_after, tx_type (deposit/charge/earning/contributor_credit/platform_revenue), reference_id |
| `settings` | key (string) | DB-backed config overrides. Fields: value, is_secret |
| `admin_sessions` | session_id (uuid) | Admin login sessions. Fields: token_hash, token_prefix, expires_at, auth_method (password/github_oauth), github_login, github_orgs (JSON) |
| `trusted_mrtds` | mrtd (96-hex) | Trusted MRTD baselines. Fields: mrtd_type (agent/proxy), note |
| `capacity_pool_targets` | target_id (uuid) | Desired warm capacity. Fields: datacenter, node_size, min_warm_count, enabled, require_verified/healthy/hostname, dispatch |
| `capacity_reservations` | reservation_id (uuid) | Agent-to-pool mappings. Fields: agent_id, datacenter, node_size, status (open/consumed/released/expired), deployment_id |
| `capacity_launch_orders` | order_id (uuid) | VM provisioning orders. Fields: datacenter, node_size, status (open/claimed/provisioning/fulfilled/failed), account_id, claimed_by_account_id, bootstrap_token_hash, vm_name |

### API Endpoints

#### Health & Attestation
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | none | Liveness check with boot_id, git_sha, attestation cache, GCP config flags |
| GET | `/api/v1/attestation` | none | CP's own TDX quote (fresh or cached, optional nonce query param) |
| GET | `/api/v1/trusted-mrtds` | none | Public list of trusted MRTD baselines |

#### Agent Lifecycle
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/agents/challenge` | none | Issue nonce for registration (5-min TTL) |
| POST | `/api/v1/agents/register` | attestation | Register agent: verify Intel TA JWT, check MRTD trust, verify nonce, create CF tunnel, return agent_id + tunnel_token |
| POST | `/api/v1/agents/{id}/heartbeat` | agent-control | Push fresh attestation + status |
| POST | `/api/v1/agents/{id}/status` | agent-control | Update agent status during deployment |
| POST | `/api/v1/agents/{id}/deployed` | agent-control | Report successful workload deployment |
| GET | `/api/v1/agents` | none | List agents (filter: status, vm_name) |
| GET | `/api/v1/agents/{id}` | none | Get agent details |
| GET | `/api/v1/agents/{id}/attestation` | none | Agent attestation chain (MRTD, RTMRs, TCB) |
| GET | `/api/v1/agents/{id}/logs` | none | Proxy log pull from agent via tunnel |
| GET | `/api/v1/agents/{id}/stats` | none | Proxy system stats from agent |
| DELETE | `/api/v1/agents/{id}` | admin | Delete agent + cleanup CF tunnel |
| POST | `/api/v1/agents/{id}/reset` | admin | Reset agent to undeployed, recreate tunnel if needed |
| POST | `/api/v1/agents/{id}/undeploy` | admin | Proxy undeploy to agent, reset CP state |
| PATCH | `/api/v1/agents/{id}/owner` | admin | Set github_owner label |
| POST | `/api/v1/agents/{id}/console-access` | admin/owner | Mint short-lived console access token (900-3600s) |

#### Owner-Scoped (self-service via GitHub identity)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/me/agents` | admin-token | List agents owned by current GitHub user |
| GET | `/api/v1/me/agents/{id}` | admin-token | Get owned agent |
| POST | `/api/v1/me/agents/{id}/reset` | admin-token | Reset owned agent |
| POST | `/api/v1/me/agents/{id}/console-access` | admin-token | Console token for owned agent |
| GET | `/api/v1/me/deployments` | admin-token | List deployments on owned agents |

#### Deployments
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/deploy` | api-key/oidc | Deploy compose to agent (with preflight/dry_run). Matches owner, selects agent by datacenter/size/cloud filters |
| POST | `/api/v1/agents/{id}/undeploy` | admin | Stop workload on agent |
| GET | `/api/v1/deployments` | none | List deployments (filter: status, agent_id) |
| GET | `/api/v1/deployments/{id}` | none | Get deployment details |

#### App Catalog
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/apps` | none | Register new app |
| GET | `/api/v1/apps` | none | List apps (filter: name, tags) |
| GET | `/api/v1/apps/{name}` | none | Get app details |
| DELETE | `/api/v1/apps/{name}` | none | Delete app |
| POST | `/api/v1/apps/{name}/versions` | none | Publish version (triggers measurement) |
| GET | `/api/v1/apps/{name}/versions` | none | List versions |
| GET | `/api/v1/apps/{name}/versions/{ver}` | none | Get version |
| POST | `/api/v1/apps/{name}/versions/{ver}/attest` | admin | Manually attest version |
| POST | `/api/v1/internal/measurement-callback` | none | Receive measurement results (digest, signature, MRTD) |

#### App Revenue Shares
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/apps/{name}/revenue-shares` | none | List contributor share rules |
| POST | `/api/v1/apps/{name}/revenue-shares` | admin | Create share rule (bps, total <= 10000) |
| DELETE | `/api/v1/apps/{name}/revenue-shares/{id}` | admin | Delete share rule |

#### Authentication
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/admin/login` | password | Password login, returns 24hr session token |
| POST | `/admin/logout` | none | Invalidate session |
| GET | `/auth/methods` | none | Available auth methods (password, github_oauth) |
| GET | `/auth/github` | none | Start GitHub OAuth flow (returns auth_url + state) |
| GET | `/auth/github/callback` | oauth | Handle callback, create session, fetch user orgs |
| GET | `/auth/me` | admin-token | Current user info (login, orgs, expires_at) |

#### Billing Accounts
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/accounts` | none | Create account, return API key (one-time) |
| POST | `/api/v1/accounts/{id}/identity` | api-key | Link to GitHub identity |
| GET | `/api/v1/accounts` | admin | List accounts (filter: name, type) |
| GET | `/api/v1/accounts/{id}` | api-key | Get account + balance |
| POST | `/api/v1/accounts/{id}/api-key/rotate` | api-key | Rotate API key |
| DELETE | `/api/v1/accounts/{id}` | api-key | Delete (zero balance only) |
| POST | `/api/v1/accounts/{id}/deposit` | api-key | Manual deposit |
| GET | `/api/v1/accounts/{id}/transactions` | api-key | Transaction history (limit 200) |

#### Billing & Stripe
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/billing/rates` | none | Rate card: CPU $0.04/vCPU-hr, memory $0.005/GB-hr, GPU $0.50/hr, storage $0.10/GB-mo |
| POST | `/api/v1/accounts/{id}/payment-intent` | api-key | Create Stripe PaymentIntent |
| POST | `/api/v1/webhooks/stripe` | stripe-sig | Handle payment_intent.succeeded → deposit |

#### Capacity Management
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/admin/agents/capacity/targets` | admin | List warm-pool targets + reservation status |
| PUT | `/api/v1/admin/agents/capacity/targets` | admin | Upsert target (datacenter, size, min_warm_count, flags) |
| DELETE | `/api/v1/admin/agents/capacity/targets` | admin | Delete target (query: datacenter, node_size) |
| GET | `/api/v1/admin/agents/capacity/reservations` | admin | List reservations (filter: status) |
| GET | `/api/v1/admin/agents/capacity/orders` | admin | List launch orders (filter: status, datacenter, size) |
| POST | `/api/v1/admin/agents/capacity/reconcile` | admin | Compute shortfalls, optionally dispatch orders |
| POST | `/api/v1/accounts/{id}/capacity/request` | api-key | Purchase warm capacity (charge + create orders) |
| GET | `/api/v1/accounts/{id}/capacity/orders` | api-key | List account's launch orders |

#### Launcher Worker API
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/launchers/capacity/orders/claim` | launcher-key | Claim next open order, get bootstrap token |
| POST | `/api/v1/launchers/capacity/orders/{id}` | launcher-key | Update order (provisioning/fulfilled/failed) |

#### Admin
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/admin/settings` | admin | List settings (filter: group) |
| PUT | `/api/v1/admin/settings/{key}` | admin | Save setting to DB |
| DELETE | `/api/v1/admin/settings/{key}` | admin | Delete setting (revert to env/default) |
| GET | `/api/v1/admin/trusted-mrtds` | admin | Admin view of trusted MRTDs |
| POST | `/api/v1/admin/trusted-mrtds` | admin | Add/upsert trusted MRTD |
| DELETE | `/api/v1/admin/trusted-mrtds/{mrtd}` | admin | Remove trusted MRTD |
| GET | `/api/v1/admin/cloudflare/status` | admin | CF config status, protected tunnels |
| GET | `/api/v1/admin/cloudflare/tunnels` | admin | List CF tunnels (paginated, agent tracking) |
| DELETE | `/api/v1/admin/cloudflare/tunnels/{id}` | admin | Delete CF tunnel |
| GET | `/api/v1/admin/cloudflare/dns` | admin | List CF DNS records |
| DELETE | `/api/v1/admin/cloudflare/dns/{id}` | admin | Delete DNS record |
| GET | `/api/v1/admin/stripe/status` | admin | Stripe config check |
| POST | `/api/v1/admin/cleanup/orphans` | admin | Unified cleanup: orphaned CF tunnels, GCP instances, stale agents |
| POST | `/api/v1/admin/agents/{id}/cleanup` | admin | Single-agent cleanup: stop workload, delete tunnel, optionally delete GCP VM |

#### Proxy & Logs
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/proxy` | none | Proxy endpoint info |
| ANY | `/proxy/{service}/{path}` | none | Forward request to service via agent tunnel |
| GET | `/api/v1/logs/control-plane` | none | CP in-memory log buffer (lines, min_level) |
| GET | `/api/v1/logs/containers` | none | Docker container logs (since, container filter) |
| GET | `/api/v1/logs/export` | none | Export CP + container logs as zip |

### Authentication Model

Four auth mechanisms, used by different endpoint groups:

| Mechanism | How It Works | Used By |
|-----------|-------------|---------|
| **Admin session** | POST /admin/login with password or GitHub OAuth → 24hr token. Token hashed (bcrypt/argon2), looked up by 12-char prefix. Admin if password auth or GitHub login in ADMIN_GITHUB_LOGINS env. | Admin routes, owner-scoped /me/* routes |
| **API key** | Account creation returns `ee_live_<32char>`. Hashed, looked up by prefix. Bearer token in Authorization header. | Billing, deploy, capacity purchase |
| **Launcher key** | API key with account_type=launcher | Launch order claim/update |
| **Agent control** | Per-agent api_secret issued on registration. HMAC or bearer token. | Heartbeat, status, deployed callbacks |
| **GitHub OIDC** | JWT from GitHub Actions, verified against `https://token.actions.githubusercontent.com/.well-known/jwks`. Ownership matched via `repository_owner` claim. | Deploy endpoint (alternative to API key) |

### Billing Logic

**Hourly charging (background task, every 1 hour):**
1. For each running deployment: `cost = cpu_vcpus × $0.04 + memory_gb × $0.005 + gpu_count × $0.50`
2. Charge deployer account (create transaction, update balance)
3. If balance < 0: mark deployment `insufficient_funds`
4. Revenue split: 70% to agent operator account, 30% to platform
5. Platform 30% further split: `contributor_pool_bps/10000` to app maintainers (proportional to share_bps), remainder to platform account

**Insufficient funds terminator (background, every 5 min):**
- Deployments marked `insufficient_funds` → call agent API to stop workload → set status=stopped

**Stripe integration:**
- `POST /api/v1/accounts/{id}/payment-intent` → Stripe PaymentIntent with metadata={account_id}
- Stripe webhook `payment_intent.succeeded` → deposit funds to account

### Settings System

40+ settings with 3-tier resolution: **DB value > environment variable > default**.

In-memory cache with 5-second TTL. Settings grouped by: cloudflare, github_oauth, stripe, intel_ta, operational, provisioner, auth, billing.

Key operational settings:
- `tcb_enforcement_mode` (strict/warn/disabled) — Intel TCB status enforcement
- `nonce_enforcement_mode` (required/optional/disabled) — replay prevention
- `rtmr_enforcement_mode` (strict/warn/disabled) — RTMR drift detection
- `signature_verification_mode` (strict/warn/disabled) — cosign image signature
- `agent_stale_hours` (24) — hours before silent agent is deleted
- `billing.enabled` (true) — master billing switch
- `billing.contributor_pool_bps` (5000) — 50% of platform revenue to contributors

### Background Tasks

| Task | Interval | What It Does |
|------|----------|-------------|
| Nonce cleanup | 1 min | Purge expired nonces from in-memory DashMap |
| Session cleanup | 1 hour | Delete expired admin sessions from DB |
| Agent health checker | 30 sec | Pull /api/health from agents via tunnel; optionally pull fresh attestation every 1hr |
| CP attestation refresh | 5 min | Generate fresh TDX quote via configfs-tsm, cache it |
| Version measurement | 30 sec | Process pending app versions: resolve OCI digests, verify cosign signatures, extract MRTD |
| Hourly charging | 1 hour | Charge all running deployments, distribute revenue |
| Insufficient funds terminator | 5 min | Stop deployments with insufficient_funds status |
| Capacity pool reconciler | 30 sec | Compare warm targets vs eligible agents, create launch orders for shortfalls |
| GCP capacity fulfiller | 5 sec | Claim open GCP orders, provision instances via Compute API, reap stale fulfilled orders |
| Stale agent cleanup | periodic | Delete agents silent > agent_stale_hours |

### External Service Integrations

#### Cloudflare (tunnel + DNS management)
- `POST /accounts/{acct}/cfd_tunnel` — create tunnel with secret, get token
- `GET /accounts/{acct}/cfd_tunnel/{id}/token` — retrieve tunnel bearer token
- `PUT /accounts/{acct}/cfd_tunnel/{id}/configurations` — set ingress routing rules
- `DELETE /accounts/{acct}/cfd_tunnel/{id}` — delete tunnel
- `DELETE /accounts/{acct}/cfd_tunnel/{id}/connections` — clear active connections
- `POST /zones/{zone}/dns_records` — create CNAME `agent-{id}.domain` → `{tunnel_id}.cfargotunnel.com`
- `GET /zones/{zone}/dns_records` — list DNS records
- `DELETE /zones/{zone}/dns_records/{id}` — remove CNAME
- `GET /accounts/{acct}/cfd_tunnel` — list tunnels (paginated)

#### GCP Compute
- `POST /projects/{p}/zones/{z}/instances` — create TDX VM with cloud-init (embeds launcher config)
- `DELETE /projects/{p}/zones/{z}/instances/{name}` — delete VM
- `GET /projects/{p}/aggregated/instances` — list across zones (filtered by `easyenclave:managed` label)
- `POST https://oauth2.googleapis.com/token` — exchange SA JWT for bearer token (1hr)

#### Intel Trust Authority
- JWKS endpoint: `GET https://portal.trustauthority.intel.com/certs`
- JWT verification: decode attestation token, verify signature against JWKS, extract claims (tdx_mrtd, tcb_status, rtmrs)

#### Stripe
- `POST /v1/payment_intents` — create payment intent
- Webhook: `payment_intent.succeeded` — verify signature, deposit funds
- `GET /v1/balance` — health check / credential validation

#### GitHub OAuth
- `POST https://github.com/login/oauth/access_token` — exchange code for token
- `GET https://api.github.com/user` — fetch user profile
- `GET https://api.github.com/user/orgs` — fetch user orgs

#### GitHub Actions OIDC
- `GET https://token.actions.githubusercontent.com/.well-known/jwks` — JWKS for JWT verification
- Claims used: `repository_owner` (matched against agent github_owner label)

#### Cosign (subprocess)
- `cosign verify --certificate-oidc-issuer <issuer> --certificate-identity-regexp <regex> <image@digest>` — keyless OIDC signature verification

#### External Provisioner (webhook)
- `POST {provisioner.webhook_url}` — dispatch VM provisioning request
- `GET {provisioner.inventory_url}` — fetch cloud resource inventory
- `POST {provisioner.cleanup_url}` — request resource cleanup

### Agent Binary (ee-agent)

Two mutually exclusive modes determined by config:

**Agent mode (default):**
1. Read config from kernel cmdline / config.json (cp_url, bootstrap_token, node_size, datacenter, owner)
2. `GET /api/v1/agents/challenge` → receive nonce
3. Write nonce into TDX report data via configfs-tsm → get TDX quote
4. Submit quote to Intel Trust Authority → get signed JWT
5. `POST /api/v1/agents/register` with JWT + measurements → get agent_id, tunnel_token, hostname
6. Start cloudflared with tunnel_token (persist to `/data/ee-agent/tunnel_token` for reboot)
7. Start HTTP server on port 8081
8. Begin periodic heartbeat with fresh attestation (every 1 hour)
9. Wait for deploy commands via `/api/deploy`

**CP-bootstrap mode:**
1. Pull pre-built CP image from GHCR
2. Run docker-compose with CP service, passing through all env vars
3. Start cloudflared with pre-configured tunnel token
4. Skip registration (this VM IS the CP)

**Agent HTTP endpoints:**
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/health` | none | Status + optional fresh attestation (`?attest=true`) |
| GET | `/api/logs` | token/cp-auth | Container logs (since, container filter) |
| GET | `/api/stats` | token/cp-auth | System stats |
| POST | `/api/deploy` | token/cp-auth | Deploy docker-compose workload |
| POST | `/api/undeploy` | token/cp-auth | Stop workload |

**Subprocess management:**
- cloudflared: managed lifecycle, restart on crash
- Workload: `docker compose up -d` / `docker compose down`
- Log capture: ring buffer of stdout/stderr from workload containers

### Launcher CLI (ee-launcher)

Host-side CLI for QEMU/KVM TDX VM management:

```
ee launch <image> [--cp] [--owner github:org/name] [--node-size tiny|standard|llm] [--cp-url URL]
ee stop <vm-id>
ee list
ee logs <vm-id>
```

- Boots QEMU/KVM VMs with TDX support
- Injects config via kernel cmdline (owner, cp-url, node-size, datacenter)
- Node size presets: tiny (4GB/4CPU), standard (16GB/16CPU), llm (configurable)
- OCI image extraction via skopeo/podman
- Preflight: verifies QGS/attestation infrastructure is healthy
- Fire-and-forget: exits after VM boot

### Key Data Flows

**1. Agent Registration:**
```
Agent                          CP                           Cloudflare
  │ GET /agents/challenge ──→  │                              │
  │ ←── nonce (5-min TTL)      │                              │
  │                            │                              │
  │ [write nonce to TDX quote] │                              │
  │ [submit quote to Intel TA] │                              │
  │                            │                              │
  │ POST /agents/register ──→  │ verify JWT (JWKS)            │
  │   {intel_ta_token,         │ check MRTD in trust list     │
  │    vm_name, node_size}     │ verify nonce consumed        │
  │                            │ check TCB status             │
  │                            │ POST create tunnel ────────→ │
  │                            │ POST create DNS CNAME ─────→ │
  │                            │ ←── tunnel_token             │
  │ ←── {agent_id,             │                              │
  │      tunnel_token,         │                              │
  │      hostname}             │                              │
  │                            │                              │
  │ [start cloudflared]        │                              │
```

**2. Deploy via GitHub Actions:**
```
GH Action                      CP                           Agent
  │ [mint OIDC JWT]            │                              │
  │ POST /deploy ────────────→ │ verify JWT (GitHub JWKS)     │
  │   {compose, node_size,     │ extract repository_owner     │
  │    Authorization: Bearer}  │ match owner → agent          │
  │                            │ select eligible agent        │
  │                            │ POST /api/deploy ──────────→ │
  │                            │                              │ docker compose up
  │                            │ ←── deployment_id            │
  │ ←── {deployment_id,        │                              │
  │      agent_id, status}     │                              │
```

**3. Hourly Billing:**
```
Background Task                 DB
  │ SELECT running deployments → │
  │ For each:                    │
  │   cost = cpu×0.04 + mem×0.005 + gpu×0.50
  │   INSERT transaction (charge deployer) → │
  │   INSERT transaction (earning to agent 70%) → │
  │   INSERT transaction (contributor credits) → │
  │   INSERT transaction (platform revenue) → │
  │   UPDATE deployment.last_charge_time → │
```

---

## Workspace Structure

5 crates. Billing, GCP, and measurement stay inside `ee-cp` as modules — they're tightly coupled to CP state/stores and nothing else reuses them.

```
easyenclave/
├── Cargo.toml                        # workspace
├── crates/
│   ├── ee-common/                    # shared types, config, error, DTOs, pricing
│   ├── ee-attestation/               # TDX quote parsing, Intel TA JWKS, OCI measurement
│   ├── ee-cp/                        # control plane (axum + SQLite)
│   │   └── src/
│   │       ├── main.rs
│   │       ├── state.rs              # AppState
│   │       ├── db.rs                 # SQLite schema (sqlx migrations)
│   │       ├── stores/               # data access: agent, deployment, account, app,
│   │       │                         #   capacity, transaction, session, service, setting, mrtd
│   │       ├── routes/               # HTTP handlers: health, agents, deploy, apps, auth,
│   │       │                         #   accounts, billing, admin, admin_cloud, capacity, proxy
│   │       ├── auth/                 # api_key, admin_session, github_oidc, github_oauth, ownership
│   │       ├── services/             # billing, tunnel (CF), nonce, attestation, provisioner,
│   │       │                         #   gcp, stripe
│   │       └── background/           # health_checker, stale_cleanup, nonce_cleanup, session_cleanup,
│   │                                 #   charging, insufficient_funds, capacity_pool,
│   │                                 #   capacity_fulfiller, measurement, cp_attestation
│   ├── ee-agent/                     # TDX VM agent binary (agent + cp-bootstrap modes)
│   └── ee-launcher/                  # host CLI: launch/stop/list/logs (QEMU/KVM)
```

**Dependency graph:**
```
ee-common  →  ee-attestation  →  ee-cp
                               →  ee-agent
ee-common  →  ee-launcher
```

## Key Design Decisions

1. **5 crates, not more.** Billing/GCP/measurement are ee-cp modules. They share stores and AppState — extracting them would require trait abstractions for 6+ stores with zero reuse elsewhere.

2. **Argon2 over bcrypt** for API key/password hashing. Better Rust ecosystem support, OWASP-recommended. No migration compatibility needed (clean rewrite).

3. **Settings system ported faithfully.** DB > env > default resolution with 5s TTL cache. All 40+ settings from v1. Uses `Arc<RwLock<HashMap>>` in-memory cache with background refresh.

4. **Both auth models coexist.** v1 accounts + API keys AND GitHub Actions OIDC.

5. **Background tasks as tokio::spawn** with `CancellationToken` for graceful shutdown. 10 background loops total.

6. **OCI measurement in ee-attestation** (not ee-cp) — it's about trust establishment, conceptually alongside TDX quotes. The compose-level orchestration stays in ee-cp.

## Implementation Phases

### Phase 1: Workspace + ee-common (Small)
Create Cargo workspace root. ee-common with all shared types.

**Create:**
- `Cargo.toml` (workspace)
- `crates/ee-common/` — `types.rs` (all 15 DB model structs from `app/db_models.py`), `api.rs` (60+ request/response DTOs from `app/models.py`), `config.rs` (CpConfig, AgentConfig, LauncherConfig from env), `error.rs` (AppError → axum IntoResponse), `pricing.rs` (rate cards, revenue split from `app/pricing.py`)
- `.github/workflows/ci.yml` — `cargo fmt --check`, `cargo clippy`, `cargo test`

**Tests:** config parsing, pricing calc, error serialization
**Replaces:** `app/db_models.py` (types), `app/models.py`, `app/pricing.py`

---

### Phase 2: ee-attestation — TDX Quotes (Small)
Binary TDX quote parsing from configfs-tsm.

**Create:**
- `crates/ee-attestation/` — `tsm.rs` (parse_quote, extract_mrtd/rtmrs/report_data, generate_tdx_quote)

**Tests:** quote parsing with pre-recorded binary data, MRTD extraction at correct offsets, report_data nonce recovery
**Replaces:** quote parsing from `infra/launcher/launcher.py`, parts of `app/attestation.py`

---

### Phase 3: ee-attestation — Intel TA JWKS (Small)
Verify Intel Trust Authority JWT attestation tokens.

**Create:**
- `crates/ee-attestation/src/ita.rs` — verify_attestation_token, extract claims, JWKS client with cache

**Tests:** JWT verify with mock JWKS (wiremock), claim extraction, expired token rejection
**Replaces:** `app/ita.py`

---

### Phase 4: ee-cp Skeleton — DB + Settings + Health (Medium)
Minimal running CP binary with SQLite, the full settings system, and /health.

**Create:**
- `crates/ee-cp/` — `main.rs`, `state.rs`, `db.rs` (all 15 tables as sqlx migrations), `stores/setting.rs` (DB > env > default with TTL cache, all 40+ settings), `stores/trusted_mrtd.rs`, `routes/health.rs`

**Tests:** server starts + /health 200, migrations run, settings resolution order, TTL cache
**Replaces:** `app/database.py`, `app/settings.py`, health from `app/main.py`

---

### Phase 5: ee-cp Stores (Medium)
All remaining data access stores.

**Create:**
- `crates/ee-cp/src/stores/` — `agent.rs`, `deployment.rs`, `account.rs`, `app.rs`, `transaction.rs`, `capacity.rs`, `session.rs`, `service.rs`

**Tests:** agent CRUD round-trip, account balance from transactions, deployment status transitions, capacity order claim/fulfill lifecycle, session expiry
**Replaces:** `app/storage.py`, `app/crud.py`

---

### Phase 6: Nonce + Agent Registration (Medium)
Challenge-response nonce and agent registration flow.

**Create:**
- `services/nonce.rs` (DashMap nonce store), `services/attestation.rs` (MRTD check, TCB enforcement, nonce verify, RTMR check), `routes/agents.rs` (challenge, register, heartbeat, status, deployed, list, get, delete, reset, owner patch, console-access)

**Tests:** nonce lifecycle, registration with mock attestation, heartbeat updates, agent CRUD via API
**Replaces:** `app/nonce.py`, agent routes from `app/main.py`

---

### Phase 7: Cloudflare Tunnels (Medium)
CF API client wired into registration.

**Create:**
- `services/tunnel.rs` (create_tunnel_for_agent, update_ingress, delete_tunnel, delete_dns, list_tunnels, list_dns)

**Tests:** mock CF API (wiremock) for tunnel+DNS creation, registration returns tunnel_token, tunnel cleanup on agent delete
**Replaces:** `app/cloudflare.py`

---

### Phase 8: Auth — API Keys, Sessions, GitHub OAuth (Medium)
Account auth, admin login, GitHub OAuth, GitHub OIDC, ownership.

**Create:**
- `auth/` — `api_key.rs` (argon2), `admin_session.rs`, `github_oauth.rs`, `github_oidc.rs`, `ownership.rs`
- `routes/auth.rs`, `routes/accounts.rs`

**Tests:** API key hash/verify, session lifecycle, ownership matching, GitHub OIDC with mock JWKS, admin login
**Replaces:** `app/auth.py`, `app/oauth.py`, account routes from `app/routes_auth_billing.py`

---

### Phase 9: Deploy + Apps + Proxy (Medium)
Deployment lifecycle, app catalog, proxy, owner-scoped routes, logs/diagnostics.

**Create:**
- `routes/deploy.rs`, `routes/apps.rs` (+ revenue shares + measurement callback), `routes/proxy.rs`, `routes/owner.rs` (/me/* routes), `routes/logs.rs`

**Tests:** deploy creates record + assigns agent, preflight dry_run, app version lifecycle, proxy forwards, deploy with OIDC + ownership
**Replaces:** deploy/app/proxy routes from `app/main.py`, `app/proxy.py`, `app/routes_misc.py`

---

### Phase 10: Billing + Stripe (Medium)
Hourly charging, revenue distribution, Stripe.

**Create:**
- `services/billing.rs`, `services/stripe.rs`, `routes/billing.rs`, `background/charging.rs`, `background/insufficient_funds.rs`

**Tests:** charge calculation, 70/30 revenue split, contributor credits, insufficient funds termination, Stripe webhook verify
**Replaces:** `app/billing.py`, billing routes from `app/routes_auth_billing.py`

---

### Phase 11: Capacity + GCP + Admin (Large)
Capacity management, GCP provisioning, external provisioner, admin routes, all remaining background tasks.

**Create:**
- `routes/capacity.rs`, `routes/admin.rs`, `routes/admin_cloud.rs`
- `services/provisioner.rs`, `services/gcp.rs` (SA OAuth, Compute API, cloud-init)
- `background/` — health_checker, stale_cleanup, nonce_cleanup, session_cleanup, capacity_pool, capacity_fulfiller, cp_attestation

**Tests:** capacity target CRUD, reservation lifecycle, launch order claim/fulfill/expire, GCP OAuth (mock), GCP instance creation (mock), provisioner dispatch (mock), capacity reconciliation
**Replaces:** `app/gcp_capacity.py`, `app/provisioner.py`, `app/routes_admin_cloud.py`, background tasks from `app/main.py`

---

### Phase 12: OCI Measurement (Small)
Image digest resolution and cosign signature verification.

**Create:**
- `crates/ee-attestation/src/measurement.rs` (parse_image_ref, resolve_digest, verify_signature, measure_compose)
- `background/measurement.rs`

**Tests:** image ref parsing, digest resolution with mock registry, compose measurement e2e
**Replaces:** `app/version_measurement.py`

---

### Phase 13: ee-agent (Large)
Full agent binary — both modes.

**Create:**
- `crates/ee-agent/` — `main.rs`, `mode_agent.rs`, `mode_cp.rs`, `registration.rs`, `attestation.rs`, `tunnel.rs`, `server.rs`, `workload.rs`, `logs.rs`

**Tests:** registration retry with mock CP, heartbeat sends attestation, workload deploy/undeploy (mock docker), log buffer, cp-bootstrap starts subprocess
**Replaces:** `infra/launcher/launcher.py`

---

### Phase 14: ee-launcher CLI (Medium)
Host-side VM management CLI.

**Create:**
- `crates/ee-launcher/` — `main.rs`, `qemu.rs`, `oci.rs`, `config.rs`, `preflight.rs`

**Tests:** config injection round-trip, node size parsing, CLI arg validation
**Replaces:** `infra/tdx_cli.py`

---

### Phase 15: VM Image + E2E + Release CI (Large)
Image build, integration tests, CI/CD.

**Create:**
- `image/Dockerfile`, `image/build.sh`
- `tests/integration/` (full e2e)
- `.github/workflows/release.yml`, `.github/workflows/staging.yml`

**Replaces:** `infra/image/`, CI workflows

---

## Phase Dependencies

```
1 → 2 → 3 ─┐
1 → 4 → 5 ─┤
            ├→ 6 → 7 → 9 → 13
            │        ↗
            ├→ 8 ──┘→ 10 → 11
            └→ 12
14 requires only Phase 1
15 requires all above
```

Phases 8 and 12 can run in parallel with 6-7. Phase 14 can start any time after Phase 1.

## Verification

After each phase:
- `cargo check` — compiles
- `cargo test` — all tests pass
- `cargo clippy` — no warnings

After Phase 11 (all CP routes complete):
- Start CP in-process, run full registration + deploy cycle with mocks

After Phase 15:
- Full e2e: launcher → CP bootstrap → agent registration → deploy → verify workload reachable via tunnel

## Key Reference Files

| v2 Target | Port From |
|-----------|-----------|
| ee-common/types.rs | `app/db_models.py` (330 LOC, 15 models) |
| ee-common/api.rs | `app/models.py` (802 LOC, 60+ DTOs) |
| ee-cp/stores/ | `app/storage.py` (1789 LOC) |
| ee-cp/services/billing.rs | `app/billing.py` (444 LOC) |
| ee-cp/services/tunnel.rs | `app/cloudflare.py` (510 LOC) |
| ee-cp/services/gcp.rs | `app/gcp_capacity.py` (739 LOC) |
| ee-cp/auth/ | `app/auth.py` (306 LOC) + `app/oauth.py` (166 LOC) |
| ee-cp/routes/ | `app/main.py` (4345 LOC) + `app/routes_*.py` (~1800 LOC) |
| ee-cp/stores/setting.rs | `app/settings.py` (611 LOC, 40+ settings) |
| ee-attestation/measurement.rs | `app/version_measurement.py` (290 LOC) |
| ee-agent | `infra/launcher/launcher.py` (3070 LOC) |
| ee-launcher | `infra/tdx_cli.py` (1670 LOC) |
