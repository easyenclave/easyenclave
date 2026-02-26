# easyenclave v2: Rust Rewrite Plan

## Context

easyenclave v1 is a Python/FastAPI system (~55k lines) for deploying confidential workloads on Intel TDX VMs. It works but has grown organically. v2 is a ground-up Rust rewrite targeting an internet-scale confidential compute network with a radically simpler architecture:

- **No billing** -- replaced by ownership (label matching)
- **No user accounts/API keys** -- GitHub Actions OIDC for auth
- **No docker-compose translation** -- one OCI image per VM
- **Stateless CP** -- DB is cache, rebuilt from agent re-registration
- **Self-contained VMs** -- agent+cloudflared+workload all inside TDX VM
- **Fire-and-forget launcher** -- CLI tool, not a daemon

## Architecture

```
Launcher CLI (host)              TDX VM (self-contained)
┌──────────────────┐            ┌─────────────────────────────┐
│ ee launch <img>  │ ──boot──> │ supervisord                  │
│ ee stop <vm-id>  │           │   ├─ ee-agent (Rust)         │
│ ee list          │           │   │   ├─ registers with CP   │
│                  │           │   │   ├─ periodic attestation │
│ Exits after boot │           │   │   └─ serves logs/health  │
└──────────────────┘           │   ├─ cloudflared             │
                               │   │   └─ tunnel to CF edge   │
                               │   └─ workload (OCI image)    │
                               │                              │
                               │ Boots on host reboot (systemd│
                               │ Logs via serial console      │
                               └─────────────────────────────┘
```

**The CP is itself a workload on an agent.** The same TDX VM image runs everything:

```
Bootstrap: ee launch --cp <cp-image> --cf-tunnel-token <token>

┌─────────── TDX VM (CP instance) ──────────┐
│ supervisord                                │
│   ├─ ee-agent (--mode cp-bootstrap)        │
│   │   └─ skips registration (it IS the CP) │
│   ├─ ee-cp (the control plane binary)      │
│   ├─ cloudflared (pre-configured tunnel)   │
│   └─ (no separate workload)                │
└────────────────────────────────────────────┘

Then regular agents register with this CP:

┌─────────── TDX VM (workload agent) ───────┐
│ supervisord                                │
│   ├─ ee-agent (--mode agent)               │
│   │   └─ registers with CP, gets tunnel    │
│   ├─ cloudflared (tunnel from CP)          │
│   └─ workload (OCI image)                  │
└────────────────────────────────────────────┘
```

The CP is attested just like any other agent -- its MRTD is verifiable.
Agents can optionally verify CP attestation on deploy commands.

## Key Flows

### CP Bootstrap
1. CP requires being launched for launched with secrets for CF and Github oauth
2. `ee launch --cp <cp-image> --owner github:org/easyenclave --dns easyenclave.com` # with those defaults
3. VM boots, supervisord starts ee-agent in `cp-bootstrap` mode
4. Agent starts ee-cp binary as its workload (instead of registering with an external CP)
5. Agent creates tunnel token using cf creds
6. CP is now online, attested, and reachable via its Cloudflare tunnel
7. Other agents can now register with this CP

### Agent Registration
1. VM boots, supervisord starts ee-agent in `agent` mode
2. Agent: `GET /api/v1/agents/challenge?vm_name=X` → gets nonce
3. Agent: writes nonce into TDX quote via configfs-tsm
4. Agent: submits quote to Intel Trust Authority → gets signed JWT
5. Agent: `POST /api/v1/agents/register` with JWT + measurements + owner label
6. CP: verifies JWT (via Intel TA JWKS), checks MRTD, verifies nonce
7. CP: creates Cloudflare tunnel via CF API
8. CP: returns `{agent_id, tunnel_token, hostname}`
9. Agent: starts `cloudflared tunnel run --token <token>`
10. Agent: begins periodic heartbeat with fresh attestation

### App Publish (from GitHub Actions)
1. GH Action builds OCI image, measures MRTD (reproducible build)
2. GH Action mints OIDC JWT
3. GH Action: `POST /api/v1/apps` with `Authorization: Bearer <jwt>` + image ref + MRTD + metadata
4. CP: verifies JWT, records app in catalog with publisher identity
5. App is now in the public catalog, browsable by anyone

### Deploy (from GitHub Actions)
1. GH Action mints OIDC JWT (contains org/repo claims)
2. GH Action: `POST /api/v1/deploy` with `Authorization: Bearer <jwt>` + app name (from catalog)
3. CP: verifies JWT against GitHub JWKS
4. CP: looks up app in catalog, gets image ref + expected MRTD
5. CP: matches `repository_owner` against agent's `owner` label (deployer must own the agent)
6. CP: forwards deploy request to matched agent via its tunnel
7. Agent: pulls OCI image, runs workload
8. On next heartbeat: CP verifies running workload's MRTD matches the published app measurement

### Auth Model
- **CI deploys**: GitHub Actions OIDC tokens (zero-secret, JWT verified against `https://token.actions.githubusercontent.com/.well-known/jwks`)
- **Agent ownership**: launcher sets `--owner github:org/mycompany` at boot
- **Matching**: CP checks `jwt.repository_owner == agent.owner` (after stripping prefix)
- **Anti-spam**: in-memory rate limit per identity (max agents per owner)
- **No accounts, no API keys, no sessions, no DB auth state**

### Tunnel Model
- CP holds CF API credentials (account-level)
- CP creates tunnel + DNS on agent registration
- Returns scoped `tunnel_token` to agent (agent has zero CF API access)
- Agent runs `cloudflared tunnel run --token <token>`
- Agent persists token to `/data/ee-agent/tunnel_token` for reboot resilience

## Rust Workspace Structure

```
easyenclave/
├── Cargo.toml                      # workspace
├── crates/
│   ├── ee-common/                  # shared types, config, HTTP helpers
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── types.rs            # Agent, AgentStatus, HealthStatus
│   │       ├── api.rs              # request/response DTOs (agents, apps, deploy)
│   │       ├── config.rs           # env-based config (CpConfig, AgentConfig)
│   │       └── error.rs            # AppError
│   │
│   ├── ee-attestation/             # TDX + Intel TA (shared by CP and agent)
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── tsm.rs              # configfs-tsm quote generation + parsing
│   │       └── ita.rs              # Intel TA JWT verify (JWKS) + mint
│   │
│   ├── ee-cp/                      # control plane binary
│   │   └── src/
│   │       ├── main.rs
│   │       ├── state.rs            # AppState: in-memory registry, SQLite, config
│   │       ├── db.rs               # SQLite cache schema (sqlx)
│   │       ├── routes/
│   │       │   ├── mod.rs
│   │       │   ├── health.rs       # GET /health
│   │       │   ├── agents.rs       # register, heartbeat, list, get
│   │       │   ├── deploy.rs       # POST /api/v1/deploy (GitHub OIDC auth, deploys catalog app)
│   │       │   └── apps.rs         # app store: publish, list, get, versions (GitHub OIDC auth)
│   │       ├── github_oidc.rs      # JWT verification against GitHub JWKS
│   │       ├── ownership.rs        # label matching logic
│   │       ├── tunnel.rs           # CF API client (create/delete tunnel+DNS)
│   │       ├── nonce.rs            # in-memory nonce store (DashMap)
│   │       ├── mrtd.rs             # trusted MRTD registry
│   │       ├── attestation.rs      # verification pipeline (wraps ee-attestation)
│   │       └── background.rs       # health scraping, stale cleanup, nonce expiry
│   │
│   ├── ee-agent/                   # agent binary (runs inside TDX VM)
│   │   └── src/
│   │       ├── main.rs             # two modes: agent | cp-bootstrap
│   │       ├── mode_agent.rs       # agent mode: attest → register → tunnel → serve
│   │       ├── mode_cp.rs          # cp-bootstrap mode: start ee-cp + cloudflared
│   │       ├── registration.rs     # challenge + register with retry
│   │       ├── attestation.rs      # periodic TDX quote gen + push
│   │       ├── tunnel.rs           # cloudflared subprocess management
│   │       ├── server.rs           # axum: /api/deploy, /api/health, /api/logs
│   │       ├── workload.rs         # OCI image pull + run (podman/runc)
│   │       └── logs.rs             # capture + serve workload stdout/stderr
│   │
│   └── ee-launcher/                # host-side CLI (baremetal)
│       └── src/
│           ├── main.rs             # clap: launch [--cp], stop, list, logs
│           ├── qemu.rs             # QEMU/KVM TDX VM boot
│           ├── oci.rs              # OCI image → rootfs extraction
│           ├── config.rs           # kernel cmdline config injection
│           └── preflight.rs        # verify healthy QGS/attestation infra
│
├── image/                          # VM image build (fresh, not mkosi)
│   ├── Dockerfile                  # multi-stage: build agent, package VM
│   └── build.sh
│
├── tests/
│   └── integration/
│       └── cp_agent_e2e.rs         # full registration + deploy cycle with mocks
│
└── .github/
    └── workflows/
        └── ci.yml                  # fmt, clippy, test
```

## Crate Dependency Graph

```
ee-common          (no ee-* deps)
    ↑
ee-attestation     (depends on: ee-common)
    ↑
ee-cp              (depends on: ee-common, ee-attestation)
ee-agent           (depends on: ee-common, ee-attestation)
ee-launcher        (depends on: ee-common)
```

## Key Dependencies

| Crate | Purpose |
|-------|---------|
| axum 0.8 | HTTP framework (CP + agent) |
| tokio | async runtime |
| sqlx (sqlite) | CP cache database |
| reqwest (rustls) | HTTP client (CF API, Intel TA, GitHub JWKS) |
| jsonwebtoken | JWT verify (Intel TA, GitHub OIDC) |
| clap | CLI (launcher) |
| serde/serde_json | serialization |
| tracing | logging |
| dashmap | concurrent nonce store |
| wiremock | test mocks for CF/ITA/GitHub APIs |

## CP Route Map

```
GET  /health                              # liveness

# Agent management
GET  /api/v1/agents/challenge             # nonce for registration
POST /api/v1/agents/register              # agent self-registration
POST /api/v1/agents/{id}/heartbeat        # attestation + status push
GET  /api/v1/agents                       # list all agents (public catalog)
GET  /api/v1/agents/{id}                  # single agent details
GET  /api/v1/agents/{id}/logs             # proxy to agent log endpoint

# App store (public catalog)
POST /api/v1/apps                         # publish app (GitHub OIDC auth)
GET  /api/v1/apps                         # list all published apps
GET  /api/v1/apps/{name}                  # app details + versions
POST /api/v1/apps/{name}/versions         # publish new version (GitHub OIDC auth)

# Deploy / undeploy (GitHub OIDC auth, deploys catalog apps to owned agents)
POST /api/v1/deploy                       # deploy app to an owned agent
POST /api/v1/agents/{id}/undeploy         # undeploy from agent
```

## SQLite Schema (cache only, reconstructable)

```sql
CREATE TABLE agents (
    agent_id TEXT PRIMARY KEY,
    vm_name TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'undeployed',
    mrtd TEXT NOT NULL,
    hostname TEXT,
    tunnel_id TEXT,
    current_app TEXT,              -- name of deployed app (references apps.name)
    current_image TEXT,
    owner TEXT,
    node_size TEXT NOT NULL,
    datacenter TEXT NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    tcb_status TEXT,
    registered_at TEXT NOT NULL,
    last_heartbeat TEXT NOT NULL
);

CREATE TABLE trusted_mrtds (
    mrtd TEXT PRIMARY KEY,
    mrtd_type TEXT NOT NULL,  -- 'agent' or 'proxy'
    note TEXT DEFAULT ''
);

CREATE TABLE apps (
    name TEXT PRIMARY KEY,         -- unique app name (e.g., "my-web-app")
    description TEXT DEFAULT '',
    publisher TEXT NOT NULL,        -- GitHub identity who published (org or user)
    source_repo TEXT,               -- GitHub repo (e.g., "org/repo")
    created_at TEXT NOT NULL
);

CREATE TABLE app_versions (
    version_id TEXT PRIMARY KEY,
    app_name TEXT NOT NULL REFERENCES apps(name),
    version TEXT NOT NULL,          -- semver or tag (e.g., "1.2.3", "latest")
    image TEXT NOT NULL,            -- OCI image ref (e.g., "ghcr.io/org/app:v1.2.3")
    mrtd TEXT NOT NULL,             -- expected MRTD measurement for this image
    node_size TEXT,                 -- recommended node size
    published_at TEXT NOT NULL,
    UNIQUE(app_name, version)
);
```

## GitHub Secrets & Variables (existing, to incorporate)

### Secrets used in v2
| Secret | Used by | Purpose |
|--------|---------|---------|
| `CLOUDFLARE_ACCOUNT_ID` | ee-cp config, CI | CF tunnel management |
| `CLOUDFLARE_API_TOKEN` | ee-cp config, CI | CF API auth |
| `CLOUDFLARE_ZONE_ID` | ee-cp config, CI | DNS zone for tunnel CNAMEs |
| `INTEL_API_KEY` / `ITA_API_KEY` | ee-agent, CI | Intel Trust Authority attestation |
| `GCP_PROJECT_ID` | CI (PR e2e, prod deploy) | GCP project for TDX VMs |
| `GCP_SERVICE_ACCOUNT_KEY` | CI (PR e2e, prod deploy) | GCP API auth |
| `PRODUCTION_GCP_PROJECT_ID` | CI (prod deploy) | Production GCP project |
| `PRODUCTION_GCP_SERVICE_ACCOUNT_KEY` | CI (prod deploy) | Production GCP auth |
| `CP_HOST` | CI (prod deploy, e2e) | Control plane URL |
| `STRIPE_SECRET_KEY` | examples/billing-app | Optional pay-for-capacity example |
| `STRIPE_WEBHOOK_SECRET` | examples/billing-app | Stripe webhook verification |

### Variables used in v2
| Variable | Purpose |
|----------|---------|
| `EE_GCP_SOURCE_IMAGE_FAMILY` | VM image to boot for agents |
| `EE_GCP_SOURCE_IMAGE_PROJECT` | GCP project holding agent images |
| `EE_GCP_CONFIDENTIAL_BASE_IMAGE_*` | Base image for TDX VM builds |

### Secrets NOT used in v2 (v1-only, will be removed later)
`ADMIN_GITHUB_LOGINS`, `AGENT_ADMIN_PASSWORD`, `CP_ADMIN_PASSWORD`, `CP_DEPLOYER_ACCOUNT_ID`, `CP_DEPLOYER_API_KEY`, `EE_GITHUB_OAUTH_*`, `STAGING_*`, `AZURE_*`, `PRODUCTION_AGENT_SECRET`, `STAGING_AGENT_SECRET`

## Billing Model

Billing is **not** in the CP. It's an example app that runs on top of the network:
- Anyone can deploy the billing example on their own agents
- Users pay via Stripe to get capacity assigned to their GitHub identity
- The CP only knows about ownership labels — billing is orthogonal
- Lives in `examples/billing-app/` (not in ee-cp crate)

## CI/CD Model

Three workflows, no staging environment — PR _is_ staging:

### 1. `ci.yml` — On every push (any branch)
- `cargo fmt --check`, `cargo clippy`, `cargo test`
- Build all binaries (release mode, cache with `rust-cache`)

### 2. `pr-e2e.yml` — On PR to main
- Build VM image (or use latest from `EE_GCP_SOURCE_IMAGE_FAMILY`)
- Spin up real GCP TDX VMs using `GCP_PROJECT_ID` + `GCP_SERVICE_ACCOUNT_KEY`:
  - Boot CP instance (`ee launch --cp`)
  - Boot agent instance (`ee launch`)
  - Wait for agent registration
  - Deploy example workload via GitHub OIDC
  - Verify workload reachable via CF tunnel
  - Run full e2e test suite
- Uses `CLOUDFLARE_*` secrets for real tunnel creation
- Uses `ITA_API_KEY` for real attestation
- Namespaces all resources with PR number (e.g., `ee-pr-123-cp`)
- Posts test results as PR comment

### 3. `deploy.yml` — On merge to main
- Build release binaries + VM image
- Deploy to production using `PRODUCTION_GCP_*` secrets
- Bootstrap or update CP on production
- Publish VM image to `EE_GCP_SOURCE_IMAGE_PROJECT`

### 4. `cleanup.yml` — On PR close or branch delete
- Tear down ALL GCP VMs namespaced to that PR
- Delete CF tunnels + DNS records created by the PR
- Delete any GCP images built for the PR
- Idempotent (safe to run multiple times)

## Implementation Phases

### Phase 1: Workspace + Common Types + Attestation
- Cargo.toml workspace setup
- ee-common: types, config (env-based from secrets), error types, API DTOs
- ee-attestation: TDX quote parsing (port offsets from v1 `verify.py`), Intel TA JWKS verification (port from `ita.py`), token minting
- Unit tests: quote parsing with fabricated binary data, ITA JWT decode, nonce verification
- `ci.yml` workflow: fmt, clippy, test

### Phase 2: CP Core
- ee-cp: axum server with AppState (DashMap registry + SQLite cache)
- SQLite schema (agents + trusted_mrtds + apps + app_versions), migrations
- Nonce challenge store (DashMap with TTL)
- Full attestation verification pipeline (ITA JWKS → MRTD check → TCB → nonce)
- GitHub OIDC JWT verification via JWKS
- Ownership matching (`github:org/X` vs `repository_owner`)
- Agent routes: health, challenge, register, heartbeat, list, get, logs proxy
- App store routes: publish app, list apps, get app, publish version (all GitHub OIDC auth)
- Deploy routes: deploy catalog app to owned agent (OIDC auth, verifies MRTD match), undeploy
- Cloudflare tunnel client (create/delete tunnel + DNS + ingress)
- Background tasks: nonce expiry, stale agent cleanup, health scraping
- Config reads from env vars matching the GH secrets names (`CF_ACCOUNT_ID` ← `CLOUDFLARE_ACCOUNT_ID`, etc.)
- Integration tests with wiremock: mock ITA JWKS, mock CF API, mock GitHub OIDC JWKS — full publish + registration + deploy cycle in-process

### Phase 3: Agent Binary
- ee-agent: two modes (agent / cp-bootstrap)
- Agent mode: challenge → TDX quote → ITA mint → register → cloudflared → heartbeat loop → HTTP server
- CP-bootstrap mode: start ee-cp + cloudflared (pre-configured tunnel token)
- HTTP server: /api/deploy, /api/undeploy, /api/health, /api/logs
- Workload management via podman (pull + run + log capture)
- Registration with retry + exponential backoff
- Integration test: in-process CP + agent with mocked TDX/CF, full lifecycle

### Phase 4: Launcher CLI
- ee-launcher: clap CLI (launch, stop, list, logs)
- QEMU/KVM TDX VM boot (port from `tdx_cli.py`)
- OCI image → rootfs extraction (skopeo/podman)
- Kernel cmdline config injection (owner, cp-url, node-size, cf-tunnel-token)
- Preflight checks (QEMU, KVM, TDX, podman, skopeo)
- Unit tests: config injection roundtrip

### Phase 5: VM Image
- `image/Dockerfile`: multi-stage build (compile ee-agent + ee-cp, package with cloudflared + podman + supervisord)
- dm-verity rootfs for attestation
- Supervisord config for agent mode and cp-bootstrap mode
- `image/build.sh`: build + publish to GCR

### Phase 6: CI/CD Workflows (full suite)
- `ci.yml`: fmt + clippy + test on every push
- `pr-e2e.yml`: real GCP TDX e2e on PR to main
  - Uses: `GCP_PROJECT_ID`, `GCP_SERVICE_ACCOUNT_KEY`, `CLOUDFLARE_*`, `ITA_API_KEY`, `CP_HOST`
  - Namespaces resources by PR number
  - Posts results as PR comment
- `deploy.yml`: build + deploy to prod on merge to main
  - Uses: `PRODUCTION_GCP_*`, `CLOUDFLARE_*`, `CP_HOST`
  - Publishes VM image to `EE_GCP_SOURCE_IMAGE_PROJECT`
- `cleanup.yml`: tear down PR resources on close/delete
  - Deletes GCP VMs, CF tunnels, DNS records for the PR namespace

### Phase 7: Examples
- `examples/billing-app/`: Stripe pay-for-capacity example
  - Uses `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`
  - Deploys as a regular workload on the network
  - Users pay to get capacity assigned to their GitHub identity
- `examples/hello-tdx/`: minimal example (already exists in v1)

## Verification

1. `cargo check` — all crates compile
2. `cargo test` — unit + integration tests pass (wiremock-based: full registration, attestation, deploy cycle)
3. PR to main — real GCP TDX VMs spin up, agent registers, workload deploys, tunnel works
4. Merge to main — production deployment succeeds
5. Close PR — all ephemeral resources cleaned up

## v1 Reference Files

| v2 Component | Port from v1 |
|---|---|
| ee-cp routes | `app/main.py` (registration, heartbeat, deploy) |
| ee-attestation | `app/ita.py` (JWKS verify), `app/attestation.py` (pipeline), `sdk/easyenclave/verify.py` (quote offsets) |
| ee-cp/tunnel.rs | `app/cloudflare.py` (tunnel CRUD, DNS, ingress) |
| ee-cp/nonce.rs | nonce challenge in `app/main.py` |
| ee-agent | `infra/launcher/launcher.py` (agent mode) |
| ee-launcher | `infra/tdx_cli.py` (QEMU/KVM VM management) |
| examples/billing-app | `app/billing.py` (Stripe integration) |
