# easyenclave v2 Rust Rewrite Plan

Status: Draft implementation plan for a full greenfield rewrite.

## 1. What We Are Building

easyenclave v2 is a full Rust rewrite of the current Python/FastAPI system.

The control plane manages Intel TDX-based agent VMs that run user workloads in attested environments. It includes:
- Agent lifecycle and attestation
- Deployment orchestration
- App catalog and image measurement
- Admin operations and cloud cleanup

## 2. Project Constraints (Locked)

These decisions are fixed for this effort:
- Greenfield build: no data migration/import from v1
- No backward compatibility requirement for v1 API/clients
- No production rollback path required (no production system exists)
- SQLite is acceptable as initial production datastore
- No SLO targets defined yet
- Staging and production infra run on GCP with real Intel TDX-capable nodes (no emulated TDX in those environments)
- Agent delete/reset authorization is account-owner based, with GitHub Actions OIDC preferred when configured
- Tunnel token persistence may remain plaintext in SQLite for now

## 3. Security Baseline (Must Be Correct)

The enclave/attestation model must be internally consistent and fail closed.

Required invariants:
1. Nonce is bound to TDX quote report data, single-use, and TTL-limited.
2. Intel Trust Authority JWT verification is strict (`iss`, `aud`, `exp`, `nbf`, signature).
3. Registration accepts only trusted `MRTD` values.
4. `RTMR` policy is explicit and enforced (`strict | warn | disabled`).
5. `TCB` policy is explicit and enforced (`strict | warn | disabled`).
6. Any verification failure or timeout rejects registration.
7. Verification decisions are audit-logged with reason codes.

## 4. Target System Scope

### 4.1 Core Functional Areas
- Agent lifecycle: challenge/register/heartbeat/status/reset/delete
- Deployments: API key + GitHub OIDC initiated deployments
- Attestation: CP quote endpoint + agent quote verification
- External apps: billing and capacity provisioning run outside CP
- App catalog: apps, versions, measurement pipeline, revenue shares
- Admin: settings, trusted MRTDs, cloudflare resources, cleanup
- Proxy/logs: request forwarding and diagnostics export

### 4.2 Data Model (10 Tables)
- `agents`
- `agent_control_credentials`
- `deployments`
- `services`
- `apps`
- `app_versions`
- `accounts`
- `settings`
- `admin_sessions`
- `trusted_mrtds`

### 4.3 Authentication Modes
- Admin session token (password and GitHub OAuth)
- Account API key (`ee_live_*`)
- Agent control credential (per-agent secret)
- GitHub Actions OIDC JWT for deployment auth

GitHub Actions OIDC deploy auth runtime knobs:
- `CP_GITHUB_OIDC_AUDIENCE` (required to enable OIDC deploy auth)
- `CP_GITHUB_OIDC_ISSUER` (default: `https://token.actions.githubusercontent.com`)
- `CP_GITHUB_OIDC_JWKS_URL` (default: `https://token.actions.githubusercontent.com/.well-known/jwks`)
- `CP_GITHUB_OIDC_JWKS_TTL_SECONDS` (default: `300`)

Health/uptime ingest runtime knobs:
- `CP_AGENT_CHECK_TOKEN` (required to enable `POST /api/agents/{agent_id}/checks`)
- `CP_HEARTBEAT_INTERVAL_SECONDS` (default: `30`; used for downtime estimate)
- `CP_CHECK_TIMEOUT_SECONDS` (default: `5`)
- `CP_DOWN_AFTER_CONSECUTIVE_FAILURES` (default: `3`)
- `CP_RECOVER_AFTER_CONSECUTIVE_SUCCESSES` (default: `2`)
- `CP_ATTESTATION_RECHECK_SECONDS` (default: `300`)
- `CP_AGENT_HEALTH_PATH` (default: `/health`)
- `CP_AGENT_ATTESTATION_PATH` (optional, empty by default)

## 5. Architecture

## 5.1 Workspace Layout

```text
easyenclave/
├── Cargo.toml
└── crates/
    ├── ee-common/
    ├── ee-attestation/
    ├── ee-cp/
    ├── ee-agent/
    └── ee-ops/
```

Dependency graph:
```text
ee-common  -> ee-attestation -> ee-cp
                            -> ee-agent
```

### 5.2 Crate Responsibilities
- `ee-common`: shared types, DTOs, config, error model, pricing primitives
- `ee-attestation`: TDX quote parsing, Intel TA JWT verification, OCI measurement
- `ee-cp`: HTTP API, stores, settings, business logic, background jobs, external integrations
- `ee-agent`: in-VM binary (agent mode + cp-bootstrap mode)
- `ee-ops`: Cargo entrypoint for CI/deploy/reproducibility/infra automation

### 5.3 Key Design Decisions
1. Keep CP focused on attestation, deploy orchestration, and auth; move billing/capacity orchestration to external apps.
2. Use Argon2 for key/session secret hashing.
3. Implement settings as DB > env > default with TTL cache.
4. Keep both deploy auth paths: API key and GitHub OIDC.
5. Run background tasks with `tokio::spawn` + cancellation tokens.

## 6. External Integrations
- Cloudflare tunnels and DNS
- GCP Compute + service account OAuth (staging + prod on real TDX-capable nodes)
- Intel Trust Authority JWKS and token verification
- GitHub OAuth (admin auth)
- GitHub OIDC JWKS (deploy auth)
- Cosign verification (subprocess)

## 7. Background Jobs
- Nonce cleanup
- Session cleanup
- Agent health checks and optional attestation refresh
- Control-plane attestation refresh
- Version measurement queue processing
- Stale agent cleanup

## 8. Implementation Plan

## Phase 0: Security Contract + Test Gates (New)
Deliverables:
- `docs/security-attestation-model.md`
- `docs/enclave-test-matrix.md`
- Error taxonomy for attestation failures and policy decisions

Tests:
- nonce reuse rejection
- nonce expiration rejection
- invalid signature rejection
- invalid claim (`aud/iss/exp/nbf`) rejection
- untrusted MRTD rejection
- TCB/RTMR policy matrix behavior

Exit criteria:
- All invariants from Section 3 codified and test-backed

## Phase 1: Workspace + ee-common
Deliverables:
- Workspace root `Cargo.toml`
- `crates/ee-common` modules for shared types, DTOs, config, errors, pricing
- CI workflow for fmt/clippy/test

Tests:
- config parsing
- pricing math
- error serialization

## Phase 2: ee-attestation TDX Quote Parsing
Deliverables:
- `tsm` module: quote generation/parsing, MRTD/RTMR/report_data extraction

Tests:
- quote fixture parsing
- offset correctness
- nonce extraction from report data

## Phase 3: ee-attestation Intel TA Verification
Deliverables:
- JWKS client with caching
- attestation token verification and claim extraction

Tests:
- valid token acceptance
- expired token rejection
- signature mismatch rejection

## Phase 4: ee-cp Skeleton (DB + Settings + Health)
Deliverables:
- CP binary skeleton
- migrations for all tables
- settings store with DB > env > default and TTL cache
- `/health` endpoint

Tests:
- app start and `/health`
- migration application
- settings resolution/TTL behavior

## Phase 5: Stores
Deliverables:
- stores for agents, deployments, accounts, apps, sessions, services

Tests:
- CRUD coverage
- deployment state transitions
- session expiry
- capacity order lifecycle

## Phase 6: Nonce + Agent Registration
Deliverables:
- challenge nonce service
- attestation policy enforcement service
- agent lifecycle routes (challenge/register/heartbeat/status/deployed/list/get/delete/reset/owner patch/console token)

Tests:
- nonce lifecycle
- registration happy path
- registration failure matrix from Phase 0
- heartbeat updates

## Phase 7: Cloudflare Tunnel Integration
Deliverables:
- tunnel create/config/delete
- DNS create/delete/list
- integration into registration and cleanup paths

Tests:
- mock CF API interactions
- tunnel token returned on register
- cleanup on agent deletion

## Phase 8: Authentication Layer
Deliverables:
- API key auth
- admin session auth
- GitHub OAuth
- GitHub OIDC
- ownership checks
- auth/account routes

Tests:
- hash/verify
- session lifecycle
- OIDC owner matching

## Phase 9: Deploy + Apps + Proxy + Owner Routes
Deliverables:
- deploy routes and assignment logic
- app/version/revenue-share routes
- measurement callback route
- proxy routes and logs routes
- owner-scoped `/me/*` routes

Tests:
- deploy + dry-run
- app version lifecycle
- proxy forwarding
- OIDC deploy ownership checks

## Phase 10: External Billing App Integration
Deliverables:
- define CP-to-billing app contract (events/API)
- remove CP-owned billing routes and background jobs
- document reference billing app integration
- define `BILLING_UNLIMITED_OWNERS` policy (default: `posix4e,easyenclave`)

Tests:
- contract payload compatibility
- deploy flow without CP billing coupling
- unlimited-owner policy checks for unset + explicit override modes

## Phase 11: GCP + Admin
Deliverables:
- admin route families
- GCP provisioning client for staging and prod real TDX nodes
- remaining background jobs

Tests:
- GCP OAuth and instance create/delete (mock + real-node smoke in staging)

## Phase 12: OCI Measurement Pipeline
Deliverables:
- image ref parser
- digest resolver
- cosign verification wrapper
- compose measurement orchestration

Tests:
- parsing
- digest resolution (mock registry)
- signature verify path and failure handling

## Phase 13: ee-agent Binary
Deliverables:
- agent mode: register, tunnel, heartbeat, deploy/undeploy server
- cp-bootstrap mode
- workload process/log management

Tests:
- registration retry
- heartbeat cycle
- deploy/undeploy flow (mock docker)
- log buffering

## Phase 14: ee-ops Cargo Automation
Deliverables:
- cargo entrypoint for lint/repro/deploy/image-bake
- remove top-level shell/python script entrypoints
- keep automation scriptable via `cargo run -p ee-ops -- ...`

Tests:
- command dispatch validation
- CI workflow parity after script path removal
- reproducibility and deploy command pass-through

## Phase 15: Image + E2E + Release Pipelines
Deliverables:
- VM image build assets
- integration suite for cp bootstrap -> agent register -> deploy
- staging/release GitHub workflows

Tests:
- full end-to-end flow with mocks where needed
- artifact build validation

## 9. Delivery Order and Parallelism

Primary dependency chain:
```text
0 -> 1 -> 2 -> 3
1 -> 4 -> 5 -> 6 -> 7 -> 9 -> 13
5 -> 8 -> 9
5 -> 10 -> 11
2/3 -> 12
1 -> 14
all major phases -> 15
```

Parallelizable:
- Phase 8 can run in parallel with 6/7 once core stores exist.
- Phase 12 can run in parallel with 8/9.
- Phase 14 can run immediately after Phase 1.

## 10. Verification and Quality Gates

Per-phase required checks:
- `cargo fmt --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

System-level gates:
1. After Phase 7: registration-to-heartbeat smoke test.
2. After Phase 10: deploy flow correctness without CP billing coupling.
3. After Phase 11: external capacity app integration test.
4. After Phase 15: full E2E workflow.

## 11. API Surface (Group Inventory)

Health and attestation:
- `/health`
- `/api/attestation`
- `/api/trusted-mrtds`

Agent lifecycle:
- challenge/register/heartbeat/status/deployed/list/get/attestation/logs/stats/delete/reset/undeploy/owner/console-access
- `/api/agents/{agent_id}/checks` (ingest health + attestation check result; deployment failures exempted)

Owner-scoped:
- `/api/me/agents*`
- `/api/me/deployments`

Deployments:
- `/api/deploy`
- `/api/deployments*`

Public reliability stats:
- `/api/stats/apps/recent?window_hours=24`
- `/api/stats/agents/recent?window_hours=24`

App catalog and shares:
- `/api/apps*`
- `/api/apps/{name}/versions*`
- `/api/apps/{name}/revenue-shares*`
- `/api/internal/measurement-callback`

Auth:
- `/admin/login`
- `/admin/logout`
- `/auth/methods`
- `/auth/github`
- `/auth/github/callback`
- `/auth/me`

Accounts:
- `/api/accounts*`

Admin and cloud operations:
- admin settings/trusted MRTDs/cloudflare/stripe/cleanup routes

Proxy and logs:
- `/api/proxy`
- `/proxy/{service}/{path}`
- control-plane/container/export log routes

## 12. Immediate Start Plan

1. Execute Phase 0 and Phase 1 first.
2. Build first vertical slice through Phase 7 before broadening feature surface.
3. Keep API shape stable only after the vertical slice is passing consistently.

## 13. Execution Tracking Docs

- [v2 phase index](docs/v2/README.md)
- [v2 cross-phase checklist](docs/v2/progress-checklist.md)
- [v2 infra decision: GCP + real TDX](docs/v2/infra-gcp-tdx.md)
- [Phase 00](docs/v2/phase-00.md)
- [Phase 01](docs/v2/phase-01.md)
- [Phase 02](docs/v2/phase-02.md)
- [Phase 03](docs/v2/phase-03.md)
- [Phase 04](docs/v2/phase-04.md)
- [Phase 05](docs/v2/phase-05.md)
- [Phase 06](docs/v2/phase-06.md)
- [Phase 07](docs/v2/phase-07.md)
- [Phase 08](docs/v2/phase-08.md)
- [Phase 09](docs/v2/phase-09.md)
- [Phase 10](docs/v2/phase-10.md)
- [Phase 11](docs/v2/phase-11.md)
- [Phase 12](docs/v2/phase-12.md)
- [Phase 13](docs/v2/phase-13.md)
- [Phase 14](docs/v2/phase-14.md)
- [Phase 15](docs/v2/phase-15.md)

This README is the canonical implementation plan for v2 unless superseded by explicit design docs in `docs/`.
