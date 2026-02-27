# easyenclave v2 Rust Rewrite Plan

Status: Draft implementation plan for a full greenfield rewrite.

## 1. What We Are Building

easyenclave v2 is a full Rust rewrite of the current Python/FastAPI system.

The control plane manages Intel TDX-based agent VMs that run user workloads in attested environments. It includes:
- Agent lifecycle and attestation
- Deployment orchestration
- Billing and ledgering
- Capacity management and launch ordering
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
- Billing: hourly charging, revenue splitting, Stripe deposit flow
- Capacity: warm pool targets, reservations, launch orders, launcher claim/update
- App catalog: apps, versions, measurement pipeline, revenue shares
- Admin: settings, trusted MRTDs, cloudflare resources, cleanup
- Proxy/logs: request forwarding and diagnostics export

### 4.2 Data Model (15 Tables)
- `agents`
- `agent_control_credentials`
- `deployments`
- `services`
- `apps`
- `app_versions`
- `app_revenue_shares`
- `accounts`
- `transactions`
- `settings`
- `admin_sessions`
- `trusted_mrtds`
- `capacity_pool_targets`
- `capacity_reservations`
- `capacity_launch_orders`

### 4.3 Authentication Modes
- Admin session token (password and GitHub OAuth)
- Account API key (`ee_live_*`)
- Launcher key (account type: launcher)
- Agent control credential (per-agent secret)
- GitHub Actions OIDC JWT for deployment auth

GitHub Actions OIDC deploy auth runtime knobs:
- `CP_GITHUB_OIDC_AUDIENCE` (required to enable OIDC deploy auth)
- `CP_GITHUB_OIDC_ISSUER` (default: `https://token.actions.githubusercontent.com`)
- `CP_GITHUB_OIDC_JWKS_URL` (default: `https://token.actions.githubusercontent.com/.well-known/jwks`)
- `CP_GITHUB_OIDC_JWKS_TTL_SECONDS` (default: `300`)

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
    └── ee-launcher/
```

Dependency graph:
```text
ee-common  -> ee-attestation -> ee-cp
                            -> ee-agent
ee-common  -> ee-launcher
```

### 5.2 Crate Responsibilities
- `ee-common`: shared types, DTOs, config, error model, pricing primitives
- `ee-attestation`: TDX quote parsing, Intel TA JWT verification, OCI measurement
- `ee-cp`: HTTP API, stores, settings, business logic, background jobs, external integrations
- `ee-agent`: in-VM binary (agent mode + cp-bootstrap mode)
- `ee-launcher`: host CLI for launching/stopping/listing TDX VMs

### 5.3 Key Design Decisions
1. Keep billing, GCP, and capacity orchestration in `ee-cp` (no premature crate split).
2. Use Argon2 for key/session secret hashing.
3. Implement settings as DB > env > default with TTL cache.
4. Keep both deploy auth paths: API key and GitHub OIDC.
5. Run background tasks with `tokio::spawn` + cancellation tokens.

## 6. External Integrations
- Cloudflare tunnels and DNS
- GCP Compute + service account OAuth (staging + prod on real TDX-capable nodes)
- Intel Trust Authority JWKS and token verification
- Stripe payment intents and webhook processing
- GitHub OAuth (admin auth)
- GitHub OIDC JWKS (deploy auth)
- Cosign verification (subprocess)

## 7. Background Jobs
- Nonce cleanup
- Session cleanup
- Agent health checks and optional attestation refresh
- Control-plane attestation refresh
- Version measurement queue processing
- Hourly charging
- Insufficient-funds terminator
- Capacity pool reconciliation
- Capacity fulfiller (GCP only)
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
- stores for agents, deployments, accounts, apps, transactions, capacity, sessions, services

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

## Phase 10: Billing + Stripe
Deliverables:
- billing service and rate card logic
- Stripe client and webhook handling
- billing routes
- charging + insufficient funds background jobs

Tests:
- charge calculation
- 70/30 split
- contributor pool distribution
- webhook verification
- insufficient-funds termination behavior

## Phase 11: Capacity + GCP + Admin
Deliverables:
- capacity and admin route families
- GCP provisioning client for staging and prod real TDX nodes
- remaining background jobs

Tests:
- capacity target/reservation/order lifecycle
- launcher claim/update flow
- GCP OAuth and instance create/delete (mock + real-node smoke in staging)
- reconciliation behavior

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

## Phase 14: ee-launcher CLI
Deliverables:
- launch/stop/list/logs commands
- qemu and OCI helpers
- preflight checks

Tests:
- arg validation
- node size parsing
- config injection round-trip

## Phase 15: Image + E2E + Release Pipelines
Deliverables:
- VM image build assets
- integration suite for launcher -> cp -> agent -> deploy
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
2. After Phase 10: deploy + billing charge cycle correctness test.
3. After Phase 11: capacity reconciliation and fulfillment integration test.
4. After Phase 15: full E2E workflow.

## 11. API Surface (Group Inventory)

Health and attestation:
- `/health`
- `/api/v1/attestation`
- `/api/v1/trusted-mrtds`

Agent lifecycle:
- challenge/register/heartbeat/status/deployed/list/get/attestation/logs/stats/delete/reset/undeploy/owner/console-access

Owner-scoped:
- `/api/v1/me/agents*`
- `/api/v1/me/deployments`

Deployments:
- `/api/v1/deploy`
- `/api/v1/deployments*`

App catalog and shares:
- `/api/v1/apps*`
- `/api/v1/apps/{name}/versions*`
- `/api/v1/apps/{name}/revenue-shares*`
- `/api/v1/internal/measurement-callback`

Auth:
- `/admin/login`
- `/admin/logout`
- `/auth/methods`
- `/auth/github`
- `/auth/github/callback`
- `/auth/me`

Accounts and billing:
- `/api/v1/accounts*`
- `/api/v1/billing/rates`
- `/api/v1/webhooks/stripe`

Capacity and launcher:
- admin target/reservation/order/reconcile routes
- account capacity request/list routes
- launcher claim/update routes

Admin and cloud operations:
- admin settings/trusted MRTDs/cloudflare/stripe/cleanup routes

Proxy and logs:
- `/api/v1/proxy`
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
