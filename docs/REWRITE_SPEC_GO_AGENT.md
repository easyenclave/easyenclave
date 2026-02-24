# EasyEnclave Rewrite Spec and Plan (Go Control Plane + Go Agent, No SDK, Clean-Slate)

## 1. Product Decision

- Rewrite both control plane and agent in Go.
- Keep them in one repository (single platform repo) with clean internal boundaries.
- Remove the Python SDK from product and CI paths.
- Treat user workloads as language-agnostic Docker/Compose payloads.
- Keep CI simple: one normal CI workflow, one end-to-end workflow, one release workflow.
- This is a clean-slate rewrite: legacy API/workflow compatibility is optional, not required.

This aligns with: the CP mostly orchestrates deployments on top of the agent; workload language stays unconstrained.

## 2. Scope and Non-Goals

### In scope

- CP API/server rewrite to Go.
- Agent runtime rewrite to Go.
- New v2 storage, placement, attestation, capacity, billing, deploy, and health flows.
- CI/CD simplification and script elimination.
- SDK removal.

### Out of scope

- Forcing workloads to Go.
- Rewriting every infra helper on day one.
- Feature additions outside core platform rewrite.
- Full historical data migration from legacy CP (only minimal bootstrap state is required).

## 3. Legacy Reference Surface (Non-Binding)

The following legacy endpoints are reference input for v2 design.
They are not a compatibility commitment for the rewrite.

### Agent -> CP endpoints

- `GET /api/v1/agents/challenge?vm_name=...`
- `POST /api/v1/agents/register`
- `POST /api/v1/agents/{agent_id}/heartbeat`
- `POST /api/v1/agents/{agent_id}/status`
- `POST /api/v1/agents/{agent_id}/deployed`

### CP -> Agent endpoints

- `GET /api/control/challenge`
- `POST /api/deploy`
- `POST /api/undeploy`
- `GET /api/health` and `GET /api/health?attest=true`
- `GET /api/logs`, `GET /api/stats`

### Core behavior invariants

- Registration policy: valid `node_size`/`datacenter`, drift checks, attestation validation.
- Deploy/preflight policy: deterministic placement diagnostics.
- Capacity logic: targets, reservations, launch orders.
- Measurement/signature policy modes (`strict|warn|disabled`) in v2 policy model.
- Auth and token flows can be redesigned for v2.

## 4. Target Architecture (Go Monorepo)

### 4.1 Repo shape

Repository name can be `easyenclave-go` (or keep `easyenclave` and migrate in-place):

- `cmd/control-plane/`
- `cmd/agent/`
- `cmd/eectl/` (replacement for CI scripts and operational helpers)
- `internal/controlplane/`
- `internal/agent/`
- `internal/shared/` (strictly protocol primitives, no cyclic domain coupling)
- `api/openapi/control-plane.yaml`
- `api/openapi/agent-control.yaml`
- `migrations/`

### 4.2 Control-plane boundaries

- `internal/controlplane/agents`
- `internal/controlplane/apps`
- `internal/controlplane/deploy`
- `internal/controlplane/capacity`
- `internal/controlplane/billing`
- `internal/controlplane/attestation`
- `internal/controlplane/admin`
- `internal/controlplane/storage`

### 4.3 Agent boundaries

- `internal/agent/config`
- `internal/agent/attestation`
- `internal/agent/cpclient`
- `internal/agent/server`
- `internal/agent/deploy`
- `internal/agent/workload` (Compose/docker execution)
- `internal/agent/tunnel`
- `internal/agent/platform`

### 4.4 Workload model

- Agent executes user-provided containers.
- CP stores deploy metadata/policy and selects targets.
- Workload implementation language is irrelevant (Python, Go, Node, etc.).

### 4.5 State model (DB-wipe tolerant by design)

Design rule:

- Active runtime state must not depend on durable DB correctness.
- Database is for record/history/query convenience, not liveness truth.

State classes:

- Reconstructible active state (must be rebuildable from agents):
  - online/offline and heartbeat freshness
  - current deployment on each agent
  - current health and runtime metadata
  - warm capacity currently available
- Minimal bootstrap state (must exist at CP start):
  - CP signing/verification keys
  - trusted attestation roots and policy defaults
  - bootstrap admin identity or bootstrap token
  - control-plane identity metadata (environment, cluster id)
- Durable business state (recommended outside runtime DB):
  - billing/account ledger and audit trail
  - release manifests / desired-state manifests

Implementation shape:

- Add explicit rehydration flow on CP startup:
  1. CP starts with empty DB/cache.
  2. Agents register/re-register normally.
  3. CP requests agent runtime snapshot and rebuilds placement/runtime index.
  4. CP marks cluster ready after rehydration quorum is met.
- Keep bootstrap seed in signed config bundle (`bootstrap.json` + signature), stored in secrets/object storage.
- If DB is lost, CP can rebuild runtime state from live agents and bootstrap bundle, then continue serving.
- Desired-state metadata (apps/versions/policies) should be reloadable from signed manifests so DB restore is optional for runtime recovery.

Agent contract addition for rehydration:

- Add a CP->agent snapshot endpoint (for example `GET /api/state-snapshot`) returning:
  - deployed workload id/version/image digest
  - health status
  - node metadata needed for scheduler filters
  - last heartbeat timestamp / monotonic sequence

### 4.6 Hierarchical control plane (master + datacenter CPs)

Goal:

- Scale agent health checks and attestation handling by pushing hot loops to datacenter-local CPs.
- Keep global policy, tenancy, and business control in a master CP.

Deployment mode:

- Datacenter CP is optional.
- Agents can register directly to master CP in small environments.
- Use datacenter CP when scale/load requires local aggregation (health/attestation hot loops).
- Staging can run either mode depending on test goal and scale.
- In production, support both direct and federated operation.

Roles:

- Master CP (`global`):
  - account/auth/billing/admin policy
  - global app/version catalog and desired state
  - global placement intent and rollout policy
  - receives aggregated telemetry/attestation summaries from datacenter CPs
- Datacenter CP (`dc`):
  - owns direct agent connectivity in its datacenter
  - executes challenge/register/heartbeat/status/deployed loops
  - performs local health polling and attestation verification pipeline
  - executes local scheduling decisions constrained by master policy
  - publishes summarized state/events upstream to master
  - can be specialized per provider (for example a GCP-focused aggregator)

Direct mode (no datacenter CP):

- Agents connect directly to master CP for challenge/register/heartbeat/deploy flows.
- Same functional goals apply; API details may differ in v2.

Provider operating models:

- Small provider default (managed direct):
  - No provider-managed aggregator required.
  - Agents connect to EasyEnclave-managed master CP endpoints.
- Growth path (managed federated):
  - EasyEnclave operates datacenter/regional CP layer.
  - Provider benefits from scaled health/attestation aggregation without operating extra control-plane components.
- Large provider option (self-hosted federated):
  - Provider may run datacenter CPs and federate to EasyEnclave master CP.
  - Same federation policy model as managed federated mode.

Sync model:

- Master -> datacenter:
  - signed desired-state snapshots (apps, versions, policy, rollout intent)
  - trust roots and policy bundles
- Datacenter -> master:
  - aggregated health/availability metrics
  - attestation outcomes and proofs (digest + reference, optionally full proof on demand)
  - capacity and deployment execution state

Mode selection policy (guideline):

- Start providers in managed direct mode by default.
- Move to managed federated mode when direct mode nears scaling or latency limits.
- Offer self-hosted federated mode only for providers that need local operational control.

Failure behavior:

- If master is temporarily unavailable:
  - datacenter CP continues local health/attestation/deploy reconciliation for assigned workloads.
  - datacenter CP buffers outbound state/events until master link restores.
- If a datacenter CP is unavailable:
  - master marks datacenter degraded and re-routes new placements.
  - existing workload continuity depends on agent local behavior; no global hard-stop.
- If running in direct mode, this failure class does not apply.

API boundary additions:

- Add master<->datacenter control APIs (`/api/v1/federation/...`) with mTLS + signed payloads.
- Add monotonic event sequence IDs for replay-safe aggregation.
- Keep direct-to-master and via-datacenter topologies both supported in v2.

## 5. Script and SDK Strategy

## 5.1 SDK

- Remove `sdk/` entirely after direct-HTTP replacements are documented.
- Replace examples with `curl` + minimal snippets.

## 5.2 Scripts

- Do not keep shell/python scripts as product control surface.
- Replace with:
  - `eectl` Go subcommands for reusable operations.
  - Small inline workflow shell for trivial glue.

Current script intent maps to these Go commands:

- `scripts/ci-reproducibility-check.sh` -> `eectl trust reproducibility-check`
- `scripts/ci-build-measure.sh` -> `eectl trust measure`
- `scripts/ci-deploy.sh` -> `eectl cp bootstrap`
- `scripts/deploy_action.sh` -> `eectl deploy wait-attested` and `eectl deploy run`
- `scripts/verify-tdx-clouds.sh` -> `eectl capacity verify-clouds`
- `scripts/prune_tdvirsh_vms.sh` -> `eectl vm prune`
- `scripts/gcp_bake_image.sh` -> `eectl image bake-gcp`

Local-only utilities with no production dependency should be dropped or moved to `tools/` if still needed.

## 6. Migration Plan

### Phase 0: v2 spec freeze

- Define v2 APIs and domain boundaries from first principles.
- Write black-box tests for v2 behavior and SLOs.
- Snapshot legacy semantics only where needed for rollout safety.
- Define state taxonomy: reconstructible vs bootstrap-required vs durable business state.

Exit:

- v2 API/spec and tests are approved.

### Phase 1: Go monorepo bootstrap

- Create monorepo structure and build both binaries.
- Add shared config/logging/telemetry packages.
- Add `eectl` skeleton for operational flows.

Exit:

- `go test ./...` passes.
- Core binaries and CLI build/test in clean v2 CI.

### Phase 2: Agent v2 implementation

- Implement v2 registration/heartbeat/deploy/health/log/stats behavior.
- Define v2 auth/header patterns.
- Keep only required config source compatibility (`config.json`, cmdline, config-drive) where operationally necessary.

Exit:

- v2 agent integration tests pass against v2 CP.

### Phase 3: CP v2 implementation

- Implement CP v2 domains incrementally behind v2 tests:
  1. agents + auth
  2. apps/versions/measurement
  3. deploy/preflight
  4. capacity/launch orders
  5. billing/admin/cloud ops
- Run shadow/canary validation for rollout risk control (not strict legacy parity).
- Implement startup rehydration and DB-empty recovery before production canary.
- Introduce federation interfaces so CP can run in single-node mode first, then master+datacenter mode.

Exit:

- Go CP passes v2 suite and e2e with Go agent.
- Staging drill: wipe CP DB, restart CP, agents rehydrate state successfully.

### Phase 3.5: Federation rollout (master + datacenter CP)

- Deploy first datacenter CP in shadow against master CP.
- Shift agent connectivity for one datacenter to datacenter CP.
- Keep direct-to-master registration available as fallback path.
- Validate aggregation correctness:
  - health counts
  - attestation pass/fail summaries
  - deployment state convergence
- Expand to additional datacenters after v2 correctness holds.

Exit:

- Master CP receives correct aggregated state from all enabled datacenter CPs.
- Datacenter health/attestation load is handled locally at target scale.
- Direct mode remains supported for small or temporary environments.

### Phase 4: CI glue simplification

- Replace script-heavy workflows with 3 workflow classes:
  - `ci.yml`: lint/unit/integration
  - `e2e.yml`: boot CP+agent and run deploy/capacity smoke
  - `release.yml`: build/sign/publish binaries and images
- Remove SDK install/test/lint paths.

Exit:

- No workflow depends on `scripts/*.sh` or `scripts/*.py`.
- CI can run from typed commands (`go test`, `eectl ...`) with minimal shell.

### Phase 5: Cutover

- Canary Go CP + Go agent in staging, then production.
- For production, canary by datacenter federation first, then by external traffic percentage.
- Monitor registration, deploy success, health convergence, capacity dispatch correctness.
- Remove Python services and archived scripts after stable window.

Exit:

- Production fully on Go master CP + Go datacenter CPs + Go agent.

## 7. Minimal CI Shape (Target)

- `ci.yml`
  - `go vet ./...`
  - `golangci-lint run`
  - `go test ./...`
  - run on `ubuntu-latest` for fast static/unit checks

- `e2e.yml`
  - build CP and agent
  - boot ephemeral environment
  - run contract + deploy + capacity smoke via `eectl`
  - run on existing `self-hosted, tdx` GitHub runner for real attestation/TDX paths

- `release.yml`
  - build binaries/images
  - sign artifacts
  - publish checksums + manifest

This is the intended simple glue: compiled tools + typed interfaces, not ad-hoc script webs.

## 8. Immediate Next Steps

1. Approve monorepo decision (single Go platform repo).
2. Define v2 API contracts in `api/openapi/*.yaml` plus black-box tests.
3. Scaffold `cmd/control-plane`, `cmd/agent`, and `cmd/eectl`.
4. Build new CI workflows (`ci.yml`, `e2e.yml`, `release.yml`) without reusing legacy script glue.
5. Remove SDK install from CI and backfill v2 direct HTTP examples.

## 9. Production Control-Plane Migration Plan (Canary/A-B Safe Rollout)

### 9.1 Prerequisites

- Put a traffic router in front of both CP stacks (old Python CP and new Go CP).
- Ensure sticky routing by stable key (account_id for user APIs, agent_id/vm_name for agent APIs).
- Add per-stack dashboards and alerts for:
  - request rate, error rate, p95/p99 latency
  - registration success/failure
  - deploy success/failure
  - heartbeat freshness and stale-agent count
  - capacity dispatch failures
- Add a one-click kill switch: route 100% back to old CP.
- Decide federation endpointing:
  - agents connect to datacenter-local CP
  - clients/admin connect to master CP edge hostname
  - or agents connect directly to master CP when datacenter CP is disabled

Provider requirement:

- Small providers must not be required to run datacenter CP/aggregator components.
- Federation is an efficiency/scalability feature, not a baseline requirement.

Preferred canary topology:

- Run each CP stack with isolated runtime DB/cache.
- Do not require shared mutable runtime DB between old/new stacks.
- Keep durable business records in dedicated store; prefer event/ETL bridge over shared schema coupling.

Important:

- If production is still SQLite single-writer, true live A/B on writes is not safe.
- For request-level canary, move CP persistence to a multi-writer-safe backend first (typically Postgres).

### 9.2 Traffic classes (roll independently)

- Class A: read-heavy public APIs (`GET` endpoints).
- Class B: write/control APIs (`POST/PUT/DELETE` on apps/deploy/capacity).
- Class C: agent lifecycle APIs (challenge/register/heartbeat/status/deployed).
- Class D: admin/billing APIs.
- Class E: master<->datacenter federation sync traffic.

Do not shift all classes at once.
Federated mode: start with E (one datacenter), then A, then C, then B, then D.
Direct mode: start with A, then C, then B, then D.

### 9.3 Rollout stages

1. Shadow mode (0% user-visible)
- Mirror a sample of production traffic to Go CP.
- Compare status codes, payload shape, and latency out-of-band.
- No user responses served from Go yet.
- Run one datacenter CP in shadow aggregation mode to validate master sync.
- If using direct mode, skip datacenter shadow and focus on master CP shadow validation.

2. Cohort canary (1-2%)
- Route a deterministic cohort (hash(account_id) mod 100 < 2) to Go CP.
- Keep sticky affinity so a cohort stays on one stack.
- Keep admin/billing on old CP.
- Keep most datacenters on old CP initially; shift one datacenter's agents to new datacenter CP first.
- In direct mode, cohort canary applies directly at master CP edge.

3. Progressive ramp
- Increase by guarded steps: 2% -> 5% -> 10% -> 25% -> 50% -> 100%.
- Hold each step for a fixed soak window (for example 30-120 minutes) plus deploy/heartbeat cycles.
- Promote only if all guardrails are green.

4. Full cutover
- Route 100% to Go CP.
- Keep old CP hot-standby for rollback window (24-72 hours).
- Move all datacenters to federated Go datacenter CPs before decommissioning old stack.
- Or keep selected environments (for example staging) in direct mode if federation is not needed there.
- In production, allow mixed operation:
  - small providers on managed direct
  - large/high-scale providers on managed or self-hosted federated mode

### 9.4 Guardrails (auto-stop / rollback)

Rollback to previous stable percentage if any trigger breaches:

- 5xx rate > baseline + 1% absolute for 5 minutes.
- p99 latency > 2x baseline for 10 minutes.
- agent registration success drops below 99%.
- deploy success drops below agreed SLO.
- heartbeat stale-agent count increases above threshold.
- capacity order failure rate above threshold.
- master<->datacenter sync lag exceeds threshold (for example >60s sustained).
- federation event replay/sequence error rate above threshold.

### 9.5 A/B testing guidance

- Use A/B only for read-only or side-effect-safe paths.
- For write paths, prefer canary cohorts with sticky routing and strong rollback.
- Never run uncontrolled random A/B on billing or deployment mutation endpoints.

### 9.6 Data migration safety (clean-slate)

- Preferred: run v2 on its own data model/store and migrate only required bootstrap state.
- If temporary dual-run is required, bridge via explicit translators/events, not shared mutable tables.
- Avoid destructive changes during overlap window.
- After cutover, decommission legacy stores and translation paths.

### 9.7 Operational runbook (minimal)

1. Start at 0% Go, enable shadow comparisons.
2. Shift Class A to 2%, validate metrics and diffs.
3. Shift Class C to 2%, validate registration/heartbeat/deploy health.
4. Increase A and C together to 10%.
5. Shift Class B to 1-2%, then ramp.
6. Shift Class D last.
7. Reach 100%, keep rollback switch armed during stabilization window.

### 9.8 Cloudflare implementation pattern

Use Cloudflare as the traffic control plane for rollout:

- Keep two origin pools:
  - `cp-old` (Python CP)
  - `cp-new` (Go CP)
- Front both with one stable public hostname (`app*.easyenclave.com`).

Recommended mechanics:

1. Weighted canary (fastest start)
- Use Cloudflare Load Balancer weighted pools.
- Start `cp-new` at 1-2%, then ramp per section 9.3.
- Enable session affinity for read-heavy/public paths.

2. Deterministic cohort canary (safer for write paths)
- Put a Cloudflare Worker in front of CP hostname.
- Worker computes cohort from stable key:
  - user traffic: `account_id` (or auth subject)
  - agent traffic: `agent_id` or `vm_name`
- Hash key -> bucket -> route to `cp-old` or `cp-new`.
- Keep sticky mapping so the same key always hits the same CP during rollout.

3. Path-class routing
- Route classes independently using Worker logic:
  - class A first (`GET` reads)
  - class C next (agent lifecycle)
  - class B then (writes/deploy/capacity)
  - class D last (admin/billing)

4. Kill switch
- Single env/config flag in Worker to force 100% `cp-old`.
- Keep this as first branch in routing logic for immediate rollback.

Operational notes:

- Add response header (`X-EE-CP-Stack: old|new`) for observability and debugging.
- Mirror sample requests in Worker only for side-effect-safe paths.
- If using LB-only weights, avoid random split for billing/write APIs; prefer deterministic Worker cohorts.

### 9.9 Disaster-recovery validation (required before 100%)

Run this drill in staging before final cutover:

1. Start Go CP and healthy agents.
2. Delete/wipe CP runtime DB.
3. Restart CP with only bootstrap bundle + secrets.
4. Verify agent re-registration + snapshot rehydration.
5. Verify deploy/preflight/heartbeat paths recover without manual DB restore.
6. Verify datacenter CP can continue local loops during temporary master outage and resync after recovery.

Promotion gate:

- Do not advance above 25% canary until DB-wipe drill is green.

## 10. Environment Baseline and Topology Mapping

Current known footprint:

- Two GCP accounts, infra concentrated in `us-central`.
- One Chicago server: H100 GPU + 256GB RAM.
- One Europe server: 256GB RAM, no GPU.
- Existing TDX self-hosted GitHub runner already running on the Chicago node.

Initial datacenter labels (recommended):

- `gcp-a:us-central1` (GCP account A)
- `gcp-b:us-central1` (GCP account B)
- `baremetal:chicago-h100`
- `baremetal:europe-cpu`

Capacity intent (recommended):

- LLM/GPU workloads prefer `baremetal:chicago-h100`.
- CPU-heavy non-GPU workloads can use `gcp-a`, `gcp-b`, and `baremetal:europe-cpu`.
- Keep explicit placement constraints in deploy policy so GPU-only services never land on non-GPU nodes.

Control-plane topology for this footprint:

- Master CP:
  - Keep current primary node as main/master CP.
  - Optional warm standby in one GCP `us-central` account.
- Datacenter CP usage:
  - Add a specialized GCP datacenter CP/aggregator for `gcp-a` + `gcp-b` capacity loops.
  - Keep the other TDX bare-metal node in direct mode to master CP.
  - Add Europe datacenter CP only if local scale/latency needs justify it.

Concrete hybrid topology (recommended for your current setup):

- `master-cp`: current main node (authoritative policy/control plane).
- `dc-cp-gcp`: specialized aggregator handling GCP health/attestation/capacity traffic.
- `baremetal:chicago-h100`: can run direct to `master-cp` unless/ until local loop load justifies a local dc-cp.
- `baremetal:europe-cpu`: direct to `master-cp`.

Runner placement note:

- Keep attestation-sensitive CI/e2e jobs on the existing Chicago `self-hosted, tdx` runner.
- Use hosted runners for non-TDX build/lint/unit workflows to preserve TDX runner capacity.

Rollout order for this environment:

1. Staging in direct mode (master CP only).
2. Deploy `dc-cp-gcp` in shadow mode for `gcp-a/gcp-b`.
3. Production canary with GCP routed through `dc-cp-gcp`, bare metal still direct.
4. Expand GCP percentage ramp (`gcp-a` then `gcp-b`).
5. Keep Europe direct; add federation there only if needed.

Observability requirements by datacenter:

- Per-datacenter registration success rate.
- Per-datacenter attestation latency and failure reasons.
- Per-datacenter deploy success/failure and queue delay.
- GPU node utilization and saturation (`baremetal:chicago-h100`).

## 11. Legacy `infra/` Logic to Carry Forward (Required)

This section is derived from a full read of legacy `infra/` (`tdx_cli.py`, `launcher/launcher.py`, `image/*`, VM template, systemd units).
For the rewrite, these are product requirements unless explicitly marked optional.

### 11.1 Boot/Image/runtime invariants

- Keep measured boot model:
  - direct kernel/initrd boot
  - dm-verity protected read-only root filesystem
  - writable runtime state on `/data` (not on root)
- Keep `/data` setup semantics:
  - if `/dev/vdb` exists: create ephemeral-key dm-crypt mapping, format ext4, mount `/data`
  - else: mount `/data` as tmpfs fallback
- Keep container storage rooted at `/data`:
  - Docker data root `/data/docker`
  - containerd root `/data/containerd`
- Keep ConfigFS-TSM setup at boot (`/sys/kernel/config/tsm/report`) for quote generation.
- Keep network boot baseline:
  - DHCP on wired interfaces
  - reliable `network-online` before launcher/agent start
- Keep serial console logging as first-class diagnostic path for CI and measurement capture.

### 11.2 Config ingestion + bootstrap transport

- Keep ordered config source chain in agent runtime:
  1. file config (`/etc/easyenclave/config.json` or explicit override)
  2. config-drive ISO (`/config.json`)
  3. kernel cmdline payload (`easyenclave.config` or `easyenclave.configz`)
- Keep cmdline payload compression support (`configz` zlib+base64) and size-aware fallback.
- Keep deterministic measurement behavior:
  - measurement mode must not add mutable/extra config-drive inputs
  - if cmdline exceeds safe limit in measurement mode, fail fast
- Keep host-side fallback behavior for non-measure VMs:
  - if cmdline config too large, emit config-drive ISO and boot without embedded config blob.

### 11.3 Attestation/control-channel security semantics

- Keep nonce challenge flow for agent registration:
  - CP issues nonce
  - agent embeds nonce in TDX quote REPORTDATA
  - CP verifies nonce binding
- Keep agent registration payload shape semantics:
  - includes `vm_name`, `node_size`, `datacenter`, attestation payload
- Keep CP->agent authenticated control writes:
  - per-agent shared secret required
  - optional/required CP attestation envelope mode for write endpoints (`deploy`, `undeploy`)
- Keep trusted-CP measurement policy support on agent side:
  - configured trusted CP MRTDs allowlist
  - optional first-seen CP MRTD pinning behavior
- Keep periodic attestation heartbeat push from agent to CP.

### 11.4 Deployment/runtime execution semantics

- Keep agent control API surface in v2 equivalent form:
  - health/status
  - deploy/undeploy
  - logs/stats
  - control challenge endpoint for CP->agent attestation
- Keep workload deploy flow semantics:
  - decode compose + build context payloads
  - run compose up with transient-network retry policy
  - wait for health endpoint before marking deployed
  - compute compose hash and bind into attestation metadata
- Keep reverse proxy behavior:
  - unknown HTTP routes on agent admin port proxy to workload port.

### 11.5 CP-in-VM bootstrap/tunnel semantics

- Keep CP bootstrap rule: pinned immutable `control_plane_image` required (no implicit `latest`).
- Keep CP runtime env passthrough model for trust/auth/billing/provider config (typed in Go, same capability).
- Keep Cloudflare control-plane tunnel automation semantics:
  - canonical network hostname + stable alias hostname (`app` / `app-staging`)
  - DNS upsert idempotency
  - cloudflared process supervision/restart
- Keep optional agent tunnel setup from CP registration response (`tunnel_token`, `hostname`).

### 11.6 VM orchestration semantics (`tdx_cli` -> `eectl`)

- Replace legacy `tdx` Python CLI with Go `eectl` commands, preserving behavior:
  - VM create/list/status/delete/measure
  - CP bootstrap VM creation with optional wait + bootstrap agent bring-up
  - cleanup of orphaned libvirt/workdir artifacts
- Keep node size presets + env overrides + explicit resource override flags.
- Keep naming/label semantics for role/network/size (exact format may change; diagnostics value must remain).

### 11.7 Failure behavior semantics to keep

- Keep explicit registration retry policy with bounded backoff and configurable max attempts.
- Keep connectivity-degradation handling for cloud-attached agents:
  - probe tunnel reachability
  - optional self-termination after threshold (especially GCP nodes)
- Keep best-effort process supervision loops for CP container and tunnel connectors.

### 11.8 Explicitly dropped from legacy infra

- `customize.sh` / cloud-init heavy path is not part of the v2 control surface.
- Python launcher/CLI/scripts are removed as runtime dependencies.
- Legacy script entrypoints are replaced by Go binaries (`control-plane`, `agent`, `eectl`).
- SDK-dependent CI and SDK release/test flows stay removed.

## 12. Delivery Plan to Incorporate Legacy Infra Logic

### Phase A: Go runtime parity foundation

- Implement Go agent config loaders (file -> config-drive -> cmdline, including `configz`).
- Implement Go TDX attestation module (quote parsing, nonce binding checks, ITA integration).
- Implement Go agent API server with deploy/undeploy/health/logs/stats + workload proxy.

### Phase B: Go VM/bootstrap toolchain parity

- Implement `eectl vm` + `eectl cp bootstrap` with libvirt and image artifact handling.
- Implement cmdline-size safety + config-drive fallback logic.
- Implement measurement mode with deterministic boot constraints and serial extraction.

### Phase C: Image/runtime build parity

- Implement v2 image build path with:
  - dm-verity root
  - initrd content for verity boot
  - systemd units for data disk + TSM + launcher/agent startup
- Keep reproducible build hygiene and deterministic cleanup behaviors.

### Phase D: Production rollout and federation

- Land master+datacenter CP federation APIs and event sequencing.
- Use Cloudflare weighted/cohort traffic routing for staged CP migration.
- Execute DB-wipe recovery drill and federation outage/resync drill before >25% canary.
