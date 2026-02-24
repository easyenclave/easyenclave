# EasyEnclave v2 Rewrite Spec (Go)

## 1. Product Decision
- Full rewrite of control-plane and agent in Go.
- Keep both in one repo under `v2/`.
- Remove SDK from product/CI critical path.
- Replace script-based operations with typed Go binaries.
- Use installer-driven host bootstrap for agents.

## 2. Programs

### `control-plane`
Purpose:
- challenge/register/heartbeat/status/deployed lifecycle for agents
- deploy/preflight/federation APIs
- policy, scheduling, trust, and rollout control

### `agent`
Purpose:
- runtime endpoint for deploy/undeploy/health/logs/stats/snapshot
- attestation and CP communication
- workload execution and health gating

### `installer`
Purpose:
- install/upgrade agent binary on host
- write runtime env and service unit
- enable/start supervised service (or run directly when systemd is skipped)

## 3. Scope

### In Scope
- Go CP runtime and API.
- Go agent runtime and API.
- Go installer host bootstrap flow.
- v2 CI/e2e/release workflows.
- Federation-ready master/dc CP interfaces.
- DB-wipe tolerant runtime design.

### Out of Scope
- Legacy API compatibility guarantees.
- Reusing old Python runtime/services.
- Reintroducing operator CLI as control surface.

## 4. Architecture

## 4.1 Repository Shape
- `v2/cmd/control-plane`
- `v2/cmd/agent`
- `v2/cmd/installer`
- `v2/internal/controlplane`
- `v2/internal/agent`
- `v2/internal/installer`
- `v2/internal/shared`
- `v2/api/openapi/control-plane.yaml`
- `v2/api/openapi/agent-control.yaml`

## 4.2 Runtime Topology
- Direct mode: agents connect to master CP.
- Federated mode: agents connect to datacenter CP; dc CP syncs up to master CP.
- Production must support both modes simultaneously.

## 4.3 State Model (DB-Wipe Tolerant)
- Reconstructible runtime state:
  - online/offline, heartbeat freshness
  - deployed workload per agent
  - runtime health/status labels
- Bootstrap-required state:
  - CP identity + signing/verification roots
  - base trust policy and bootstrap admin control
- Durable business state:
  - billing/audit/tenant records

Design rule:
- CP liveness must not depend on pre-existing DB runtime rows.
- Agents can reconnect and repopulate runtime state after DB loss.

## 5. Legacy Infra Behaviors to Preserve

## 5.1 Config and Bootstrap Inputs
Agent config source chain must remain:
1. file config
2. config-drive `config.json`
3. kernel cmdline (`easyenclave.config` / `easyenclave.configz`)

## 5.2 Attestation Registration Semantics
- CP issues nonce challenge.
- Agent binds nonce into TDX quote `REPORTDATA`.
- CP validates nonce binding at registration.

## 5.3 Runtime Execution Semantics
- agent supports deploy/undeploy + health/logs/stats/snapshot
- CP tracks heartbeat/status/deployed transitions
- snapshot endpoint supports CP rehydration

## 5.4 Host Runtime Assumptions
- dm-verity read-only root + writable runtime area
- ConfigFS-TSM availability for quote paths
- serial diagnostics retained for low-level boot/attestation debugging

## 6. Current Implementation Status (This PR Series)

Implemented:
- v2 OpenAPI contracts and generated stubs
- CP challenge + registration path with nonce-bound quote check
- shared TDX quote parser package
- agent config source chain (`config`/`configz`/config-drive)
- agent deploy/undeploy state transitions + snapshot metadata
- installer binary + tested install/service-render path
- removal of legacy `infra/` working tree from branch
- workflows updated to build `control-plane`, `agent`, `installer`

Not yet complete:
- full workload execution parity (compose/build-context/health retries)
- full attestation lifecycle and policy enforcement matrix
- full scheduling/capacity/billing implementation
- full production federation control loop behavior

## 7. Full Delivery Plan

### Phase 0: Contract Freeze
- finalize API contracts and acceptance criteria
- freeze trust and state taxonomy

Exit:
- approved API/spec with black-box test plan

### Phase 1: Core Runtime Foundation (in progress)
- CP registration/auth primitives
- agent config bootstrap primitives
- installer host bootstrap path

Exit:
- binaries build/test in CI

### Phase 2: Agent Runtime Completion
- implement deploy execution path with health gating
- implement attestation refresh + heartbeat push model
- implement CP->agent write authentication envelope

Exit:
- integration tests pass against CP v2

### Phase 3: Control Plane Completion
- implement apps/versions/deploy/capacity/billing/admin domains
- implement startup rehydration from agent snapshots

Exit:
- DB-wipe recovery drill passes

### Phase 4: Federation Completion
- master<->dc APIs with monotonic sequence/replay safety
- direct + federated mixed production mode

Exit:
- aggregation correctness validated at staging scale

### Phase 5: Production Cutover
- staged Cloudflare traffic migration
- guarded percentage ramps and rollback switch
- finalize decommission of legacy runtime

Exit:
- sustained 100% traffic on Go stack with guardrails green

## 8. Production Migration Plan

### 8.1 Traffic Strategy
- Keep old and new CP stacks behind one edge.
- Use weighted and/or deterministic cohort routing.
- Shift traffic classes independently:
  1. reads
  2. agent lifecycle
  3. write/deploy/capacity
  4. admin/billing

### 8.2 Guardrails
Rollback if breached:
- elevated 5xx rate
- p99 latency regression
- registration/deploy success drop
- stale heartbeat growth
- federation lag/replay errors

### 8.3 Required Drills Before Full Cutover
- DB-wipe recovery
- dc CP isolation/resync
- rollback kill switch verification

## 9. Environment Mapping (Current)
- Two GCP accounts in `us-central`.
- Chicago baremetal node (H100 + 256GB).
- Europe baremetal node (CPU + 256GB).
- Existing TDX GitHub runner on Chicago node.

Recommended rollout:
1. staging direct mode
2. shadow dc CP for GCP
3. production canary via GCP first
4. maintain direct mode option for smaller providers

## 10. Completion Definition
Rewrite is complete when:
1. `control-plane`, `agent`, `installer` are the only production control binaries.
2. agent lifecycle (register/attest/deploy/heartbeat/snapshot) is Go-native.
3. DB-wipe recovery is validated and operationally repeatable.
4. production supports both direct and federated modes.
5. migration reaches sustained 100% without guardrail breach.
