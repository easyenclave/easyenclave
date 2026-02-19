# EasyEnclave Architecture

This document describes the current EasyEnclave architecture after the control-plane cutover:
- Placement and deploy decisions are made in the control plane.
- Warm-capacity reservations are managed in the control plane.
- Agent launchers/workers provide capacity but do not make placement decisions.

## 1) System Overview

```mermaid
flowchart TD
    Dev[Developer / CI Workflow]
    CP[EasyEnclave Control Plane]
    Catalog[App + Version Catalog]
    Measure[Version Measurement Pipeline]
    Capacity[Capacity Targets + Reservations + Orders]
    Workers[Capacity Launcher Workers<br/>GCP / Baremetal]
    Agents[TDX Agents<br/>tiny / standard / llm]
    ITA[Intel Trust Authority]
    CF[Cloudflare Tunnel + DNS]
    Client[Service Client / SDK]

    Dev -->|register / publish / deploy| CP
    CP --> Catalog
    CP --> Measure
    CP --> Capacity
    Capacity --> Workers
    Workers -->|launch + bootstrap| Agents
    Agents -->|register + heartbeat + attest| CP
    Agents --> ITA
    Agents --> CF
    Client -->|proxy request| CP
    CP -->|route traffic| Agents
```

## 2) Deploy Path (Control Plane Owned)

```mermaid
sequenceDiagram
    participant CI as CI / Deploy Action
    participant CP as Control Plane
    participant A as Selected Agent

    CI->>CP: POST /deploy/preflight
    CP->>CP: Evaluate policy, cloud/datacenter, node_size, health
    CP-->>CI: Eligible + diagnostics (dry-run only)

    CI->>CP: POST /deploy
    CP->>CP: Select agent + version variant
    CP->>CP: Create reservation on demand if warm target requires it
    CP->>A: POST /api/deploy
    A-->>CP: 202 accepted
    CP-->>CI: deployment_id + agent_id
```

## 3) Measurement Path

```mermaid
sequenceDiagram
    participant CI as Publish Workflow
    participant CP as Control Plane
    participant M as Measuring Enclave / Measurer Agent

    CI->>CP: POST /apps/{app}/versions
    CP->>CP: status=pending
    CP->>M: dispatch measurement job
    M->>M: resolve image tags to immutable digests
    M-->>CP: callback with MRTD/RTMRs + compose hash
    CP->>CP: persist trusted values, status=attested/rejected
```

## 4) Responsibilities

- Control Plane
  - App/version registry
  - Deploy preflight and placement
  - Warm-pool target management and reservation lifecycle
  - Measurement orchestration and trust policy
- Capacity Workers
  - Claim launch orders from CP
  - Boot provider-specific capacity (GCP/baremetal)
  - Bootstrap agents so they register back to CP
- Agents
  - TDX attestation and health reporting
  - Deployment execution and service runtime
  - Optional Cloudflare tunnel registration

## 5) Key Flows and References

- Deploy example workflows:
  - `.github/workflows/deploy-examples.yml`
  - `.github/workflows/deploy-examples-gcp.yml`
- Deploy action internals:
  - `.github/actions/deploy/action.yml`
  - `scripts/deploy_action.sh`
- Capacity launcher docs:
  - `docs/CAPACITY_LAUNCHER.md`
