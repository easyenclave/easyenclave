# EasyEnclave Architecture

This document describes the current Rust-first EasyEnclave architecture.

## 1) System Overview

```mermaid
flowchart TD
    Dev[Developer / CI Workflow]
    CP[EasyEnclave Rust Control Plane]
    Capacity[Capacity Targets + Reservations + Orders]
    Workers[Capacity Launcher Workers<br/>GCP / Baremetal]
    Agents[TDX Agents<br/>tiny / standard / llm]
    ITA[Intel Trust Authority]
    CF[Cloudflare Tunnel + DNS]

    Dev -->|deploy / admin APIs| CP
    CP --> Capacity
    Capacity --> Workers
    Workers -->|launch + bootstrap| Agents
    Agents -->|register + heartbeat + attest| CP
    Agents --> ITA
    Agents --> CF
```

## 2) Deploy Path (Control Plane Owned)

```mermaid
sequenceDiagram
    participant CI as CI / GitHub Actions
    participant CP as Control Plane
    participant A as Selected Agent

    CI->>CP: POST /api/v1/deploy
    CP->>CP: Select agent + verify ownership/auth + placement filters
    CP->>A: POST /api/deploy
    A-->>CP: 202 accepted
    CP-->>CI: deployment_id + agent_id
```

## 3) Responsibilities

- Control Plane
  - Agent lifecycle and attestation checks
  - Deployment preflight and placement
  - Capacity target/reservation/order orchestration
  - Admin auth (password + GitHub OAuth) and owner auth (API key + GitHub OIDC)
- Capacity Workers
  - Claim launch orders from CP
  - Boot provider-specific capacity (GCP/baremetal)
  - Bootstrap agents so they register back to CP
- Agents
  - TDX attestation and health reporting
  - Deployment execution and service runtime
  - Optional Cloudflare tunnel registration

## 4) Canonical Workflow References

- `.github/workflows/test.yml`
- `.github/workflows/pr-staging-checks.yml`
- `.github/workflows/staging-rollout.yml`
- `.github/workflows/release-trust-bundle.yml`
- `.github/workflows/release-gcp-image.yml`
- `.github/workflows/production-rollout.yml`
- `.github/workflows/bootstrap-control-plane.yml`

## 5) Related Docs

- `docs/CAPACITY_LAUNCHER.md`
- `docs/CI_CD_NETWORKS.md`
- `docs/runbooks/release-production.md`
