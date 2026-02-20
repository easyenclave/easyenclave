# CI/CD Networks: Staging and Production

This document defines the canonical CI/CD split for EasyEnclave networks.

## Goals

- Run per-PR staging deploy validation for same-repo PRs.
- Keep staging rollout automatic from latest `main` with no billing spend.
- Keep production rollout strict and deterministic (auto from CI on `main`, plus manual dispatch).
- Run builtin deploy examples for baremetal and GCP in parallel.

## Workflow Graph

```mermaid
flowchart TD
    PR["Pull Request"] --> PRCHK["PR Staging Checks"]
    PRCHK --> PRBM["PR Deploy Examples Baremetal"]
    PRCHK --> PRGCP["PR Deploy Examples GCP"]
    MAIN["Push main"] --> CI["CI lint test image"]
    CI --> STG["Staging Rollout auto"]
    STG --> BM["Builtin Deploy Examples Baremetal"]
    STG --> GCP["Builtin Deploy Examples GCP"]
    CI --> PROD["Production Rollout strict"]
    REL["Manual dispatch"] --> PROD
    PROD --> PBM["Builtin Deploy Examples Baremetal"]
    PROD --> PGCP["Builtin Deploy Examples GCP"]
```

## Environment Profiles

### Staging

- Trigger: `Staging Rollout` after `CI` success on `main` (or manual).
- Trust level: **untrusted** (test-only network).
- Auth policy: relaxed for iteration (`AUTH_REQUIRE_GITHUB_OAUTH_IN_PRODUCTION=false`).
- Attestation policy: nonce optional, warn on RTMR/signature drift.
- Billing policy: disabled (`BILLING_ENABLED=false`) and simulated requests.
- Objective: validate the newest `main` features first, with low-cost integration confidence and cheaper access to stronger CPU/GPU capacity for testing. Do not treat staging as a trusted production boundary. Same-repo PR checks also run builtin deploy examples against staging.

### Production

- Trigger: `Production Rollout` after `CI` success on `main` and via manual dispatch.
- Auth policy: strict (`AUTH_REQUIRE_GITHUB_OAUTH_IN_PRODUCTION=true`).
- Attestation policy: strict TCB + nonce + RTMR + signature verification.
- Billing policy: enabled (`BILLING_ENABLED=true`, no simulation).
- Objective: deterministic release with full attestation posture.

## Canonical Workflows

- `.github/workflows/test.yml`
- `.github/workflows/pr-staging-checks.yml`
- `.github/workflows/staging-rollout.yml`
- `.github/workflows/production-rollout.yml`

Reusable/manual components:

- `.github/workflows/bootstrap-control-plane.yml`
- `.github/workflows/deploy-examples.yml`
- `.github/workflows/deploy-examples-gcp.yml`

## Policy Notes

- `deploy-examples*.yml` are intentionally reusable/manual only.
- Only rollout workflows orchestrate automatic network mutation.
- PR checks can run deploy examples only for same-repo PRs on the staging control plane.
- Baremetal and GCP example deploys execute in parallel after bootstrap.
