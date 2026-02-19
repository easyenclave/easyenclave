# CI/CD Networks: Staging and Production

This document defines the canonical CI/CD split for EasyEnclave networks.

## Goals

- Keep PR validation fast and non-mutating.
- Keep staging rollout automatic from latest `main` with no billing spend.
- Keep production rollout manual, strict, and deterministic.
- Run builtin deploy examples for baremetal and GCP in parallel.

## Workflow Graph

```mermaid
flowchart TD
    PR[Pull Request] --> PRCHK[PR Staging Checks]
    MAIN[Push main] --> CI[CI (lint/test/image)]
    CI --> STG[Staging Rollout]
    STG --> BM[Builtin Deploy Examples (Baremetal)]
    STG --> GCP[Builtin Deploy Examples (GCP)]
    REL[Manual release] --> PROD[Production Rollout]
    PROD --> PBM[Builtin Deploy Examples (Baremetal)]
    PROD --> PGCP[Builtin Deploy Examples (GCP)]
```

## Environment Profiles

### Staging

- Trigger: `Staging Rollout` after `CI` success on `main` (or manual).
- Trust level: **untrusted** (test-only network).
- Auth policy: relaxed for iteration (`AUTH_REQUIRE_GITHUB_OAUTH_IN_PRODUCTION=false`).
- Attestation policy: enforce nonce, warn on RTMR/signature drift.
- Billing policy: disabled (`BILLING_ENABLED=false`) and simulated requests.
- Objective: low-cost integration confidence and developer validation. Do not treat staging as a trusted production boundary.

### Production

- Trigger: `Production Rollout` (manual only).
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
- PR checks do not provision nodes or request paid capacity.
- Baremetal and GCP example deploys execute in parallel after bootstrap.
