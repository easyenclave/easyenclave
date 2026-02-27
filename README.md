# easyenclave v2

Rust rewrite of easyenclave focused on confidential workloads on Intel TDX.

## Decisions (Locked)

- Auth for publish/deploy: GitHub Actions OIDC only.
- CP attestation verification: mandatory.
- Attestation flow: agent submits TDX quote + CP nonce proof to CP; CP performs ITA appraisal centrally.
- CP state: fully ephemeral (in-memory), no persistent DB.
- Cloud provider scope: GCP only.
- VM execution model: raw OS image with `supervisord` in guest.
- Delivery mode: PR branch only, no direct changes to `main`.
- Production deployment workflow is manual-dispatch only during rewrite.

## Workspace

- `crates/ee-common`: shared types, DTOs, config, error type
- `crates/ee-attestation`: TDX quote helpers and Intel TA token plumbing
- `crates/ee-cp`: control plane API server
- `crates/ee-agent`: in-VM agent binary
- `crates/ee-launcher`: host-side launcher CLI
- `image/`: VM image build assets
- `tests/integration/`: integration tests

## Implementation Tracker

- [x] Replace v1 repository layout with v2 Rust layout
- [x] Create workspace + shared crates baseline
- [x] Add CP route surface skeleton
- [x] Add agent binary implementation
- [x] Add launcher implementation
- [x] Add integration tests for publish/register/deploy flow
- [x] Add CI workflows (`ci.yml`, `pr-e2e.yml`, `deploy.yml`, `cleanup.yml`)
- [x] Enforce GitHub OIDC verification path in CP (test shortcut only when explicitly enabled)
- [x] Move attestation from agent-side ITA minting to CP-side ITA appraisal (agent sends quote only)
- [x] Enforce nonce binding in CP appraisal pipeline (`challenge -> quote report_data -> ITA verify`)
- [x] Wire real TDX + CF + ITA flow for PR runner (TDX VM boot, CF tunnel+DNS create/delete, ITA key validation)

## Quick Start

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p ee-cp
```

## Live Plan

1. Switch default guest image to the final v2 image containing ee-agent/ee-cp/systemd wiring.
2. Replace temporary local-CP API assertion in PR e2e with full in-guest CP bootstrap and end-to-end deploy validation.
3. Add explicit non-`UpToDate` TCB integration test using controlled ITA test fixture response.

## Notes

- Source specification for this rewrite: `tingly-weaving-pond.md`.
- This branch intentionally replaces the prior Python/FastAPI codebase.
