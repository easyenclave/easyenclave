# easyenclave v2

Rust rewrite of easyenclave focused on confidential workloads on Intel TDX.

## Decisions (Locked)

- Auth for publish/deploy: GitHub Actions OIDC only.
- CP attestation verification: mandatory.
- CP state: fully ephemeral (in-memory), no persistent DB.
- Cloud provider scope: GCP only.
- VM execution model: raw OS image with `supervisord` in guest.
- Delivery mode: PR branch only, no direct changes to `main`.

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
- [ ] Add agent binary implementation
- [ ] Add launcher implementation
- [ ] Add integration tests for publish/register/deploy flow
- [ ] Add CI workflows (`ci.yml`, `pr-e2e.yml`, `deploy.yml`, `cleanup.yml`)
- [ ] Wire real TDX + CF + ITA flow for PR runner

## Quick Start

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p ee-cp
```

## Live Plan

1. Finish compilable baseline for all crates.
2. Add end-to-end integration test against local CP/agent test harness.
3. Add CI + PR workflow that boots real TDX VMs on GCP and validates deploy through Cloudflare.
4. Iterate on real attestation plumbing and tighten failure modes.

## Notes

- Source specification for this rewrite: `tingly-weaving-pond.md`.
- This branch intentionally replaces the prior Python/FastAPI codebase.
