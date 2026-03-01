# Phase 14 - ee-ops

Status: In progress

## Goal

Consolidate repo automation under Cargo and remove top-level script entrypoints.

## Deliverables

- `crates/ee-ops` command dispatcher
- Cargo command parity for:
  - lint
  - reproducibility gate
  - trusted-value measurement
  - CI deploy bootstrap
  - GCP image bake
  - admin password hash helper
- CI workflow migration from `./scripts/*` to `cargo run -p ee-ops -- ...`
- Deletion of legacy top-level `scripts/` directory

## Test Gates

- command argument/dispatch validation
- CI workflow smoke checks pass with Cargo entrypoint
- repro/deploy/image-bake commands execute through `ee-ops`

## Definition Of Done

- [ ] All former `scripts/*` commands are available via `ee-ops`
- [ ] CI workflows use Cargo commands only
- [ ] No top-level `scripts/` directory remains

## PR Checklist

- [ ] Command handlers implemented
- [ ] Workflows/docs migrated
- [ ] Script entrypoints removed
