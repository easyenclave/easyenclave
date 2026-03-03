# Phase 14 - Legacy Ops Wrapper (Superseded)

Status: In progress

## Goal

Consolidate repo automation under Cargo and remove top-level script entrypoints.

## Deliverables

- (Historical) `ee-ops` command dispatcher
- Cargo command parity for:
  - lint
  - reproducibility gate
  - trusted-value measurement
  - CI deploy bootstrap
  - GCP image bake
  - admin password hash helper
- CI workflow migration toward first-class automation entrypoints
- Root-level infra layout (`ansible/`, `packer/`, `scripts/`)

## Test Gates

- command argument/dispatch validation
- CI workflow smoke checks pass with Cargo entrypoint
- repro/deploy/image-bake commands execute through maintained entrypoints

## Definition Of Done

- [ ] (Historical) migration tasks captured
- [ ] CI workflows use maintained entrypoints

## PR Checklist

- [ ] Command handlers implemented
- [ ] Workflows/docs migrated
- [ ] Script entrypoints removed
