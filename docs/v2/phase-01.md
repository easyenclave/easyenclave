# Phase 01 - Workspace + ee-common

Status: Not started

## Goal

Create the Rust workspace foundation and the shared crate used by all binaries.

## Deliverables

- Workspace root `Cargo.toml`
- `crates/ee-common` with:
  - shared domain types
  - API DTOs
  - config parsing
  - app error model
  - pricing primitives
- CI workflow for fmt, clippy, and tests

## Test Gates

- Config parsing validation
- Pricing calculation correctness
- Error serialization correctness

## Definition Of Done

- [ ] Workspace builds
- [ ] `ee-common` API is consumed by at least one crate skeleton
- [ ] CI workflow runs and fails on lint/test errors

## PR Checklist

- [ ] Cargo workspace files added
- [ ] `ee-common` modules added
- [ ] CI workflow added/updated
- [ ] Tests passing in CI
