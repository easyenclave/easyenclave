# Phase 15 - Image + E2E + Release Pipelines

Status: Not started

## Goal

Finalize image build, end-to-end integration testing, and release/staging workflows.

## Deliverables

- VM image build assets
- Full integration suite
- Staging and release workflows

## Test Gates

- Launcher -> CP bootstrap -> agent registration -> deploy flow passes
- Workload reachable through tunnel path in test topology
- Build artifacts are reproducible and publishable

## Definition Of Done

- [ ] End-to-end tests pass in CI
- [ ] Release workflow produces expected artifacts
- [ ] Staging promotion path is documented and tested

## PR Checklist

- [ ] Image build scripts validated
- [ ] E2E tests committed and stable
- [ ] Release workflow configured
