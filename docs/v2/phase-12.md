# Phase 12 - OCI Measurement Pipeline

Status: Not started

## Goal

Implement image measurement pipeline for app versions with digest resolution and signature validation.

## Deliverables

- Image reference parser
- Digest resolver
- Cosign verification wrapper
- Compose measurement orchestration
- Measurement background processor

## Test Gates

- Image ref parser coverage
- Digest resolution via mocked registry
- Signature verification success/failure paths
- Compose-level measurement e2e

## Definition Of Done

- [ ] Measurement outputs are deterministic
- [ ] Signature policy is enforceable and logged
- [ ] Failed measurements surface actionable reasons

## PR Checklist

- [ ] Measurement module implemented
- [ ] Background processor integrated
- [ ] Registry/cosign mocks used in tests
