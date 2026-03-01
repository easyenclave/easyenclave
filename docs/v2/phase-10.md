# Phase 10 - External Billing App Integration

Status: Not started

## Goal

Define and implement the CP contract for an external billing app (CP is not the billing engine).

## Deliverables

- CP -> billing app contract (events or API payloads)
- Contract docs for required deployment/account fields
- Removal of CP-owned billing routes and background jobs
- Integration test stubs against a billing app mock
- Billing owner policy via `BILLING_UNLIMITED_OWNERS` (default: `posix4e,easyenclave`)

## Test Gates

- Contract payload validation
- Retry and idempotency behavior for contract delivery
- Deploy flow works without CP-owned billing internals
- CI validates unlimited-owner policy with env unset and env override

## Definition Of Done

- [ ] CP has no billing-specific business logic
- [ ] External billing contract is stable and documented
- [ ] Retry behavior is idempotent

## PR Checklist

- [ ] Contract adapter implemented
- [ ] CP billing routes/jobs removed
- [ ] Contract tests added
