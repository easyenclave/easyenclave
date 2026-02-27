# Phase 10 - Billing + Stripe

Status: Not started

## Goal

Implement charging, revenue split, ledger writes, and Stripe deposit ingestion.

## Deliverables

- Billing service with hourly charge computation
- Revenue split logic (agent/operator/platform/contributor paths)
- Stripe client + webhook verification
- Billing routes
- Charging and insufficient-funds background jobs

## Test Gates

- Charge calculation correctness
- 70/30 split correctness
- Contributor pool distribution correctness
- Stripe webhook signature verification
- Insufficient-funds termination behavior

## Definition Of Done

- [ ] Ledger operations are balanced and auditable
- [ ] Retry behavior is idempotent
- [ ] Billing jobs are safe under partial failures

## PR Checklist

- [ ] Billing service implemented
- [ ] Stripe webhook handler implemented
- [ ] Ledger invariants tested
- [ ] Background jobs tested
