# Phase 05 - Stores

Status: Not started

## Goal

Implement all primary data-access stores for the control plane.

## Deliverables

- Store modules for agents, deployments, accounts, apps, transactions, capacity, sessions, and services
- Transaction-safe balance and ledger operations
- Common query patterns for listing/filtering

## Test Gates

- CRUD round-trip coverage per store
- Deployment status transition checks
- Session expiry behavior
- Capacity order claim/fulfill lifecycle

## Definition Of Done

- [ ] Store APIs are stable enough for route integration
- [ ] Data integrity constraints are enforced
- [ ] Transactional operations are covered by tests

## PR Checklist

- [ ] Store modules implemented
- [ ] Schema assumptions documented
- [ ] Unit/integration tests added
