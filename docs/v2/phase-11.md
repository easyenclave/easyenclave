# Phase 11 - Capacity + GCP + Admin

Status: Not started

## Goal

Implement warm-capacity control, GCP provisioning for staging/prod, and admin route surface.

## Deliverables

- Capacity target/reservation/order routes
- Launcher claim/update routes
- GCP service with SA OAuth and instance lifecycle calls
- Real Intel TDX-capable node provisioning path for both staging and production
- Admin settings/trusted-MRTD/cloud cleanup routes
- Remaining background jobs (capacity pool, fulfiller, stale cleanup, health checker, session cleanup)

## Test Gates

- Capacity lifecycle flows
- Claim/fulfill/expire order flows
- GCP token and instance mock tests
- Staging smoke test on real GCP TDX node
- Reconcile behavior tests

## Definition Of Done

- [ ] Capacity shortfall reconciliation works
- [ ] Provisioning flow is observable and recoverable
- [ ] Staging and production use GCP real TDX nodes (no emulation)
- [ ] Admin ops are authenticated and auditable

## PR Checklist

- [ ] Capacity routes implemented
- [ ] GCP real-node provisioning service implemented
- [ ] Admin routes implemented
- [ ] Background job tests added
