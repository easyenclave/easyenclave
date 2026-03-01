# Phase 11 - GCP + Admin

Status: Not started

## Goal

Implement GCP provisioning integration points and admin route surface.

## Deliverables

- GCP service with SA OAuth and instance lifecycle calls
- Real Intel TDX-capable node provisioning path for both staging and production
- Admin settings/trusted-MRTD/cloud cleanup routes
- Remaining background jobs (stale cleanup, health checker, session cleanup)

## Test Gates

- GCP token and instance mock tests
- Staging smoke test on real GCP TDX node

## Definition Of Done

- [ ] Provisioning flow is observable and recoverable
- [ ] Staging and production use GCP real TDX nodes (no emulation)
- [ ] Admin ops are authenticated and auditable

## PR Checklist

- [ ] GCP real-node provisioning service implemented
- [ ] Admin routes implemented
- [ ] Background job tests added
