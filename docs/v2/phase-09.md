# Phase 09 - Deploy + Apps + Proxy + Owner Routes

Status: Not started

## Goal

Implement deployment workflow, app catalog APIs, proxying, diagnostics, and owner self-service routes.

## Deliverables

- Deploy routes with preflight/dry-run
- App and app version routes
- Revenue-share routes
- Measurement callback route
- Proxy and logs routes
- `/api/v1/me/*` owner routes

## Test Gates

- Deploy creates records and selects eligible agents
- Dry-run path returns preflight result without mutation
- App version lifecycle works
- Proxy forwards correctly
- OIDC ownership rules enforced

## Definition Of Done

- [ ] Deploy and app APIs are end-to-end functional
- [ ] Proxying is bounded and safe
- [ ] Owner-scoped routes are correctly protected

## PR Checklist

- [ ] Deploy handlers implemented
- [ ] App/revenue-share handlers implemented
- [ ] Proxy/log handlers implemented
- [ ] Integration tests added
