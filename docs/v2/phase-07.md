# Phase 07 - Cloudflare Integration

Status: Not started

## Goal

Integrate Cloudflare tunnel + DNS management into registration and cleanup flows.

## Deliverables

- Tunnel service: create/config/delete
- DNS management: create/list/delete CNAME records
- Registration wiring to return tunnel token and hostname
- Cleanup hooks on agent deletion/reset

## Test Gates

- Tunnel creation via mocked Cloudflare API
- DNS record creation and cleanup
- Registration response includes tunnel credentials

## Definition Of Done

- [ ] Tunnel and DNS lifecycle is reliable
- [ ] Failure paths do not orphan resources silently
- [ ] Cleanup paths are idempotent

## PR Checklist

- [ ] Cloudflare client implemented
- [ ] Route integration completed
- [ ] API failure-path tests added
