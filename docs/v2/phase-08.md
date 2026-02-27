# Phase 08 - Authentication Layer

Status: Not started

## Goal

Implement account/admin auth models and identity-based ownership enforcement.

## Deliverables

- API key auth with Argon2 hashing
- Admin session auth
- GitHub OAuth flow
- GitHub OIDC verifier for deploy path
- Ownership enforcement utilities
- Auth and account routes

## Test Gates

- API key hash/verify
- Session lifecycle
- OIDC claim verification and owner mapping
- Admin login success/failure paths

## Definition Of Done

- [ ] All auth paths validate and reject correctly
- [ ] Ownership checks protect owner-scoped endpoints
- [ ] Secret material is never logged

## PR Checklist

- [ ] Auth middleware implemented
- [ ] Session store integration complete
- [ ] OIDC/OAuth tests added
- [ ] Ownership tests added
