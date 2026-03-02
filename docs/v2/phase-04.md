# Phase 04 - ee-cp Skeleton

Status: Not started

## Goal

Stand up the minimum running control plane with DB schema, settings, and health endpoint.

## Deliverables

- `crates/ee-cp` binary scaffold
- SQL migrations for core tables
- Settings system with `DB > env > default` resolution and TTL cache
- `/health` endpoint

## Test Gates

- CP starts and serves `/health`
- Migrations apply cleanly
- Settings resolution order is correct
- Settings TTL cache behavior is correct

## Definition Of Done

- [ ] Control plane binary runs locally
- [ ] Migrations are reproducible
- [ ] Settings behavior matches contract

## PR Checklist

- [ ] Main app wiring added
- [ ] Migration files added
- [ ] Settings store tests added
- [ ] Health route tests added
