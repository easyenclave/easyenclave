# easyenclave v2 Execution Docs

This folder breaks the v2 rewrite plan into phase-by-phase implementation docs with checklists intended for PR tracking.

## How To Use

1. Pick the active phase doc.
2. Convert checklist items into PR tasks.
3. Keep status and notes updated in each phase file.
4. Update `progress-checklist.md` after each merged phase.

## Phase Docs

- [Phase 00 - Security Contract + Test Gates](phase-00.md)
- [Phase 01 - Workspace + ee-common](phase-01.md)
- [Phase 02 - ee-attestation TDX Quote Parsing](phase-02.md)
- [Phase 03 - ee-attestation Intel TA Verification](phase-03.md)
- [Phase 04 - ee-cp Skeleton](phase-04.md)
- [Phase 05 - Stores](phase-05.md)
- [Phase 06 - Nonce + Agent Registration](phase-06.md)
- [Phase 07 - Cloudflare Integration](phase-07.md)
- [Phase 08 - Authentication Layer](phase-08.md)
- [Phase 09 - Deploy + Apps + Proxy + Owner Routes](phase-09.md)
- [Phase 10 - Billing + Stripe](phase-10.md)
- [Phase 11 - Capacity + GCP + Admin](phase-11.md)
- [Phase 12 - OCI Measurement Pipeline](phase-12.md)
- [Phase 13 - ee-agent](phase-13.md)
- [Phase 14 - ee-launcher](phase-14.md)
- [Phase 15 - Image + E2E + Release Pipelines](phase-15.md)

## Tracking

- [Cross-Phase Progress Checklist](progress-checklist.md)
- [Infra Decision - GCP + Real TDX](infra-gcp-tdx.md)
