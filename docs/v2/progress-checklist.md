# v2 Cross-Phase Progress Checklist

## Status Board

- [ ] Phase 00 complete
- [ ] Phase 01 complete
- [ ] Phase 02 complete
- [ ] Phase 03 complete
- [ ] Phase 04 complete
- [ ] Phase 05 complete
- [ ] Phase 06 complete
- [ ] Phase 07 complete
- [ ] Phase 08 complete
- [ ] Phase 09 complete
- [ ] Phase 10 complete
- [ ] Phase 11 complete
- [ ] Phase 12 complete
- [ ] Phase 13 complete
- [ ] Phase 14 complete
- [ ] Phase 15 complete

## Required Global Gates

- [ ] `cargo fmt --check` passes for workspace
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] Registration to heartbeat smoke test passes
- [ ] Deploy + billing charge cycle test passes
- [ ] Capacity reconciliation + fulfillment test passes
- [ ] Full end-to-end launcher -> cp -> agent -> deploy flow passes
- [ ] Staging smoke test passes on real GCP TDX node
- [ ] Production preflight enforces real GCP TDX node availability

## Notes

- Active phase: Phase 07 (Cloudflare tunnel integration) with Phase 08 auth model already partially implemented
- Current blockers: final Cloudflare domain strategy per environment; auth policy for destructive agent lifecycle routes
- Next milestone: add authenticated agent delete/reset routes wired to Cloudflare cleanup and capacity state updates
