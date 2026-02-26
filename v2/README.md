# easyenclave v2 scaffold

This directory contains a Rust workspace that follows the v2 architecture blueprint in
`/home/ubuntu/sunny-noodling-squirrel.md`.

## Workspace crates

- `ee-common`: shared API types and helpers
- `ee-attestation`: quote/token stubs and verification helpers
- `ee-agent`: agent service (health/deploy/register/heartbeat)
- `ee-aggregator`: pull-based scraper + relay + state endpoint
- `ee-cp`: control plane (registration APIs + aggregator scrape cache)
- `ee-hostd`: host daemon API skeleton
- `ee-devbox`: local single-process stack runner

## Quick start

```bash
cd v2
cargo test
cargo run -p ee-devbox
```
