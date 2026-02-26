# easyenclave (v2)

This repository now contains only the v2 Rust implementation.

## Layout

- `v2/`: Rust workspace (`ee-cp`, `ee-aggregator`, `ee-agent`, `ee-hostd`, shared crates, and `ee-devbox`)
- `.github/workflows/v2-ci.yml`: Rust CI for v2
- `.github/workflows/v2-pr-policy.yml`: PR label policy for v2 preview
- `.github/workflows/v2-pr-preview.yml`: self-hosted TDX preview workflow

## Local development

```bash
cd v2
cargo test --workspace
cargo run -p ee-devbox
```

## Branch protection checks

See [`docs/runbooks/v2-branch-protection.md`](docs/runbooks/v2-branch-protection.md).
