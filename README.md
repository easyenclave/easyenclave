# EasyEnclave

EasyEnclave is a Rust control plane + agent system for confidential compute workloads on Intel TDX VMs.

## Components

- `ee-cp`: control-plane API server (Axum + SQLite/SQLx).
- `ee-agent`: node runtime for agent/control-plane bootstrap/measure modes.
- `ee-admin`: small operator CLI (currently admin password hashing).

## Repository Layout

- `src/`: Rust code for control plane, agent, attestation, and shared modules.
- `migrations/`: SQLite schema migrations used by `ee-cp` at startup.
- `ansible/`: orchestration playbooks for deploy, image bake, and VM lifecycle.
- `packer/`: image templates consumed by Ansible workflows.
- `.github/workflows/`: CI/CD entry points (the canonical deployment flows).
- `Dockerfile.ee-cp`: control-plane container build.

## Local Development

Prerequisites:

- Rust stable toolchain
- `sqlite3` (optional but useful for inspection)
- Docker (only if you need local OCI runtime behavior)

Run checks:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Run control plane locally:

```bash
CP_BIND_ADDR=0.0.0.0:8080 \
CP_DATABASE_URL='sqlite://easyenclave.db?mode=rwc' \
CP_ADMIN_PASSWORD='dev-password' \
cargo run --bin ee-cp
```

Health check:

```bash
curl -fsS http://127.0.0.1:8080/health | jq .
```

Run agent locally (example):

```bash
cat >/tmp/agent.json <<'JSON'
{
  "mode": "agent",
  "control_plane_url": "http://127.0.0.1:8080",
  "node_size": "tiny",
  "datacenter": "local:dev"
}
JSON

EASYENCLAVE_CONFIG=/tmp/agent.json cargo run --bin ee-agent
```

## Deployment and Infra

Deployments are workflow-driven and use Ansible/Packer directly.

- Staging: [`.github/workflows/staging-deploy.yml`](.github/workflows/staging-deploy.yml)
- Production: [`.github/workflows/production-deploy.yml`](.github/workflows/production-deploy.yml)
- Baremetal image flow: [`.github/workflows/baremetal-image.yml`](.github/workflows/baremetal-image.yml)

Infra orchestration overview: [`ansible/README.md`](ansible/README.md)

## Configuration

Control plane config is env-driven. Key vars:

- `CP_BIND_ADDR` (default `0.0.0.0:8080`)
- `CP_DATABASE_URL` (default `sqlite://easyenclave.db?mode=rwc`)
- `CP_ADMIN_PASSWORD` (optional but required for admin password login flows)

`ee-agent` reads env + JSON config (default path `/etc/easyenclave/agent.json`, override with `EASYENCLAVE_CONFIG`).

## Current State

This repo is a single Rust crate with multiple binaries. CI enforces `fmt`, `clippy`, and `test` on each PR.
