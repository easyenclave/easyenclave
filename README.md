# EasyEnclave v2

Clean-slate Go rewrite of EasyEnclave.

## Programs
- `v2/cmd/control-plane`: control-plane API and orchestration service
- `v2/cmd/agent`: host agent runtime
- `v2/cmd/installer`: host installer/bootstrap for running the agent as a service

## Core Direction
- Single Go repo for control-plane and agent.
- No SDK in product/CI path.
- No script-based product control surface.
- Installer-driven host bootstrap for agents.
- Optional federated control-plane topology (master + datacenter CP) plus direct mode.

## Docs
- Rewrite plan and architecture: `docs/REWRITE_SPEC_GO_AGENT.md`
- v2 developer usage: `v2/README.md`
- CI/CD secret setup: `.github/SECRETS_SETUP.md`
