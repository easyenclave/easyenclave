# Add a New Cloud Provider

Primary directories: `crates/ee-cp/`, `infra/`, `.github/workflows/`

## Goal

Add CP-native provisioning support for a new cloud with deterministic placement labels.

## Provider Backlog (TODO)

- [x] GCP
- [ ] Azure
- [ ] AWS
- [ ] OCI
- [ ] Local/baremetal pool API parity with cloud-style capacity hooks

## Node Size Expansion Backlog (TODO)

- [ ] Add a new node size to an existing cloud (capacity module + scheduler labels + preflight checks)
- [ ] Add `tiny` support for each new cloud
- [ ] Add `standard` support for each new cloud
- [ ] Add `llm` support for each new cloud

## Architecture Points to Extend

1. Provisioning module:
- Add provider client/service under `crates/ee-cp/src/services/`.
- Follow existing GCP patterns for auth, create, delete, and list.

2. Control-plane orchestration:
- Wire provider into capacity fulfillment and order claiming in `crates/ee-cp/src/` route/service modules.
- Keep datacenter format normalized as `<cloud>:<zone-or-region>`.

3. Launcher config pass-through:
- Add provider config fields in `infra/tdx_cli.py`.
- Export provider env vars in `infra/launcher/launcher.py`.

4. CI/CD workflow coverage:
- Extend `test.yml` and `staging-rollout.yml` checks if provider-specific behavior is required.

5. Documentation and runbooks:
- Add operator runbook under `docs/runbooks/`.
- Update `docs/CI_CD_NETWORKS.md` if rollout behavior changes.

## Validation Checklist

- Can create and clean up instances from CP-native flow.
- Agent registers with valid datacenter label.
- Deploy preflight selects eligible agents correctly.
- Stale/orphan cleanup path is implemented and tested.
