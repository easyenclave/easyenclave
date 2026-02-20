# Add a New Cloud Provider

Primary directories: `app/`, `infra/`, `.github/workflows/`

## Goal

Add CP-native provisioning support for a new cloud with deterministic placement labels.

## Architecture Points to Extend

1. Provisioning module:

- Add `app/<provider>_capacity.py` with create/delete/list primitives.
- Follow `app/gcp_capacity.py` patterns (API auth, instance create, cleanup).

2. Control-plane orchestration:

- Wire provider into capacity fulfiller logic in `app/main.py`.
- Keep datacenter format normalized as `<cloud>:<zone-or-region>`.

3. Launcher config pass-through:

- Add provider config fields in `infra/tdx_cli.py`.
- Export provider env vars to CP container in `infra/launcher/launcher.py`.

4. CI/CD workflow coverage:

- Add provider deploy example workflow (reusable/manual).
- Integrate provider checks in staging/PR paths as needed.

5. Documentation and runbooks:

- Add operator runbook under `docs/runbooks/`.
- Update `docs/CI_CD_NETWORKS.md` if rollout behavior changes.

## Validation Checklist

- Can create and clean up instances from CP-native flow.
- Agent registers with valid datacenter label.
- Deploy preflight selects eligible agents correctly.
- Stale/orphan cleanup path is implemented and tested.
