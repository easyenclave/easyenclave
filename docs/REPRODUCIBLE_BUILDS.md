# Reproducible Builds

This runbook documents how we verify reproducibility for the TDX dm-verity image artifacts.

## What is checked

The CI reproducibility gate runs two clean `mkosi` builds and verifies:

1. `infra/image/output/easyenclave.vmlinuz` SHA256 is identical
2. `infra/image/output/easyenclave.initrd` SHA256 is identical
3. `infra/image/output/easyenclave.root.raw` SHA256 is identical
4. `infra/image/output/easyenclave.cmdline` SHA256 is identical
5. Tiny-profile TDX measurements (`mrtd`, `rtmr0..rtmr3`) are identical

If any value differs, CI fails before deployment.

## CI entrypoint

The gate is executed by:

```bash
./scripts/ci-reproducibility-check.sh
```

## Running locally

Prerequisites:
- Host with TDX tooling used by `infra/tdx_cli.py`
- Nix installed

From repo root:

```bash
./scripts/ci-reproducibility-check.sh
```

## Notes

- `scripts/ci-build-measure.sh` supports `CI_SKIP_IMAGE_BUILD=true` so deploy measurement can reuse already-validated artifacts from the gate.
- This gate proves short-horizon build reproducibility in one CI run. Snapshot pinning and longer-horizon reproducibility controls are tracked in the consolidated roadmap issue.
