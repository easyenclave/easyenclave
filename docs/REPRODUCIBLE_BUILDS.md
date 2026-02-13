# Reproducible Builds

This runbook documents how we verify reproducibility for the TDX dm-verity image artifacts.

## Simple model

We build twice so we can detect nondeterminism from the same commit.

- Build #1 and Build #2 should produce the same outputs.
- If they differ, the build pipeline is not deterministic.
- Measurement drift is always treated as a deployment blocker.

## What is checked

The CI reproducibility gate runs two builds and verifies:

1. `infra/image/output/easyenclave.vmlinuz` SHA256 is identical
2. `infra/image/output/easyenclave.initrd` SHA256 is identical
3. `infra/image/output/easyenclave.root.raw` SHA256 is identical
4. `infra/image/output/easyenclave.cmdline` SHA256 is identical
5. Tiny-profile stable TDX measurement fields (`mrtd`, `rtmr0`, `rtmr1`, `rtmr2`) are identical

If any value differs, CI fails before deployment.

CI always runs this gate in strict mode: both measurement mismatch and artifact mismatch fail.

CI also publishes a determinism report:
- Job summary table in GitHub Actions (artifact digests + measurements + durations)
- Uploaded artifact bundle `reproducibility-report` with `report.json`, `summary.md`, and per-build comparison files

## CI entrypoint

The gate is executed by:

```bash
./scripts/ci-reproducibility-check.sh
```

The same strict check runs locally with:

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

Local report output is written to:

```bash
infra/output/reproducibility/
```

## Notes

- `scripts/ci-reproducibility-check.sh` now emits deploy trust outputs (`mrtds`, `rtmrs`, `rtmrs_by_size`) directly after the reproducibility gate passes.
- This gate proves short-horizon build reproducibility in one CI run. Snapshot pinning and longer-horizon reproducibility controls are tracked in the consolidated roadmap issue.
