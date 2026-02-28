# Reproducible Trusted Values

This runbook documents how we verify deterministic trusted measurements for the pinned GCP TDX image.

## Simple model

We measure twice so we can detect nondeterminism from the same image/commit.

- Pass #1 and Pass #2 should produce the same trusted values.
- If they differ, the rollout is blocked.
- Measurement drift is always treated as a deployment blocker.

## What is checked

The CI reproducibility gate runs two passes and verifies:

1. Trusted digest is identical
2. Trusted measurement payload is identical:
3. `mrtds_by_size` map (`tiny`, `standard`, `llm`)
4. `rtmrs_by_size` map (`tiny`, `standard`, `llm`)

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
- `gcloud` auth with access to the target project/image
- `GCP_PROJECT_ID` and `GCP_SERVICE_ACCOUNT_KEY`
- `EE_GCP_IMAGE_NAME` (preferred) or `EE_GCP_IMAGE_FAMILY`

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
