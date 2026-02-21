# Release and Production Runbook

Primary directories: `.github/workflows/`, `infra/`

## Goal

Generate release-pinned trust/image components and roll production using `release_tag`.

## Prerequisites

- Published release tag (for example `v0.1.0`).
- Self-hosted `[self-hosted, tdx]` runner available.
- Required secrets configured (`INTEL_API_KEY`, `CP_ADMIN_PASSWORD`, `GCP_PROJECT_ID`, `GCP_SERVICE_ACCOUNT_KEY`, etc.).

## Steps

1. Create release (if not already published):

```bash
gh release create v0.1.0 --target main --title v0.1.0 --notes "Release v0.1.0"
```

2. Generate release trust bundle:

```bash
gh workflow run release-trust-bundle.yml -f release_tag=v0.1.0
```

3. Generate release GCP image descriptor:

```bash
gh workflow run release-gcp-image.yml -f release_tag=v0.1.0
```

4. Generate release example image descriptors (signed digest refs for builtin deploy examples):

```bash
gh workflow run release-example-images.yml -f release_tag=v0.1.0
```

5. Verify assets:

```bash
gh release view v0.1.0 --json assets --jq '.assets[].name'
```

Expected assets:

- `trusted_values.v0.1.0.json`
- `trusted_values.json`
- `gcp-image.v0.1.0.json`
- `gcp-image.json`
- `example-images.v0.1.0.json`
- `example-images.json`

6. Roll production:

```bash
gh workflow run production-rollout.yml -f release_tag=v0.1.0
```

## Failure Modes

- Missing trust asset: `production-rollout` fails in trust-bundle resolution.
- Missing GCP image asset: `production-rollout` fails in gcp-image resolution.
- Missing example image asset: rollout fails in example-images resolution.
- Release tag mismatch in asset payload: rollout fails fast to avoid mixed artifacts.
