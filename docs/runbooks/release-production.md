# Release and Production Runbook

Primary directories: `.github/workflows/`, `infra/`

## Goal

Publish a release and roll production using release-pinned trust and image assets.

## Prerequisites

- A commit on `main` ready for release.
- Self-hosted `[self-hosted, tdx]` runner available for trust-bundle build.
- Production secrets configured (`PRODUCTION_GCP_PROJECT_ID`, `PRODUCTION_GCP_SERVICE_ACCOUNT_KEY`, `INTEL_API_KEY`, `CP_ADMIN_PASSWORD`, etc.).

## Steps

1. Create and publish release:

```bash
gh release create v0.1.13 --target main --title v0.1.13 --notes "Production release v0.1.13"
```

2. Monitor release workflows triggered by the published release:

```bash
gh run list --workflow "Release Trust Bundle" --limit 5
gh run list --workflow "Release GCP Image" --limit 5
gh run list --workflow "Production Rollout" --limit 5
```

3. Verify required release assets:

```bash
gh release view v0.1.13 --json assets --jq '.assets[].name'
```

Expected assets include:
- `trusted_values.v0.1.13.json`
- `trusted_values.json`
- `gcp-image.v0.1.13.json`
- `gcp-image.json`

4. If needed, rerun production manually for the same release tag:

```bash
gh workflow run production-rollout.yml -f release_tag=v0.1.13
```

## Failure Modes

- Missing trust asset: `production-rollout` fails in trust-bundle resolution.
- Missing GCP image asset: `production-rollout` fails in gcp-image resolution.
- Release tag mismatch in asset payload: rollout fails fast to avoid mixed artifacts.
