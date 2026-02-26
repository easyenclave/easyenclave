# v2 Branch Protection

Use this policy on the default branch (`main`) so every v2 PR gets both fast Rust checks and a TDX preview run.

## Required status checks

Require these checks before merge:

- `v2 Rust CI / checks`
- `v2 PR Policy / require-preview-label`
- `v2 PR Preview / preview`

## Why this combination

- `v2 Rust CI / checks`: enforces fmt, clippy (`-D warnings`), and workspace tests.
- `v2 PR Policy / require-preview-label`: blocks merge unless the PR has the `preview` label.
- `v2 PR Preview / preview`: runs the self-hosted TDX preview smoke path.

Because the policy check requires the `preview` label, the preview workflow is guaranteed to run for v2 PRs.

## Recommended branch settings

- Require pull request reviews before merging.
- Dismiss stale approvals on new commits.
- Require branches to be up to date before merging.
- Restrict who can push to `main`.
