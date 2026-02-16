# Pure-TDX Cloud Verification

This runbook verifies agent readiness in pure-TDX mode across datacenter labels.

## Scope
- Supported now: `baremetal`, `gcp`, `azure`
- Not supported in pure-TDX mode: `aws` (skipped unless explicitly failed)

## What gets verified
1. At least one eligible agent exists per target datacenter:
   - `verified=true`
   - `health_status=healthy`
   - `hostname` present
   - `status in {undeployed,deployed,deploying}`
   - optional `node_size` match
2. Deploy preflight allow-policy:
   - `allowed_datacenters=[<dc>]` returns `eligible=true`
   - selected datacenter matches `<dc>`
3. Deploy preflight deny-policy:
   - `denied_datacenters=[<dc>]` returns `eligible=false`

## Local execution
```bash
CP_URL="https://app.easyenclave.com" \
CLOUDS="baremetal,gcp,azure" \
NODE_SIZE="llm" \
VERIFY_APP_NAME="private-llm" \
VERIFY_APP_VERSION="20260213-abcdef1" \
DC_BAREMETAL="baremetal:github-runner" \
DC_GCP="gcp:us-central1-a" \
DC_AZURE="azure:eastus2-1" \
./scripts/verify-tdx-clouds.sh
```

## GitHub workflow
Use `Verify TDX Clouds` (`.github/workflows/verify-tdx-clouds.yml`) via `workflow_dispatch`.

For GCP LLM bring-up + deploy smoke, use
`GCP Bootstrap LLM` (`.github/workflows/gcp-bootstrap-llm.yml`).
It requests capacity from the control plane, deploys `private-llm` to GCP-only
eligible agents, and runs the example smoke test.

## Credential plan for cloud agent bring-up
Required repository secrets for CP-driven bring-up workflows:
1. `CP_ADMIN_TOKEN` (preferred) or `CP_ADMIN_PASSWORD`
2. `AGENT_ADMIN_PASSWORD`

Cloud credentials are expected to be configured in the control plane
provisioner integration, not in GitHub Actions.
