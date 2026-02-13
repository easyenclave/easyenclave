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

## Credential plan for cloud agent bring-up
This verifier assumes agents are already registered. For full end-to-end cloud bring-up we still need:
1. GCP service account credentials with VM/network permissions in a test project.
2. Azure service principal with VM/network permissions in a test subscription/resource group.
3. Intel TA key + Cloudflare settings (already used by current agent/control-plane flows).

Once those are available, add a provisioning phase before `verify-tdx-clouds.sh` that launches one agent per cloud AZ label.
