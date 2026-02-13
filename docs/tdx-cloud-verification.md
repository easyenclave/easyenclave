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

For full bring-up + verification + cleanup of real cloud agents, use
`Cloud Confidential Agents` (`.github/workflows/cloud-confidential-agents.yml`).
It provisions one confidential VM agent per enabled cloud, waits for registration,
runs policy verification, and always cleans up tagged resources.

## Credential plan for cloud agent bring-up
Required repository secrets for cloud bring-up workflow:
1. `INTEL_API_KEY`
2. GCP:
   - `GCP_PROJECT_ID`
   - either OIDC (`GCP_WORKLOAD_IDENTITY_PROVIDER` + `GCP_SERVICE_ACCOUNT`)
     or JSON key (`GCP_SERVICE_ACCOUNT_KEY`)
3. Azure:
   - `AZURE_RESOURCE_GROUP`
   - either OIDC (`AZURE_CLIENT_ID` + `AZURE_TENANT_ID` + `AZURE_SUBSCRIPTION_ID`)
     or JSON credentials (`AZURE_CREDENTIALS`)
