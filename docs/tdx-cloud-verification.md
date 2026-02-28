# TDX Cloud Verification

Use this checklist to confirm a staging/production control plane is backed by real TDX-capable agent nodes.

## 1) Check control plane health

```bash
curl -sS https://app-staging.easyenclave.com/health | jq
```

## 2) Check registered agents

```bash
curl -sS https://app-staging.easyenclave.com/api/v1/agents | jq '.[] | {agent_id,vm_name,node_size,datacenter,verified,status}'
```

Expected:
- At least one `verified: true` agent
- `datacenter` label present (for example `gcp:us-central1-f`)

## 3) Check rollout workflow state

```bash
gh run list --workflow "Staging Rollout" --limit 5
gh run list --workflow "Production Rollout" --limit 5
```

## 4) Spot-check deployment path

```bash
curl -sS https://app-staging.easyenclave.com/api/v1/deployments | jq '.[0] // empty'
```

A successful deployment record confirms end-to-end CP -> agent execution is functioning.
