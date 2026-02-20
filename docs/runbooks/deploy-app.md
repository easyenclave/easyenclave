# Deploy an App to an Agent

Primary directories: `app/`, `examples/`

## Goal

Register an app, publish a version, and deploy it onto eligible agents.

## Option A: Use Builtin Examples

From repo root:

```bash
gh workflow run deploy-examples.yml -f cp_url=https://app.easyenclave.com
gh workflow run deploy-examples-gcp.yml -f cp_url=https://app.easyenclave.com
```

## Option B: API Flow (Manual)

1. Register app:

```bash
curl -X POST https://app.easyenclave.com/api/v1/apps \
  -H "Content-Type: application/json" \
  -d '{"name":"my-app","description":"My confidential app"}'
```

2. Publish version (`compose` must be base64-encoded docker-compose YAML):

```bash
curl -X POST https://app.easyenclave.com/api/v1/apps/my-app/versions \
  -H "Content-Type: application/json" \
  -d '{"version":"v1","compose":"<base64-compose>","node_size":"tiny"}'
```

3. Deploy:

```bash
curl -X POST https://app.easyenclave.com/api/v1/apps/my-app/versions/v1/deploy \
  -H "Content-Type: application/json" \
  -d '{"node_size":"tiny","allowed_clouds":["baremetal"]}'
```

4. Verify deployment/agents:

```bash
curl -s https://app.easyenclave.com/api/v1/deployments | jq '.deployments[0]'
curl -s https://app.easyenclave.com/api/v1/agents | jq '.agents[] | {agent_id,deployed_app,status,health_status}'
```
