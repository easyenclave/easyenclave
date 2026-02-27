# Deploy to EasyEnclave Action

A GitHub Action to deploy Docker Compose applications to EasyEnclave's confidential computing platform.

## Prerequisites

**Apps must be registered before deployment.** Register your app once using the API:

```bash
curl -X POST https://app.easyenclave.com/api/v1/apps \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-app",
    "description": "My application",
    "source_repo": "my-org/my-repo"
  }'
```

## Usage

```yaml
- uses: easyenclave/easyenclave/.github/actions/deploy@main
  with:
    app_name: my-app
    compose_file: docker-compose.yml
    service_name: my-app
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `app_name` | Yes | - | App name (must be pre-registered) |
| `compose_file` | Yes | - | Path to your docker-compose.yml |
| `service_name` | Yes | - | Name for your deployment |
| `health_endpoint` | No | `/health` | Health check endpoint path |
| `control_plane_url` | No | `https://app.easyenclave.com` | EasyEnclave control plane URL |
| `github_owner` | No | - | GitHub user or org to set as agent owner |
| `node_size` | No | `` | Required node size (`tiny`, `standard`, `llm`) |
| `allowed_datacenters` | No | `` | Comma-separated datacenter allow-list |
| `denied_datacenters` | No | `` | Comma-separated datacenter deny-list |
| `allowed_clouds` | No | `` | Comma-separated cloud allow-list (`baremetal,gcp,azure`) |
| `denied_clouds` | No | `` | Comma-separated cloud deny-list |
| `allow_measuring_enclave_fallback` | No | `false` | Allow fallback to measuring-enclave agents |

## Outputs

| Output | Description |
|--------|-------------|
| `deployment_id` | The deployment ID |
| `agent_id` | The TDX agent ID used |
| `service_url` | The deployed service URL |
| `version` | The published app version (format: YYYYMMDD-HHMMSS-sha) |

## Example

### Basic deployment

```yaml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: easyenclave/easyenclave/.github/actions/deploy@main
        with:
          app_name: my-app
          compose_file: docker-compose.yml
          service_name: my-app
```

### With outputs

```yaml
- uses: easyenclave/easyenclave/.github/actions/deploy@main
  id: deploy
  with:
    app_name: my-app
    compose_file: docker-compose.yml
    service_name: my-app

- run: |
    echo "Deployed version ${{ steps.deploy.outputs.version }}"
    echo "Service URL: ${{ steps.deploy.outputs.service_url }}"
```

### OIDC deploy (no API key secret)

If your EasyEnclave account is linked to your GitHub owner (`github_org` or `github_login`),
you can deploy with a GitHub Actions OIDC token instead of storing an API key secret.

Use the minimal example workflow at:

`examples/deploy-with-github-oidc.yml`

### With org ownership

Set `github_owner` so that GitHub org members can manage agents via the owner-scoped API (`/api/v1/me/agents`) without needing full admin access:

```yaml
- uses: easyenclave/easyenclave/.github/actions/deploy@main
  with:
    app_name: my-app
    compose_file: docker-compose.yml
    service_name: my-app
    github_owner: ${{ github.repository_owner }}
```

Any member of the `github.repository_owner` org who logs in via GitHub OAuth will see the deployed agent under "My Agents" and can reset or redeploy it. Admins (listed in `ADMIN_GITHUB_LOGINS`) retain full access to all agents.

## How it works

1. Verifies the app is registered in the catalog
2. Generates a version string (timestamp + git SHA)
3. Publishes the version with source inspection
4. Runs deploy preflight and lets control-plane place onto an eligible agent
5. Deploys the attested version to the agent
6. Waits for health checks to pass
7. Returns the service URL

The action handles all TDX complexity - you just need Docker files.

## App Catalog Flow

All deployments go through the app catalog:

```
Register App (one-time) -> Publish Version -> Deploy Version
```

This ensures:
- Source code inspection before deployment
- Version tracking and audit trail
- Attestation of all deployed code

## Requirements

- A docker-compose.yml file in your repo
- An EasyEnclave account with running agents
- Your service must expose a health endpoint
- **App must be pre-registered** (see Prerequisites)
