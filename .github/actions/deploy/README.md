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
| `trusted_mrtd` | No | - | TDX VM image MRTD to trust |

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

## How it works

1. Verifies the app is registered in the catalog
2. Generates a version string (timestamp + git SHA)
3. Publishes the version with source inspection
4. Finds an available verified TDX agent
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
