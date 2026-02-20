# Build and Deploy an App to an Agent

Primary directories: `examples/`, `sdk/`, `.github/actions/`

## Goal

Start from an example, customize your app, then register, publish, and deploy it to an eligible attested agent.

## 1) Start from a Builtin Example

From repo root:

```bash
cp -r examples/hello-tdx examples/my-app
cd examples/my-app
```

Reference examples:

- `examples/hello-tdx/` for minimal HTTP service
- `examples/private-llm/` for OpenAI-compatible LLM deployment

## 2) Edit Your `docker-compose.yml`

Requirements:

- Expose your service on port `8080`
- Provide a health endpoint (`/` or `/health`)
- Pin images to stable tags or digests for deterministic rollouts

## 3) Build/Test Locally

```bash
docker compose up --build
curl -f http://localhost:8080/
```

## 4) Register + Deploy from GitHub Actions (recommended)

Use the reusable actions in this repo:

- `.github/actions/register-app`
- `.github/actions/deploy`

Example workflow job:

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/register-app
        with:
          app_name: my-app
          description: "My confidential app"
          github_owner: ${{ github.repository_owner }}
      - uses: ./.github/actions/deploy
        with:
          app_name: my-app
          compose_file: examples/my-app/docker-compose.yml
          service_name: my-app
          control_plane_url: https://app.easyenclave.com
          github_owner: ${{ github.repository_owner }}
          node_size: tiny
```

## 5) Manual API Flow (if not using GitHub Actions)

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

## 6) Verify Deployment

```bash
curl -s https://app.easyenclave.com/api/v1/deployments | jq '.deployments[0]'
curl -s https://app.easyenclave.com/api/v1/agents | jq '.agents[] | {agent_id,deployed_app,status,health_status}'
```

For SDK/OpenAI-style smoke tests, see:

- `examples/private-llm/test.py`
- `examples/private-llm/README.md`

## 7) Builtin End-to-End Example Workflows

From repo root:

```bash
gh workflow run deploy-examples.yml -f cp_url=https://app.easyenclave.com
gh workflow run deploy-examples-gcp.yml -f cp_url=https://app.easyenclave.com
```
