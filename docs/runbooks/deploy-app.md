# Deploy a Workload to an Agent

Primary directories: `examples/`, `infra/`, `.github/workflows/`

## Goal

Deploy a compose payload to an eligible attested agent using the Rust control plane.

## 1) Prepare a compose payload

From repo root:

```bash
cp -r examples/hello-tdx examples/my-app
cd examples/my-app
```

Verify locally:

```bash
docker compose up --build
curl -f http://localhost:8080/
```

## 2) Create a deployer account (one-time)

```bash
curl -sS -X POST https://app.easyenclave.com/api/v1/accounts \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-org-deployer",
    "account_type": "deployer",
    "github_org": "my-org"
  }' | jq
```

Save the returned `api_key`.

## 3) Deploy with API key

```bash
curl -sS -X POST https://app.easyenclave.com/api/v1/deploy \
  -H "Authorization: Bearer $EE_API_KEY" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --rawfile compose docker-compose.yml '{compose:$compose,node_size:"tiny"}')" | jq
```

## 4) Deploy from GitHub Actions with OIDC (recommended)

```yaml
name: deploy
on:
  workflow_dispatch: {}
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Request GitHub OIDC token
        id: oidc
        run: |
          set -euo pipefail
          token="$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=easyenclave-deploy" | jq -r '.value')"
          echo "token=$token" >> "$GITHUB_OUTPUT"
      - name: Deploy
        env:
          CP_URL: https://app.easyenclave.com
          OIDC_TOKEN: ${{ steps.oidc.outputs.token }}
        run: |
          set -euo pipefail
          payload="$(jq -n --rawfile compose examples/hello-tdx/docker-compose.yml '{compose:$compose,node_size:"tiny"}')"
          curl -sS -X POST "$CP_URL/api/v1/deploy" \
            -H "Authorization: Bearer $OIDC_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$payload" | jq
```

## 5) Verify rollout

```bash
curl -sS https://app.easyenclave.com/api/v1/deployments | jq
curl -sS https://app.easyenclave.com/api/v1/agents | jq '.[] | {agent_id,vm_name,node_size,status,verified}'
```
