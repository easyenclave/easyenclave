# Examples

Example apps that run inside TDX enclaves via EasyEnclave. Each is a standard `docker-compose.yml` deployed to an attested agent through the control-plane API.

| Example | Description | Test |
|---------|-------------|------|
| [hello-tdx](hello-tdx/) | Minimal HTTP server — the smallest possible EasyEnclave app | health check via deploy action |
| [private-llm](private-llm/) | Ollama LLM running privately inside a TDX enclave | [`test.py`](private-llm/test.py) — SDK smoke test (direct + proxy) |

## Deploy Example Workflow

Use [`.github/workflows/deploy-examples.yml`](../.github/workflows/deploy-examples.yml) as the canonical example for app deploy.

It demonstrates:
- deploy auth via deployer API key or GitHub OIDC
- profile-based defaults for `staging` and `production`
- posting compose + constraints to `POST /api/deploy`
- resolving the deployed agent endpoint from `/api/agents/{agent_id}`

## Adding a new example

1. Create a directory under `examples/` with a `docker-compose.yml`.
2. Expose your service on port `8080`.
3. Add/update a workflow entry in `deploy-examples.yml`.
4. Add a `test.py` that exercises your app using the SDK.
