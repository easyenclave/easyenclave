# Examples

Example apps that run inside TDX enclaves via EasyEnclave. Each is a standard `docker-compose.yml` — EasyEnclave handles attestation, tunneling, and deployment.

| Example | Description |
|---------|-------------|
| [hello-tdx](hello-tdx/) | Minimal HTTP server — the smallest possible EasyEnclave app |
| [private-llm](private-llm/) | Ollama LLM running privately inside a TDX enclave |

## How deployment works

All examples are deployed automatically by the [Deploy Examples](../.github/workflows/deploy-examples.yml) workflow after CI passes on `main`:

1. App is registered in the catalog (`POST /api/v1/apps`)
2. The `docker-compose.yml` is published as a new version
3. The [measuring enclave](../apps/measuring-enclave/) resolves image digests and attests the version
4. An available TDX agent is selected and the version is deployed
5. The agent pulls images, runs `docker compose up`, and reports health
6. The service becomes reachable through a Cloudflare tunnel at `https://agent-{id}.easyenclave.com`

## Adding a new example

1. Create a directory under `examples/` with a `docker-compose.yml`
2. Expose your service on port 8080 (the agent proxies traffic to this port)
3. Add a deploy job in `deploy-examples.yml`

See the [deploy action docs](../.github/actions/deploy/README.md) for the full action reference.
