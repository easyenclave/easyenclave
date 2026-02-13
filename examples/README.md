# Examples

Example apps that run inside TDX enclaves via EasyEnclave. Each is a standard `docker-compose.yml` — EasyEnclave handles attestation, tunneling, and deployment.

| Example | Description | Test |
|---------|-------------|------|
| [hello-tdx](hello-tdx/) | Minimal HTTP server — the smallest possible EasyEnclave app | health check via deploy action |
| [private-llm](private-llm/) | Ollama LLM running privately inside a TDX enclave | [`test.py`](private-llm/test.py) — SDK smoke test (direct + proxy) |
| [noise-contacts](noise-contacts/) | Real contacts demo over Noise with attestation-bound identity checks | [`test.py`](noise-contacts/test.py) — handshake + encrypted register/lookup |

The workflow also verifies that deploying an **unregistered** app is rejected — proving the catalog is enforced, not optional.

## How deployment works

All examples are deployed automatically by the [Deploy Examples](../.github/workflows/deploy-examples.yml) workflow after CI passes on `main`:

1. App is registered in the catalog (`POST /api/v1/apps`)
2. The `docker-compose.yml` is published as a new version
3. The [measuring enclave](../apps/measuring-enclave/) resolves image digests and attests the version
4. An available TDX agent is selected and the version is deployed
5. The agent pulls images, runs `docker compose up`, and reports health
6. The service becomes reachable through a Cloudflare tunnel at `https://agent-{id}.easyenclave.com`

Each deploy sets `github_owner: ${{ github.repository_owner }}` so the deploying GitHub org owns the agents. Org members can log in via GitHub OAuth and manage their agents at `/api/v1/me/agents` without needing full admin access.

## Adding a new example

1. Create a directory under `examples/` with a `docker-compose.yml`
2. Expose your service on port 8080 (the agent proxies traffic to this port)
3. Add a deploy job in `deploy-examples.yml` (include `github_owner: ${{ github.repository_owner }}`)
4. Add a `test.py` that exercises your app using the [SDK](../sdk/) — it becomes both a smoke test and runnable documentation

See the [deploy action docs](../.github/actions/deploy/README.md) for the full action reference.
