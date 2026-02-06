# Private LLM

Run a private LLM (Ollama + SmolLM2 135M) inside a TDX enclave. Queries and responses never leave the attested VM.

## What it does

- **ollama** — Runs the Ollama inference server on port 8080, exposing an OpenAI-compatible API at `/v1/chat/completions`
- **model-loader** — Init container that pulls `smollm2:135m` (~100MB) on first boot, then exits

## docker-compose.yml

```yaml
services:
  ollama:
    image: ollama/ollama:latest
    ports:
      - "8080:8080"
    environment:
      - OLLAMA_HOST=0.0.0.0:8080
    volumes:
      - ollama_data:/root/.ollama
    healthcheck:
      test: ["CMD", "ollama", "list"]

  model-loader:
    image: curlimages/curl:latest
    depends_on:
      ollama:
        condition: service_healthy
    restart: "no"
    entrypoint: ["sh", "-c", "curl -sf -X POST http://ollama:8080/api/pull -d '{\"name\":\"smollm2:135m\"}'"]
```

## Querying the LLM

Once deployed, the LLM is reachable through the agent's Cloudflare tunnel:

```bash
curl https://agent-{id}.easyenclave.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"smollm2:135m","messages":[{"role":"user","content":"Say hello"}]}'
```

Or via the control plane proxy:

```bash
curl https://app.easyenclave.com/proxy/private-llm/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"smollm2:135m","messages":[{"role":"user","content":"Say hello"}]}'
```

## How it's tested

The [Deploy Examples](../../.github/workflows/deploy-examples.yml) workflow runs an end-to-end smoke test after deployment:

1. Deploys the compose file to a TDX agent
2. Waits for the Ollama health check to pass
3. Sends a chat completion request via `curl` through the Cloudflare tunnel
4. Asserts the response contains a non-empty message

The test uses `smollm2:135m` (135M params, ~100MB) for fast pull and load times in CI.
