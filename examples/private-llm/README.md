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

Using the Python SDK:

```python
from easyenclave import EasyEnclaveClient

client = EasyEnclaveClient("https://app.easyenclave.com")
llm = client.service("private-llm")
resp = llm.post("/v1/chat/completions", json={
    "model": "smollm2:135m",
    "messages": [{"role": "user", "content": "Say hello"}],
})
print(resp.json()["choices"][0]["message"]["content"])
```

Using the OpenAI Python client (since Ollama is OpenAI-compatible):

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://app.easyenclave.com/proxy/private-llm/v1",
    api_key="unused",  # Ollama doesn't require an API key
)
completion = client.chat.completions.create(
    model="smollm2:135m",
    messages=[{"role": "user", "content": "Say hello"}],
)
print(completion.choices[0].message.content)
```

## How it's tested

The [Deploy Examples](../../.github/workflows/deploy-examples.yml) workflow runs [`test.py`](test.py) after deployment. The script tests three access paths:

1. **Direct** — POST to the Cloudflare tunnel URL via `httpx`
2. **Proxy** — POST through the control plane proxy via `EasyEnclaveClient.service("private-llm")`
3. **OpenAI** — `openai.OpenAI(base_url=".../proxy/private-llm/v1")` — proving standard tools just work

All paths retry for up to 5 minutes while the model loads, then assert a non-empty response.

The test uses `smollm2:135m` (135M params, ~100MB) for fast pull and load times in CI.
