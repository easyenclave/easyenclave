# Private LLM

Run a private LLM (Ollama + SmolLM2 135M) inside a TDX enclave. Queries and responses never leave the attested VM.

## What it does

- **private-llm** — Runs the Ollama inference server on port 8080, exposing an OpenAI-compatible API at `/v1/chat/completions`
- **model-loader** — Init container that pulls `smollm2:135m` (~100MB) on first boot, then exits

## docker-compose.yml

```yaml
services:
  private-llm:
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
      private-llm:
        condition: service_healthy
    restart: "no"
    entrypoint: ["sh", "-c", "curl -sf -X POST http://private-llm:8080/api/pull -d '{\"name\":\"smollm2:135m\"}'"]
```

## Querying the LLM

Once deployed, the LLM is reachable through the agent's Cloudflare tunnel:

```bash
curl https://agent-{id}.easyenclave.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"smollm2:135m","messages":[{"role":"user","content":"Say hello"}]}'
```

Using the OpenAI Python client (since Ollama is OpenAI-compatible):

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://agent-{id}.easyenclave.com/v1",
    api_key="unused",  # Ollama doesn't require an API key
)
completion = client.chat.completions.create(
    model="smollm2:135m",
    messages=[{"role": "user", "content": "Say hello"}],
)
print(completion.choices[0].message.content)
```

## End-to-end example (launch VM + deploy + OpenAI test)

Run this script from repo root after authenticating `gcloud`:

```bash
export GCP_PROJECT_ID="<production-project-id>"
export ITA_API_KEY="<ita-api-key>"
export CP_DEPLOYER_API_KEY="<cp-deployer-api-key>"
export CP_URL="https://app.easyenclave.com"
export NODE_SIZE="llm"

bash examples/private-llm/launch-gcp-llm-openai.sh
```

It will:

1. Launch a real GCP TDX VM (`llm` size by default)
2. Wait for agent registration on the control plane
3. Deploy `examples/private-llm/docker-compose.yml` (Ollama + `smollm2:135m`)
4. Run an OpenAI Python client smoke test against the agent URL

You can also run the same flow via GitHub Actions using `CI` workflow dispatch input `run_private_llm_example=true`.
