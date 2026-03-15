# Private LLM

Run a private Ollama model inside a TDX enclave.

## Model Profiles

- Staging (CPU/no GPU): `smollm2:135m` (default)
- Bare-metal / single H100: `qwen2.5:32b` (via dedicated H100 compose profiles)

## Files

- `docker-compose.yml`: base CPU-safe stack (works in staging)
- `docker-compose.h100.yml`: raw H100 profile (self-contained compose)
- `docker-compose.cp.yml`: control-plane-friendly stack with `/health` and a simple chat UI
- `docker-compose.cp.h100.yml`: control-plane-friendly H100 stack with `/health`, chat UI, and GPU access
- `Caddyfile`: ingress for the control-plane profile
- `ui/`: static chat UI served by the control-plane profile
- `test.py`: smoke test for direct + proxy + OpenAI-compatible paths

## Start In Staging (No GPU)

```bash
OLLAMA_MODEL=smollm2:135m \
  docker compose -f docker-compose.yml up -d
```

## Start In Production (H100)

```bash
OLLAMA_MODEL=qwen2.5:32b \
  docker compose -f docker-compose.h100.yml up -d
```

## Start With Chat UI

This profile keeps `/health` stable for the control plane, serves a browser UI at `/`,
and proxies `/api/*` to Ollama.

```bash
OLLAMA_MODEL=smollm2:135m \
  docker compose -f docker-compose.cp.yml up -d
```

## Start With Chat UI On H100

This profile keeps `/health` stable for the control plane, serves a browser UI at `/`,
and enables NVIDIA GPU access for the model container.

```bash
OLLAMA_MODEL=qwen2.5:32b \
  docker compose -f docker-compose.cp.h100.yml up -d
```

## Query

```bash
curl https://agent-{id}.easyenclave.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen2.5:32b","messages":[{"role":"user","content":"Say hello"}]}'
```

Or through the control plane proxy:

```bash
curl https://app.easyenclave.com/proxy/private-llm/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen2.5:32b","messages":[{"role":"user","content":"Say hello"}]}'
```

## Smoke Test

`test.py` accepts model/time overrides:

- `MODEL` or `OLLAMA_MODEL` (default: `smollm2:135m`)
- `MODEL_TIMEOUT_SECONDS` (default: `300`)

Example:

```bash
MODEL=qwen2.5:32b MODEL_TIMEOUT_SECONDS=900 python3 test.py
```

## Note On Kimi 2.5

As of March 3, 2026, Ollama lists `kimi-k2.5` as `:cloud` (hosted) rather than a local self-hosted model tag. For enclave-private inference, use a local model tag (for example `qwen2.5:32b`) until a local Kimi tag is available.
