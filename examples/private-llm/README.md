# Private LLM with E2E Encryption

Deploy a private LLM with end-to-end encryption to EasyEnclave's confidential computing platform.

## What's Included

```
private-llm/
├── app/
│   ├── Dockerfile      # Python app with Noise Protocol encryption
│   └── main.py         # FastAPI server (~60 lines)
├── docker-compose.yml  # Ollama + encrypted proxy
└── README.md
```

## Deploy to EasyEnclave

### 1. Register the app (one-time setup)

Before deploying, register your app with EasyEnclave:

```bash
curl -X POST https://app.easyenclave.com/api/v1/apps \
  -H "Content-Type: application/json" \
  -d '{
    "name": "private-llm",
    "description": "Private LLM with E2E encryption",
    "source_repo": "your-org/your-repo"
  }'
```

### 2. Copy this directory to your repo

```bash
cp -r examples/private-llm my-private-llm
cd my-private-llm
git init && git add -A && git commit -m "Initial commit"
```

### 3. Add a GitHub workflow

Create `.github/workflows/deploy.yml`:

```yaml
name: Deploy to EasyEnclave
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: easyenclave/easyenclave/.github/actions/deploy@main
        id: deploy
        with:
          app_name: private-llm
          compose_file: docker-compose.yml
          service_name: private-llm

      - run: echo "Deployed ${{ steps.deploy.outputs.version }} to ${{ steps.deploy.outputs.service_url }}"
```

### 4. Push to deploy

```bash
git remote add origin https://github.com/you/my-private-llm
git push -u origin main
```

The action will:
1. Verify the app is registered
2. Publish a new version (with source inspection)
3. Find an available TDX agent
4. Deploy the attested version
5. Wait for health checks to pass
6. Output the service URL

## Features

- **E2E Encryption**: Noise Protocol encrypts traffic from client to TEE
- **TDX Attestation**: Cryptographic proof the service runs in a trusted environment
- **Session Binding**: Proves your encrypted channel connects to the attested TEE
- **Simple SDK**: Uses `easyenclave.noise` library for all complexity
- **Source Inspection**: All versions pass automated source code review

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check with Noise public key |
| `GET /attestation` | Attestation info for verification |
| `WebSocket /ws/noise` | E2E encrypted Noise channel |

## Client Usage

```python
from easyenclave.noise import NoiseClient

async with NoiseClient("wss://your-service.easyenclave.com/ws/noise") as client:
    result = await client.verify()
    if result.secure:
        response = await client.call("chat", {
            "messages": [{"role": "user", "content": "Hello!"}]
        })
        print(response["message"]["content"])
```

## Configuration

Environment variables in `docker-compose.yml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL_NAME` | `qwen2.5:0.5b` | Ollama model to use |
| `INTEL_API_KEY` | - | Intel Trust Authority API key (optional) |

## App Catalog Flow

Deployments follow this flow:

```
Register App (one-time) -> Publish Version -> Source Inspection -> Deploy
```

This ensures all deployed code is inspected and tracked.
