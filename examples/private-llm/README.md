# Private LLM with E2E Encryption

Confidential LLM inference using TDX and Noise Protocol for end-to-end encryption.

## Features

- **E2E Encryption**: Noise Protocol ensures traffic is encrypted from client to TEE
- **TDX Attestation**: Verifies the service is running in a trusted execution environment
- **Session Binding**: Cryptographically proves your encrypted channel connects to the attested TEE
- **Simple API**: Uses `easyenclave.noise` library for all the complexity

## Server (~60 lines)

The server uses `NoiseApp` from the easyenclave SDK:

```python
from easyenclave.noise import NoiseApp
import httpx

app = NoiseApp(title="Private LLM", intel_api_key_env="INTEL_API_KEY")

@app.noise_handler("chat")
async def handle_chat(payload: dict) -> dict:
    messages = payload.get("messages", [])
    async with httpx.AsyncClient() as client:
        resp = await client.post("http://ollama:11434/api/chat", json={...})
        return {"message": resp.json().get("message")}
```

## Client (~40 lines)

The client uses `NoiseClient`:

```python
from easyenclave.noise import NoiseClient

async with NoiseClient("wss://service.example.com/ws/noise") as client:
    result = await client.verify()
    if result.secure:
        response = await client.call("chat", {"messages": [...]})
```

## Deployment

1. Deploy to a TDX-enabled VM via EasyEnclave
2. Set `INTEL_API_KEY` environment variable
3. The service will automatically:
   - Generate TDX attestation on startup
   - Bind a session key to the attestation
   - Handle Noise Protocol handshakes
   - Provide `/health`, `/attestation`, and `/ws/noise` endpoints

## Endpoints

| Endpoint | Description |
|----------|-------------|
| GET `/health` | Health check with `noise_pubkey` |
| GET `/attestation` | Attestation info for discovery |
| WebSocket `/ws/noise` | E2E encrypted Noise channel |

## Security Flow

1. Client fetches server's Noise public key from `/health` or EasyEnclave
2. Client connects to `/ws/noise` and performs Noise NK handshake
3. Client requests attestation over the encrypted channel
4. Client verifies:
   - Session binding signature is valid
   - Binding public key hash matches REPORTDATA in TDX quote
   - Intel Trust Authority token is valid
5. Only after verification, client sends sensitive data
