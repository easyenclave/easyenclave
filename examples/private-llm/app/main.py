"""Private LLM Proxy - Confidential AI with E2E Encryption.

This service provides end-to-end encrypted LLM inference using the
easyenclave.noise library. All the Noise Protocol and TDX attestation
complexity is handled by the library.

Usage:
    uvicorn main:app --host 0.0.0.0 --port 8080
"""

import os

import httpx
from easyenclave.noise import NoiseApp

# Configuration
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
MODEL_NAME = os.getenv("MODEL_NAME", "qwen2.5:0.5b")

# Create the app - this handles TDX attestation and Noise setup automatically
app = NoiseApp(
    title="Private LLM",
    intel_api_key_env="INTEL_API_KEY",
)


@app.noise_handler("chat")
async def handle_chat(payload: dict) -> dict:
    """Handle chat messages over E2E encrypted Noise channel."""
    messages = payload.get("messages", [])
    model = payload.get("model", MODEL_NAME)

    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(
            f"{OLLAMA_HOST}/api/chat",
            json={"model": model, "messages": messages, "stream": False},
        )
        resp.raise_for_status()
        result = resp.json()

    return {
        "message": result.get("message", {}),
        "model": model,
        "prompt_tokens": result.get("prompt_eval_count", 0),
        "completion_tokens": result.get("eval_count", 0),
    }


# Optional: Add an endpoint to pull the model on startup
@app.on_event("startup")
async def pull_model():
    """Pull the configured model if not present."""
    async with httpx.AsyncClient(timeout=600.0) as client:
        try:
            resp = await client.get(f"{OLLAMA_HOST}/api/tags")
            if resp.status_code == 200:
                models = [m.get("name", "") for m in resp.json().get("models", [])]
                if MODEL_NAME not in models and not any(MODEL_NAME in m for m in models):
                    print(f"Pulling model {MODEL_NAME}...")
                    await client.post(
                        f"{OLLAMA_HOST}/api/pull",
                        json={"name": MODEL_NAME},
                        timeout=1800.0,
                    )
        except Exception as e:
            print(f"Could not check/pull model: {e}")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
