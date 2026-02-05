"""Measuring Enclave - Resolves Docker image digests for app version attestation.

Deployed as a TDX workload via the EasyEnclave app store. Receives measurement
requests from the control plane, resolves image tags to immutable digests via
the Docker Registry HTTP API, and posts results back to the callback URL.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging

import httpx
import yaml
from fastapi import FastAPI
from pydantic import BaseModel

from registry import resolve_digest

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Measuring Enclave")


class MeasurementRequest(BaseModel):
    """Request from the control plane to measure an app version."""

    version_id: str
    compose: str  # base64-encoded docker-compose.yml
    callback_url: str  # URL to POST results back to


@app.get("/health")
async def health():
    return {"status": "healthy"}


async def _do_measurement(req: MeasurementRequest):
    """Perform the measurement and POST results to the callback URL."""
    try:
        # 1. Decode compose
        compose_bytes = base64.b64decode(req.compose)
        compose_dict = yaml.safe_load(compose_bytes)

        # 2. Compute hash of original compose bytes
        compose_hash = hashlib.sha256(compose_bytes).hexdigest()

        # 3. Resolve image digests for each service
        resolved_images = {}
        services = compose_dict.get("services", {})
        async with httpx.AsyncClient(timeout=60.0) as client:
            for svc_name, svc_config in services.items():
                image = svc_config.get("image")
                if not image:
                    continue  # Service uses build context, no image to resolve
                try:
                    digest = await resolve_digest(image, client)
                    resolved_images[svc_name] = {
                        "original": image,
                        "digest": digest,
                    }
                except Exception as e:
                    logger.error(f"Failed to resolve {image}: {e}")
                    # Report failure for this specific image
                    await _post_callback(req, status="failed", error=f"Failed to resolve image '{image}': {e}")
                    return

        # 4. Build measurement result
        measurement = {
            "compose_hash": compose_hash,
            "resolved_images": resolved_images,
        }

        # 5. POST result to callback
        await _post_callback(req, status="success", measurement=measurement)

    except Exception as e:
        logger.error(f"Measurement failed for {req.version_id}: {e}")
        await _post_callback(req, status="failed", error=str(e))


async def _post_callback(
    req: MeasurementRequest,
    status: str,
    measurement: dict | None = None,
    error: str | None = None,
):
    """POST measurement results to the control plane callback URL."""
    payload = {
        "version_id": req.version_id,
        "status": status,
    }
    if measurement is not None:
        payload["measurement"] = measurement
    if error is not None:
        payload["error"] = error

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(req.callback_url, json=payload)
            resp.raise_for_status()
            logger.info(f"Callback posted for {req.version_id}: {status}")
    except Exception as e:
        logger.error(f"Failed to post callback for {req.version_id}: {e}")


@app.post("/api/measure")
async def measure(req: MeasurementRequest):
    """Accept a measurement request and process it asynchronously."""
    asyncio.create_task(_do_measurement(req))
    return {"status": "accepted", "version_id": req.version_id}
