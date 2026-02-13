"""Measuring Enclave - Resolves Docker image digests for app version attestation.

Deployed as a TDX workload via the EasyEnclave app store. Receives measurement
requests from the control plane, resolves image tags to immutable digests via
the Docker Registry HTTP API, and posts results back to the callback URL.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import subprocess

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


def _signature_verification_mode() -> str:
    mode = os.getenv("MEASURER_SIGNATURE_VERIFICATION_MODE", "warn").strip().lower()
    if mode not in {"strict", "warn", "disabled"}:
        logger.warning(f"Invalid MEASURER_SIGNATURE_VERIFICATION_MODE '{mode}', defaulting to 'warn'")
        return "warn"
    return mode


def _verify_signature(image: str, digest: str) -> dict:
    """Verify container signature with cosign (keyless OIDC)."""
    mode = _signature_verification_mode()
    if mode == "disabled":
        return {
            "signature_verified": None,
            "signature_error": "signature verification disabled",
            "signed_by": None,
            "transparency_log_index": None,
        }

    issuer = os.getenv("COSIGN_CERTIFICATE_OIDC_ISSUER", "https://token.actions.githubusercontent.com")
    identity_re = os.getenv(
        "COSIGN_CERTIFICATE_IDENTITY_REGEXP",
        r"^https://github.com/.+/.+/.github/workflows/.+@refs/.*$",
    )
    cosign_bin = os.getenv("COSIGN_BIN", "cosign")
    digest_ref = image if "@sha256:" in image else f"{image}@{digest}"

    cmd = [
        cosign_bin,
        "verify",
        "--output",
        "json",
        "--certificate-oidc-issuer",
        issuer,
        "--certificate-identity-regexp",
        identity_re,
        digest_ref,
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except FileNotFoundError:
        return {
            "signature_verified": False,
            "signature_error": f"{cosign_bin} binary not found",
            "signed_by": None,
            "transparency_log_index": None,
        }
    except subprocess.TimeoutExpired:
        return {
            "signature_verified": False,
            "signature_error": f"cosign verify timed out for {digest_ref}",
            "signed_by": None,
            "transparency_log_index": None,
        }

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "cosign verify failed").strip().splitlines()[0]
        return {
            "signature_verified": False,
            "signature_error": err,
            "signed_by": None,
            "transparency_log_index": None,
        }

    transparency_log_index = None
    match = re.search(r'"logIndex"\s*:\s*(\d+)', proc.stdout or "")
    if match:
        try:
            transparency_log_index = int(match.group(1))
        except ValueError:
            transparency_log_index = None

    signed_by = None
    try:
        parsed = json.loads(proc.stdout)
        if isinstance(parsed, list) and parsed:
            cert = parsed[0].get("optional", {}).get("Subject")
            if isinstance(cert, str) and cert:
                signed_by = cert
    except Exception:
        signed_by = None

    return {
        "signature_verified": True,
        "signature_error": None,
        "signed_by": signed_by or identity_re,
        "transparency_log_index": transparency_log_index,
    }


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
        signature_mode = _signature_verification_mode()
        services = compose_dict.get("services", {})
        async with httpx.AsyncClient(timeout=60.0) as client:
            for svc_name, svc_config in services.items():
                image = svc_config.get("image")
                if not image:
                    continue  # Service uses build context, no image to resolve
                try:
                    digest = await resolve_digest(image, client)
                    signature_info = _verify_signature(image, digest)
                    if signature_mode == "strict" and signature_info.get("signature_verified") is not True:
                        err = signature_info.get("signature_error") or "signature verification failed"
                        logger.error(f"Signature verification failed for {image}: {err}")
                        await _post_callback(
                            req,
                            status="failed",
                            error=f"Failed signature verification for image '{image}': {err}",
                        )
                        return
                    resolved_images[svc_name] = {
                        "original": image,
                        "digest": digest,
                        "signature_verified": signature_info.get("signature_verified"),
                        "signed_by": signature_info.get("signed_by"),
                        "transparency_log_index": signature_info.get("transparency_log_index"),
                        "signature_error": signature_info.get("signature_error"),
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
