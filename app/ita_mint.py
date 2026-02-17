"""Intel Trust Authority (ITA) token minting.

The control plane typically *verifies* ITA JWTs via JWKS (app/ita.py). This
module is used when we want the control plane to mint an ITA token from a
TDX quote so agents don't need to carry Intel API keys.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

import httpx


class ITAMintError(RuntimeError):
    pass


def _normalize_ita_base_url(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return "https://api.trustauthority.intel.com"
    raw = raw.rstrip("/")

    # People commonly set ITA_API_URL to ".../appraisal/v2" (launcher compose template).
    # Normalize to the host base so we can append "/appraisal/v1/attest" correctly.
    for suffix in (
        "/appraisal/v2",
        "/appraisal/v1",
        "/appraisal/v1/attest",
    ):
        if raw.endswith(suffix):
            raw = raw[: -len(suffix)]
            raw = raw.rstrip("/")
            break
    return raw


def _ita_attest_url() -> str:
    explicit = (os.environ.get("ITA_ATTEST_URL") or "").strip()
    if explicit:
        return explicit.rstrip("/")
    base = _normalize_ita_base_url(os.environ.get("ITA_API_URL") or os.environ.get("INTEL_API_URL"))
    return f"{base}/appraisal/v1/attest"


def _ita_api_key() -> str:
    return (os.environ.get("ITA_API_KEY") or os.environ.get("INTEL_API_KEY") or "").strip()


async def mint_intel_ta_token(*, quote_b64: str, timeout_seconds: int = 30) -> str:
    """Mint an ITA token from a base64-encoded TDX quote."""
    quote_b64 = (quote_b64 or "").strip()
    if not quote_b64:
        raise ITAMintError("quote_b64 is required")

    api_key = _ita_api_key()
    if not api_key:
        raise ITAMintError("ITA_API_KEY is not set")

    url = _ita_attest_url()
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ITAMintError("Invalid ITA attest URL")

    headers = {
        "x-api-key": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    body = {"quote": quote_b64}
    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        resp = await client.post(url, headers=headers, json=body)
    if resp.status_code >= 400:
        detail = (resp.text or "").strip()
        raise ITAMintError(f"ITA attestation failed (HTTP {resp.status_code}): {detail[:240]}")

    payload = resp.json()
    token = (payload or {}).get("token") if isinstance(payload, dict) else ""
    token = (token or "").strip()
    if not token:
        raise ITAMintError("ITA response did not include token")
    return token
