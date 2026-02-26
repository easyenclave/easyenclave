"""External agent provisioner integration.

The control plane computes placement/capacity shortfalls and can dispatch
requests to an external provisioner service via webhook.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from .settings import get_setting, get_setting_int

logger = logging.getLogger(__name__)


def _get_auth_header(token: str) -> dict[str, str]:
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def _get_timeout() -> int:
    return get_setting_int("provisioner.timeout_seconds", fallback=20)


def _get_token(specific_key: str) -> str:
    token = get_setting(specific_key).strip()
    if token:
        return token
    return get_setting("provisioner.webhook_token").strip()


async def dispatch_provision_request(
    *,
    datacenter: str,
    node_size: str,
    count: int,
    reason: str = "",
) -> tuple[bool, int | None, str | None]:
    """Dispatch a provisioning request to the configured webhook.

    Returns:
        Tuple: (dispatched, status_code, detail)
    """
    webhook_url = get_setting("provisioner.webhook_url").strip()
    if not webhook_url:
        return (False, None, "Provisioner webhook is not configured")

    timeout = _get_timeout()
    token = _get_token("provisioner.webhook_token")
    headers = {"Content-Type": "application/json", **_get_auth_header(token)}

    payload = {
        "datacenter": datacenter,
        "node_size": node_size,
        "count": count,
        "reason": reason,
        "requested_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(webhook_url, headers=headers, json=payload)
    except Exception as exc:
        logger.warning(f"Provisioner webhook call failed: {exc}")
        return (False, None, f"Provisioner webhook call failed: {exc}")

    if response.status_code >= 400:
        detail = response.text.strip() or f"HTTP {response.status_code}"
        return (False, response.status_code, detail)

    return (True, response.status_code, None)


async def fetch_external_inventory() -> tuple[bool, int | None, str | None, dict[str, Any]]:
    """Fetch external cloud inventory from provisioner webhook.

    Returns:
        Tuple: (configured, status_code, detail, payload)
    """
    inventory_url = get_setting("provisioner.inventory_url").strip()
    if not inventory_url:
        return (False, None, "External inventory webhook is not configured", {})

    timeout = _get_timeout()
    token = _get_token("provisioner.inventory_token")
    headers = {"Accept": "application/json", **_get_auth_header(token)}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(inventory_url, headers=headers)
    except Exception as exc:
        logger.warning(f"External inventory webhook call failed: {exc}")
        return (True, None, f"External inventory webhook call failed: {exc}", {})

    if response.status_code >= 400:
        detail = response.text.strip() or f"HTTP {response.status_code}"
        return (True, response.status_code, detail, {})

    try:
        payload = response.json()
    except Exception as exc:
        logger.warning(f"External inventory webhook returned non-JSON response: {exc}")
        detail = f"External inventory webhook returned non-JSON response: {exc}"
        return (True, response.status_code, detail, {})

    if not isinstance(payload, dict):
        return (
            True,
            response.status_code,
            "External inventory webhook returned JSON but not an object payload",
            {},
        )

    return (True, response.status_code, None, payload)


async def dispatch_external_cleanup(
    cleanup_request: dict[str, Any],
) -> tuple[bool, bool, int | None, str | None, dict[str, Any]]:
    """Dispatch external cloud cleanup to provisioner webhook.

    Returns:
        Tuple: (configured, dispatched, status_code, detail, payload)
    """
    cleanup_url = get_setting("provisioner.cleanup_url").strip()
    if not cleanup_url:
        return (False, False, None, "External cleanup webhook is not configured", {})

    timeout = _get_timeout()
    token = _get_token("provisioner.cleanup_token")
    headers = {"Content-Type": "application/json", **_get_auth_header(token)}

    payload = {
        **cleanup_request,
        "requested_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(cleanup_url, headers=headers, json=payload)
    except Exception as exc:
        logger.warning(f"External cleanup webhook call failed: {exc}")
        return (True, False, None, f"External cleanup webhook call failed: {exc}", {})

    if response.status_code >= 400:
        detail = response.text.strip() or f"HTTP {response.status_code}"
        return (True, False, response.status_code, detail, {})

    response_payload: dict[str, Any] = {}
    if response.content:
        try:
            parsed = response.json()
            if isinstance(parsed, dict):
                response_payload = parsed
        except Exception:
            response_payload = {}

    return (True, True, response.status_code, None, response_payload)
