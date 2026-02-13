"""External agent provisioner integration.

The control plane computes placement/capacity shortfalls and can dispatch
requests to an external provisioner service via webhook.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from .settings import get_setting, get_setting_int

logger = logging.getLogger(__name__)


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

    timeout = get_setting_int("provisioner.timeout_seconds", fallback=20)
    token = get_setting("provisioner.webhook_token").strip()

    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

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
