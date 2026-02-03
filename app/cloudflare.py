"""Cloudflare Tunnel management for EasyEnclave agents.

This module provides functions to create and manage Cloudflare Tunnels
for agents that register with the control plane. Each agent gets its own
tunnel with a DNS entry like agent-{agent_id}.easyenclave.com.

Environment variables required:
- CLOUDFLARE_ACCOUNT_ID: Cloudflare account ID
- CLOUDFLARE_ZONE_ID: Zone ID for the domain (e.g., easyenclave.com)
- CLOUDFLARE_API_TOKEN: API token with Tunnel and DNS edit permissions
- EASYENCLAVE_DOMAIN: Domain for agent hostnames (default: easyenclave.com)
"""

from __future__ import annotations

import base64
import logging
import os
import secrets
from typing import TypedDict

import httpx

logger = logging.getLogger(__name__)

CLOUDFLARE_API_URL = "https://api.cloudflare.com/client/v4"
CLOUDFLARE_ACCOUNT_ID = os.environ.get("CLOUDFLARE_ACCOUNT_ID")
CLOUDFLARE_ZONE_ID = os.environ.get("CLOUDFLARE_ZONE_ID")
CLOUDFLARE_API_TOKEN = os.environ.get("CLOUDFLARE_API_TOKEN")
EASYENCLAVE_DOMAIN = os.environ.get("EASYENCLAVE_DOMAIN", "easyenclave.com")


class TunnelInfo(TypedDict):
    """Information about a created Cloudflare Tunnel."""

    tunnel_id: str
    tunnel_token: str
    hostname: str


def is_configured() -> bool:
    """Check if Cloudflare credentials are configured."""
    return all([CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_ZONE_ID, CLOUDFLARE_API_TOKEN])


async def create_tunnel_for_agent(
    agent_id: str,
    service_port: int = 8081,
) -> TunnelInfo:
    """Create a Cloudflare Tunnel for an agent.

    This creates:
    1. A new tunnel named "agent-{agent_id}"
    2. Ingress configuration routing to localhost:{service_port}
    3. A DNS CNAME record for agent-{agent_id}.{domain}

    The tunnel routes to the agent API server (port 8081), which handles
    /api/* requests itself and proxies other requests to the workload.

    Args:
        agent_id: The agent's unique ID
        service_port: Port the agent API server listens on (default 8081)

    Returns:
        TunnelInfo with tunnel_id, tunnel_token, and hostname

    Raises:
        RuntimeError: If Cloudflare credentials not configured
        httpx.HTTPStatusError: If Cloudflare API calls fail
    """
    if not is_configured():
        raise RuntimeError("Cloudflare credentials not configured")

    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json",
    }

    tunnel_name = f"agent-{agent_id}"
    hostname = f"{tunnel_name}.{EASYENCLAVE_DOMAIN}"

    # Generate tunnel secret (32 random bytes, base64 encoded)
    tunnel_secret = base64.b64encode(secrets.token_bytes(32)).decode()

    async with httpx.AsyncClient(timeout=30.0) as client:
        # 1. Create tunnel
        logger.info(f"Creating Cloudflare tunnel: {tunnel_name}")
        create_resp = await client.post(
            f"{CLOUDFLARE_API_URL}/accounts/{CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel",
            headers=headers,
            json={
                "name": tunnel_name,
                "tunnel_secret": tunnel_secret,
            },
        )
        create_resp.raise_for_status()
        tunnel_data = create_resp.json()["result"]
        tunnel_id = tunnel_data["id"]
        tunnel_token = tunnel_data["token"]
        logger.info(f"Created tunnel: {tunnel_id}")

        # 2. Configure ingress
        logger.info(f"Configuring tunnel ingress for {hostname}")
        config_resp = await client.put(
            f"{CLOUDFLARE_API_URL}/accounts/{CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/{tunnel_id}/configurations",
            headers=headers,
            json={
                "config": {
                    "ingress": [
                        {
                            "hostname": hostname,
                            "service": f"http://localhost:{service_port}",
                        },
                        {"service": "http_status:404"},  # catch-all required
                    ]
                }
            },
        )
        config_resp.raise_for_status()
        logger.info("Tunnel ingress configured")

        # 3. Create DNS CNAME record
        logger.info(f"Creating DNS record for {hostname}")
        dns_resp = await client.post(
            f"{CLOUDFLARE_API_URL}/zones/{CLOUDFLARE_ZONE_ID}/dns_records",
            headers=headers,
            json={
                "type": "CNAME",
                "name": tunnel_name,
                "content": f"{tunnel_id}.cfargotunnel.com",
                "proxied": True,
            },
        )
        # Ignore 409 conflict if DNS already exists (idempotent)
        if dns_resp.status_code == 409 or (
            dns_resp.status_code != 200 and "already exists" in dns_resp.text.lower()
        ):
            logger.info("DNS record already exists")
        else:
            dns_resp.raise_for_status()
            logger.info("DNS record created")

        return TunnelInfo(
            tunnel_id=tunnel_id,
            tunnel_token=tunnel_token,
            hostname=hostname,
        )


async def get_or_create_tunnel(
    name: str,
    hostname: str,
    service: str = "http://localhost:8080",
) -> TunnelInfo:
    """Get existing tunnel or create new one.

    This is idempotent - if a tunnel with the given name exists,
    it returns that tunnel's info. Otherwise creates a new one.

    Args:
        name: Tunnel name (e.g., "easyenclave-control-plane")
        hostname: Full hostname (e.g., "app.easyenclave.com")
        service: Backend service URL (default "http://localhost:8080")

    Returns:
        TunnelInfo with tunnel_id, tunnel_token, and hostname
    """
    if not is_configured():
        raise RuntimeError("Cloudflare credentials not configured")

    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        # Try to find existing tunnel by name
        logger.info(f"Looking for existing tunnel: {name}")
        list_resp = await client.get(
            f"{CLOUDFLARE_API_URL}/accounts/{CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel",
            headers=headers,
            params={"name": name, "is_deleted": "false"},
        )
        list_resp.raise_for_status()
        tunnels = list_resp.json().get("result", [])

        if tunnels:
            # Found existing tunnel - get its token
            tunnel = tunnels[0]
            tunnel_id = tunnel["id"]
            logger.info(f"Found existing tunnel: {tunnel_id}")

            # Get tunnel token
            token_resp = await client.get(
                f"{CLOUDFLARE_API_URL}/accounts/{CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/{tunnel_id}/token",
                headers=headers,
            )
            token_resp.raise_for_status()
            tunnel_token = token_resp.json()["result"]

            return TunnelInfo(
                tunnel_id=tunnel_id,
                tunnel_token=tunnel_token,
                hostname=hostname,
            )

        # Create new tunnel
        logger.info(f"Creating new tunnel: {name}")
        tunnel_secret = base64.b64encode(secrets.token_bytes(32)).decode()

        create_resp = await client.post(
            f"{CLOUDFLARE_API_URL}/accounts/{CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel",
            headers=headers,
            json={
                "name": name,
                "tunnel_secret": tunnel_secret,
            },
        )
        create_resp.raise_for_status()
        tunnel_data = create_resp.json()["result"]
        tunnel_id = tunnel_data["id"]
        tunnel_token = tunnel_data["token"]
        logger.info(f"Created tunnel: {tunnel_id}")

        # Configure ingress
        logger.info(f"Configuring ingress for {hostname} -> {service}")
        config_resp = await client.put(
            f"{CLOUDFLARE_API_URL}/accounts/{CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/{tunnel_id}/configurations",
            headers=headers,
            json={
                "config": {
                    "ingress": [
                        {"hostname": hostname, "service": service},
                        {"service": "http_status:404"},
                    ]
                }
            },
        )
        config_resp.raise_for_status()

        # Create DNS record (extract subdomain from hostname)
        subdomain = hostname.replace(f".{EASYENCLAVE_DOMAIN}", "")
        logger.info(f"Creating DNS record: {subdomain} -> {tunnel_id}.cfargotunnel.com")
        dns_resp = await client.post(
            f"{CLOUDFLARE_API_URL}/zones/{CLOUDFLARE_ZONE_ID}/dns_records",
            headers=headers,
            json={
                "type": "CNAME",
                "name": subdomain,
                "content": f"{tunnel_id}.cfargotunnel.com",
                "proxied": True,
            },
        )
        if dns_resp.status_code not in (200, 409):
            if "already exists" not in dns_resp.text.lower():
                dns_resp.raise_for_status()

        return TunnelInfo(
            tunnel_id=tunnel_id,
            tunnel_token=tunnel_token,
            hostname=hostname,
        )


async def delete_tunnel(tunnel_id: str) -> bool:
    """Delete a Cloudflare Tunnel.

    Note: This also removes the tunnel's DNS record automatically
    when the tunnel is deleted.

    Args:
        tunnel_id: The tunnel UUID to delete

    Returns:
        True if deleted, False if not found or error
    """
    if not is_configured():
        logger.warning("Cloudflare not configured, cannot delete tunnel")
        return False

    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            # First, clean up any connections
            cleanup_resp = await client.delete(
                f"{CLOUDFLARE_API_URL}/accounts/{CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/{tunnel_id}/connections",
                headers=headers,
            )
            if cleanup_resp.status_code == 200:
                logger.info(f"Cleaned up tunnel connections: {tunnel_id}")

            # Delete the tunnel
            delete_resp = await client.delete(
                f"{CLOUDFLARE_API_URL}/accounts/{CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/{tunnel_id}",
                headers=headers,
            )

            if delete_resp.status_code == 200:
                logger.info(f"Deleted tunnel: {tunnel_id}")
                return True
            elif delete_resp.status_code == 404:
                logger.warning(f"Tunnel not found: {tunnel_id}")
                return False
            else:
                logger.error(f"Failed to delete tunnel: {delete_resp.text}")
                return False

        except Exception as e:
            logger.error(f"Error deleting tunnel {tunnel_id}: {e}")
            return False


async def delete_dns_record(hostname: str) -> bool:
    """Delete a DNS record by hostname.

    Args:
        hostname: Full hostname (e.g., "agent-abc123.easyenclave.com")

    Returns:
        True if deleted, False if not found or error
    """
    if not is_configured():
        return False

    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            # Find the DNS record
            list_resp = await client.get(
                f"{CLOUDFLARE_API_URL}/zones/{CLOUDFLARE_ZONE_ID}/dns_records",
                headers=headers,
                params={"name": hostname, "type": "CNAME"},
            )
            list_resp.raise_for_status()
            records = list_resp.json().get("result", [])

            if not records:
                logger.warning(f"DNS record not found: {hostname}")
                return False

            # Delete the record
            record_id = records[0]["id"]
            delete_resp = await client.delete(
                f"{CLOUDFLARE_API_URL}/zones/{CLOUDFLARE_ZONE_ID}/dns_records/{record_id}",
                headers=headers,
            )

            if delete_resp.status_code == 200:
                logger.info(f"Deleted DNS record: {hostname}")
                return True
            else:
                logger.error(f"Failed to delete DNS record: {delete_resp.text}")
                return False

        except Exception as e:
            logger.error(f"Error deleting DNS record {hostname}: {e}")
            return False
