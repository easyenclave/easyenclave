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
    ingress_rules: list[dict] | None = None,
) -> TunnelInfo:
    """Create a Cloudflare Tunnel for an agent.

    This creates:
    1. A new tunnel named "agent-{agent_id}"
    2. Ingress configuration with path-based routing to multiple ports
    3. A DNS CNAME record for agent-{agent_id}.{domain}

    Args:
        agent_id: The agent's unique ID
        ingress_rules: Optional list of ingress rules like:
            [{"path": "/ollama/*", "port": 11434}, {"path": "/*", "port": 8080}]
            If None, defaults to routing all traffic to port 8081 (agent API)

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

        # Build ingress rules from provided config or default to agent API port
        if ingress_rules:
            ingress = []
            for rule in ingress_rules:
                ingress_entry = {
                    "hostname": hostname,
                    "service": f"http://localhost:{rule['port']}",
                }
                if "path" in rule:
                    ingress_entry["path"] = rule["path"]
                ingress.append(ingress_entry)
            # Add catch-all
            ingress.append({"service": "http_status:404"})
        else:
            # Default: route all traffic to agent API at 8081
            ingress = [
                {
                    "hostname": hostname,
                    "service": "http://localhost:8081",
                },
                {"service": "http_status:404"},
            ]

        config_resp = await client.put(
            f"{CLOUDFLARE_API_URL}/accounts/{CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/{tunnel_id}/configurations",
            headers=headers,
            json={"config": {"ingress": ingress}},
        )
        config_resp.raise_for_status()
        logger.info(f"Tunnel ingress configured with {len(ingress) - 1} rule(s)")

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
            logger.info(f"DNS record already exists (status {dns_resp.status_code})")
        elif dns_resp.status_code != 200:
            # Log the error response before raising
            logger.error(
                f"DNS record creation failed (status {dns_resp.status_code}): {dns_resp.text}"
            )
            dns_resp.raise_for_status()
        else:
            logger.info("DNS record created")

        return TunnelInfo(
            tunnel_id=tunnel_id,
            tunnel_token=tunnel_token,
            hostname=hostname,
        )


async def update_tunnel_ingress(
    tunnel_id: str,
    hostname: str,
    ingress_rules: list[dict] | None = None,
) -> bool:
    """Update the ingress configuration for an existing tunnel.

    Args:
        tunnel_id: The tunnel UUID
        hostname: The tunnel hostname (e.g., agent-xyz.easyenclave.com)
        ingress_rules: List of ingress rules like:
            [{"path": "/ollama/*", "port": 11434}, {"path": "/*", "port": 8080}]
            If None, defaults to port 8081

    Returns:
        True if updated successfully, False otherwise
    """
    if not is_configured():
        logger.warning("Cloudflare not configured, cannot update tunnel ingress")
        return False

    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json",
    }

    # Build ingress rules
    if ingress_rules:
        ingress = []
        for rule in ingress_rules:
            ingress_entry = {
                "hostname": hostname,
                "service": f"http://localhost:{rule['port']}",
            }
            if "path" in rule:
                ingress_entry["path"] = rule["path"]
            ingress.append(ingress_entry)
        ingress.append({"service": "http_status:404"})
    else:
        ingress = [
            {"hostname": hostname, "service": "http://localhost:8081"},
            {"service": "http_status:404"},
        ]

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.put(
                f"{CLOUDFLARE_API_URL}/accounts/{CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/{tunnel_id}/configurations",
                headers=headers,
                json={"config": {"ingress": ingress}},
            )
            resp.raise_for_status()
            logger.info(f"Updated tunnel {tunnel_id} ingress with {len(ingress) - 1} rule(s)")
            return True
        except Exception as e:
            logger.error(f"Failed to update tunnel ingress: {e}")
            return False


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
