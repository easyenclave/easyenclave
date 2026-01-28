"""Proxy service for routing requests to services via Cloudflare tunnels.

This module provides the proxy functionality that allows clients to route
requests to services through the control plane. The control plane acts as
a trusted intermediary that has been attested via TDX.

Trust flow:
1. Client verifies CP attestation via /api/v1/attestation
2. Client gets proxy endpoint via /api/v1/proxy
3. Client routes requests through /proxy/{service}/{path}
4. CP forwards to service via Cloudflare tunnel
"""

from __future__ import annotations

import logging

import httpx
from fastapi import HTTPException, Request, Response

from .storage import agent_store, store

logger = logging.getLogger(__name__)

# Default timeout for proxied requests
PROXY_TIMEOUT = 30.0


async def get_service_url(service_name: str) -> str:
    """Get the URL for a service by name.

    Looks up the service in two places:
    1. Agent store - deployed services with tunnel hostnames
    2. Service registry - registered services with endpoints

    Only routes to agents that are deployed AND have valid attestation.
    Agents with attestation_failed status are excluded.

    Args:
        service_name: Name of the service

    Returns:
        Service URL (e.g., "https://agent-xyz.easyenclave.com")

    Raises:
        HTTPException: If service not found or attestation invalid
    """
    # First, check deployed agents for a service with this name
    for agent in agent_store.list():
        # Only route to deployed agents with valid attestation
        if agent.status == "deployed" and agent.hostname:
            # Check attestation status
            if not agent.attestation_valid:
                logger.warning(
                    f"Skipping agent {agent.agent_id} - attestation invalid: "
                    f"{agent.attestation_error}"
                )
                continue

            # Check if deployment config has this service name
            deployment_id = agent.current_deployment_id
            if deployment_id:
                from .storage import deployment_store

                deployment = deployment_store.get(deployment_id)
                if deployment:
                    config = deployment.config or {}
                    if config.get("service_name") == service_name:
                        return f"https://{agent.hostname}"

        # Explicitly refuse to route to attestation_failed agents
        if agent.status == "attestation_failed":
            deployment_id = agent.current_deployment_id
            if deployment_id:
                from .storage import deployment_store

                deployment = deployment_store.get(deployment_id)
                if deployment:
                    config = deployment.config or {}
                    if config.get("service_name") == service_name:
                        raise HTTPException(
                            status_code=503,
                            detail=f"Service '{service_name}' attestation failed - service unavailable",
                        )

    # Second, check the service registry
    service = store.get_by_name(service_name)
    if service:
        # Get the first available endpoint (prefer "prod")
        if "prod" in service.endpoints:
            return service.endpoints["prod"]
        if service.endpoints:
            return next(iter(service.endpoints.values()))

    raise HTTPException(
        status_code=404,
        detail=f"Service not found: {service_name}",
    )


async def proxy_request(
    service_name: str,
    path: str,
    request: Request,
) -> Response:
    """Proxy a request to a service.

    Args:
        service_name: Name of the target service
        path: Path to forward (without leading /)
        request: Original FastAPI request

    Returns:
        Response from the service

    Raises:
        HTTPException: If service not found or request fails
    """
    # Get service URL
    service_url = await get_service_url(service_name)

    # Build target URL
    target_url = f"{service_url}/{path}"
    if request.url.query:
        target_url = f"{target_url}?{request.url.query}"

    logger.info(f"Proxying {request.method} to {target_url}")

    # Copy headers, excluding hop-by-hop headers
    excluded_headers = {
        "host",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in excluded_headers
    }

    # Add forwarded headers
    client_host = request.client.host if request.client else "unknown"
    headers["X-Forwarded-For"] = client_host
    headers["X-Forwarded-Proto"] = request.url.scheme
    headers["X-Forwarded-Host"] = request.url.netloc

    try:
        async with httpx.AsyncClient(timeout=PROXY_TIMEOUT) as client:
            # Get request body
            body = await request.body()

            # Make the proxied request
            response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body if body else None,
            )

            # Build response headers, excluding hop-by-hop
            response_headers = {
                k: v
                for k, v in response.headers.items()
                if k.lower() not in excluded_headers
            }

            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=response_headers,
                media_type=response.headers.get("content-type"),
            )

    except httpx.TimeoutException as e:
        logger.warning(f"Proxy timeout: {target_url}")
        raise HTTPException(
            status_code=504,
            detail=f"Service timeout: {service_name}",
        ) from e
    except httpx.ConnectError as e:
        logger.warning(f"Proxy connection error: {target_url} - {e}")
        raise HTTPException(
            status_code=502,
            detail=f"Cannot connect to service: {service_name}",
        ) from e
    except Exception as e:
        logger.error(f"Proxy error: {target_url} - {e}")
        raise HTTPException(
            status_code=502,
            detail=f"Proxy error: {e}",
        ) from e
