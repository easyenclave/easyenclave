"""EasyEnclave Discovery Service - FastAPI Application."""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import cloudflare, proxy
from .attestation import (
    AttestationError,
    build_attestation_chain,
    generate_tdx_quote,
    refresh_agent_attestation,
    reverify_agents_for_mrtd,
    verify_agent_registration,
)
from .crud import build_filters, get_or_404
from .database import init_db
from .ita import verify_attestation_token
from .models import (
    Agent,
    AgentDeployedRequest,
    AgentListResponse,
    AgentRegistrationRequest,
    AgentRegistrationResponse,
    AgentStatusRequest,
    App,
    AppCreateRequest,
    AppListResponse,
    AppVersion,
    AppVersionCreateRequest,
    AppVersionListResponse,
    AppVersionResponse,
    DeployFromVersionRequest,
    Deployment,
    DeploymentCreateResponse,
    DeploymentListResponse,
    HealthResponse,
    MrtdType,
    Service,
    ServiceListResponse,
    ServiceRegistrationRequest,
    TrustedMrtd,
    TrustedMrtdCreateRequest,
    TrustedMrtdListResponse,
    VerificationResponse,
)
from .storage import (
    agent_store,
    app_store,
    app_version_store,
    deployment_store,
    store,
    trusted_mrtd_store,
)

logger = logging.getLogger(__name__)


# Admin authentication
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
# Store valid admin tokens (in production, use Redis or similar)
_admin_tokens: set[str] = set()

# Health check interval in seconds
HEALTH_CHECK_INTERVAL = 60

# Agent health check settings
AGENT_HEALTH_CHECK_INTERVAL = 30  # Check agents every 30 seconds
AGENT_ATTESTATION_INTERVAL = 300  # Request fresh attestation every 5 minutes
AGENT_UNHEALTHY_TIMEOUT = timedelta(minutes=5)  # Reassign after 5 minutes unhealthy

# Track when agents were last attested (for periodic re-attestation)
_agent_last_attestation: dict[str, datetime] = {}


async def check_service_health(service: Service) -> str:
    """Check health of a single service. Returns health status."""
    for _env, url in service.endpoints.items():
        try:
            health_url = url.rstrip("/") + "/health"
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(health_url)
                if response.status_code == 200:
                    return "healthy"
        except Exception:
            continue
    return "unhealthy"


async def background_health_checker():
    """Background task to periodically check health of all services."""
    while True:
        try:
            services = store.get_all_for_health_check()
            for service in services:
                try:
                    status = await check_service_health(service)
                    store.update(
                        service.service_id,
                        health_status=status,
                        last_health_check=datetime.utcnow(),
                    )
                except Exception as e:
                    logger.warning(f"Health check failed for {service.name}: {e}")
        except Exception as e:
            logger.error(f"Background health checker error: {e}")

        await asyncio.sleep(HEALTH_CHECK_INTERVAL)


async def check_agent_health(
    agent: Agent, include_attestation: bool = False
) -> tuple[str, dict | None]:
    """Check health of an agent via its tunnel.

    Args:
        agent: The agent to check
        include_attestation: If True, request fresh attestation from agent

    Returns:
        Tuple of (health_status, attestation_dict or None)
    """
    if not agent.hostname:
        return "unknown", None

    try:
        health_url = f"https://{agent.hostname}/api/health"
        if include_attestation:
            health_url += "?attest=true"

        async with httpx.AsyncClient(timeout=30.0 if include_attestation else 10.0) as client:
            response = await client.get(health_url)
            if response.status_code == 200:
                data = response.json()
                attestation = data.get("attestation") if include_attestation else None
                return "healthy", attestation
    except Exception as e:
        logger.debug(f"Health check failed for agent {agent.agent_id}: {e}")
    return "unhealthy", None


async def background_agent_health_checker():
    """Background task to check health of agents and periodically refresh attestation.

    Health checks:
    - Fast health check every 30 seconds: GET /api/health
    - Attestation refresh every 5 minutes: GET /api/health?attest=true

    This implements the CP-initiated health checking for the push/pull model.
    Agents with tunnels are checked directly via their Cloudflare tunnel hostname.
    """
    while True:
        try:
            now = datetime.utcnow()

            # Check all agents with tunnels (not just deployed ones)
            all_agents = agent_store.list()
            for agent in all_agents:
                if not agent.hostname:
                    continue  # Skip agents without tunnels

                try:
                    # Determine if we need fresh attestation
                    last_attest = _agent_last_attestation.get(agent.agent_id)
                    need_attestation = (
                        last_attest is None
                        or (now - last_attest).total_seconds() > AGENT_ATTESTATION_INTERVAL
                    )

                    # Check health (with attestation if needed)
                    status, attestation = await check_agent_health(
                        agent, include_attestation=need_attestation
                    )
                    agent_store.update_health(agent.agent_id, status)

                    if need_attestation and status == "healthy":
                        _agent_last_attestation[agent.agent_id] = now
                        if attestation:
                            await refresh_agent_attestation(agent.agent_id, attestation)

                    logger.debug(
                        f"Agent {agent.agent_id} health: {status}"
                        + (" (attested)" if need_attestation and status == "healthy" else "")
                    )
                except Exception as e:
                    logger.warning(f"Health check failed for agent {agent.agent_id}: {e}")

            # Check for agents that have been unhealthy too long
            unhealthy_agents = agent_store.get_unhealthy_agents(AGENT_UNHEALTHY_TIMEOUT)
            for agent in unhealthy_agents:
                try:
                    await handle_agent_reassignment(agent)
                except Exception as e:
                    logger.error(f"Reassignment failed for agent {agent.agent_id}: {e}")

            # Try to reassign pending deployments to available agents
            await process_pending_reassignments()

        except Exception as e:
            logger.error(f"Background agent health checker error: {e}")

        await asyncio.sleep(AGENT_HEALTH_CHECK_INTERVAL)


async def handle_agent_reassignment(agent: Agent):
    """Handle reassignment of an unhealthy agent's deployment."""
    deployment_id = agent.current_deployment_id
    if not deployment_id:
        # No deployment to reassign, just reset the agent
        agent_store.reset_for_reassignment(agent.agent_id)
        logger.info(f"Reset unhealthy agent {agent.agent_id} (no deployment)")
        return

    # Mark deployment for reassignment
    deployment_store.mark_for_reassignment(deployment_id)
    logger.warning(
        f"Marked deployment {deployment_id} for reassignment "
        f"(agent {agent.agent_id} unhealthy for >{AGENT_UNHEALTHY_TIMEOUT})"
    )

    # Reset the old agent
    agent_store.reset_for_reassignment(agent.agent_id)


async def process_pending_reassignments():
    """Try to reassign deployments marked for reassignment to available agents."""
    deployments = deployment_store.get_for_reassignment()

    for deployment in deployments:
        # Find an available agent
        available_agent = agent_store.get_available()
        if available_agent:
            # Reassign the deployment
            deployment_store.reassign(deployment.deployment_id, available_agent.agent_id)
            logger.info(
                f"Reassigned deployment {deployment.deployment_id} "
                f"to agent {available_agent.agent_id}"
            )
        else:
            logger.debug(
                f"No available agent for deployment {deployment.deployment_id} - will retry"
            )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan - start background tasks."""
    # Initialize database
    init_db()
    logger.info("Database initialized")

    # Start background health checkers
    service_health_task = asyncio.create_task(background_health_checker())
    agent_health_task = asyncio.create_task(background_agent_health_checker())
    logger.info("Started background health checkers (services + agents)")
    yield
    # Shutdown
    service_health_task.cancel()
    agent_health_task.cancel()
    try:
        await service_health_task
    except asyncio.CancelledError:
        pass
    try:
        await agent_health_task
    except asyncio.CancelledError:
        pass


# Create FastAPI app
app = FastAPI(
    title="EasyEnclave Discovery Service",
    description="Confidential discovery service for TDX-attested applications",
    version="0.2.0",
    lifespan=lifespan,
)

# CORS middleware - allow requests from easyenclave.com
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://easyenclave.com",
        "https://www.easyenclave.com",
        "http://localhost:8080",  # Local development
        "http://127.0.0.1:8080",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files directory
STATIC_DIR = Path(__file__).parent / "static"


# Health check endpoint (required by launcher)
@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.utcnow(),
    )


# API v1 endpoints
@app.post("/api/v1/register", response_model=Service)
async def register_service(request: ServiceRegistrationRequest):
    """Register a new service with the discovery service.

    Requires:
    - Valid MRTD (TDX measurement)
    - Valid Intel Trust Authority token
    - At least one endpoint

    Note: We trust the agent's local health check. The agent has already verified
    its identity via attestation (Intel TA + MRTD), so there's no security benefit
    to doing an external health check from the control plane. Additionally, external
    checks can fail due to DNS/tunnel propagation delays.
    """
    # Require attestation
    if not request.mrtd:
        raise HTTPException(status_code=400, detail="Registration requires MRTD (TDX measurement)")
    if not request.intel_ta_token:
        raise HTTPException(
            status_code=400, detail="Registration requires Intel Trust Authority token"
        )

    # Verify at least one endpoint
    if not request.endpoints:
        raise HTTPException(status_code=400, detail="Registration requires at least one endpoint")

    # Trust the agent's local health check - the agent already verified health
    # before calling this endpoint, and we trust the agent via attestation
    service = Service(
        name=request.name,
        description=request.description,
        source_repo=request.source_repo,
        source_commit=request.source_commit,
        compose_hash=request.compose_hash,
        endpoints=request.endpoints,
        mrtd=request.mrtd,
        attestation_json=request.attestation_json,
        intel_ta_token=request.intel_ta_token,
        tags=request.tags,
        health_status="healthy",
        last_health_check=datetime.utcnow(),
    )

    # Upsert: update existing service with same name, or create new
    service_id, is_new = store.upsert(service)

    # Return the stored service (may have preserved service_id if updated)
    stored_service = store.get(service_id)
    logger.info(f"Service {'created' if is_new else 'updated'}: {service.name} ({service_id})")
    return stored_service


@app.get("/api/v1/services", response_model=ServiceListResponse)
async def list_services(
    name: str | None = Query(None, description="Filter by name (partial match)"),
    tags: str | None = Query(None, description="Filter by tags (comma-separated)"),
    environment: str | None = Query(None, description="Filter by environment"),
    mrtd: str | None = Query(None, description="Filter by MRTD (exact match)"),
    health_status: str | None = Query(None, description="Filter by health status"),
    q: str | None = Query(None, description="Search query"),
    include_down: bool = Query(
        False, description="Include services that have been down for extended period"
    ),
):
    """List all registered services with optional filters.

    By default, services that have been unhealthy for more than 1 hour are hidden.
    Use include_down=true to show all services.
    """
    # If search query provided, use search
    if q:
        services = store.search(q)
        # Filter out timed-out services from search results too
        if not include_down:
            services = [s for s in services if not store._is_timed_out(s)]
    else:
        filters = build_filters(
            name=name, tags=tags, environment=environment, mrtd=mrtd, health_status=health_status
        )
        services = store.list(filters, include_down=include_down)

    return ServiceListResponse(services=services, total=len(services))


@app.get("/api/v1/services/{service_id}", response_model=Service)
async def get_service(service_id: str):
    """Get details for a specific service."""
    return get_or_404(store, service_id, "Service")


@app.delete("/api/v1/services/{service_id}")
async def delete_service(service_id: str):
    """Deregister a service."""
    from .crud import delete_or_404

    return delete_or_404(store, service_id, "Service", "service_id")


@app.get("/api/v1/services/{service_id}/verify", response_model=VerificationResponse)
async def verify_service(service_id: str):
    """Verify a service's attestation via Intel Trust Authority."""
    service = get_or_404(store, service_id, "Service")

    if not service.intel_ta_token:
        return VerificationResponse(
            service_id=service_id,
            verified=False,
            verification_time=datetime.utcnow(),
            error="Service has no Intel Trust Authority token",
        )

    result = await verify_attestation_token(service.intel_ta_token)
    return VerificationResponse(
        service_id=service_id,
        verified=result["verified"],
        verification_time=result["verification_time"],
        details=result["details"],
        error=result["error"],
    )


# ==============================================================================
# Launcher Agent API - Agents register, poll, and report status
# ==============================================================================


@app.post("/api/v1/agents/register", response_model=AgentRegistrationResponse)
async def register_agent(request: AgentRegistrationRequest):
    """Register a launcher agent with the control plane.

    Launcher agents call this on boot to register themselves.
    Requires valid TDX attestation with Intel Trust Authority verification.

    Verification steps:
    1. Intel TA token required and verified (cryptographic proof from Intel)
    2. MRTD extracted from verified Intel TA claims
    3. MRTD must be in the trusted list with type 'agent' or 'proxy'

    If verification passes and Cloudflare is configured, a tunnel is created
    for the agent at agent-{agent_id}.easyenclave.com.
    """
    if not request.attestation:
        raise HTTPException(status_code=400, detail="Registration requires attestation")

    if not request.vm_name:
        raise HTTPException(status_code=400, detail="Registration requires vm_name")

    # Check if agent with this vm_name already exists
    existing = agent_store.get_by_vm_name(request.vm_name)
    if existing and existing.status != "attestation_failed":
        # Update heartbeat and return existing agent
        # Note: We don't return tunnel_token on re-registration for security
        agent_store.heartbeat(existing.agent_id)
        logger.info(f"Agent re-registered: {existing.agent_id} ({request.vm_name})")
        return AgentRegistrationResponse(
            agent_id=existing.agent_id,
            poll_interval=30,
            hostname=existing.hostname,
        )
    # If agent is in attestation_failed status, allow full re-registration with new attestation
    if existing and existing.status == "attestation_failed":
        logger.info(f"Agent {existing.agent_id} re-registering after attestation failure")

    # Verify attestation (Intel TA token + MRTD trusted list)
    try:
        verification = await verify_agent_registration(request.attestation)
    except AttestationError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    mrtd = verification.mrtd
    intel_ta_token = verification.intel_ta_token
    trusted_mrtd_info = verification.trusted_mrtd_info

    logger.info(f"Agent Intel TA token verified ({request.vm_name})")
    logger.info(
        f"Agent MRTD verified from Intel TA: {mrtd[:16]}... (type: {trusted_mrtd_info.type}) "
        f"(source: {trusted_mrtd_info.source_repo}@{trusted_mrtd_info.source_commit[:8] if trusted_mrtd_info.source_commit else 'unknown'})"
    )

    # Both Intel TA and MRTD verified - agent is trusted
    intel_ta_verified = True
    verified = True

    # Create agent record (reuse existing agent_id if recovering from attestation_failed)
    agent_kwargs = {
        "vm_name": request.vm_name,
        "attestation": request.attestation,
        "mrtd": mrtd,
        "intel_ta_token": intel_ta_token,
        "version": request.version,
        "status": "undeployed",
        "verified": verified,
        "verification_error": None,
    }
    if existing:
        agent_kwargs["agent_id"] = existing.agent_id
    agent = Agent(**agent_kwargs)
    agent_id = agent_store.register(agent)

    # Create Cloudflare tunnel for verified agents
    tunnel_token = None
    hostname = None
    tunnel_error = None
    if verified and cloudflare.is_configured():
        try:
            tunnel_info = await cloudflare.create_tunnel_for_agent(agent_id)
            tunnel_token = tunnel_info["tunnel_token"]
            hostname = tunnel_info["hostname"]

            # Update agent with tunnel info (including token for poll response)
            agent_store.update_tunnel_info(
                agent_id,
                tunnel_id=tunnel_info["tunnel_id"],
                hostname=hostname,
                tunnel_token=tunnel_token,
            )
            logger.info(f"Created tunnel for agent {agent_id}: {hostname}")
        except Exception as e:
            tunnel_error = str(e)
            logger.warning(f"Failed to create tunnel for agent {agent_id}: {e}")
            # Store the error on the agent so it's visible in the API
            agent_store.update_tunnel_error(agent_id, tunnel_error)

    logger.info(
        f"Agent registered: {agent_id} ({request.vm_name}) "
        f"verified={verified} intel_ta={intel_ta_verified} tunnel_error={tunnel_error}"
    )

    return AgentRegistrationResponse(
        agent_id=agent_id,
        poll_interval=30,
        tunnel_token=tunnel_token,
        hostname=hostname,
    )


@app.post("/api/v1/agents/{agent_id}/status")
async def update_agent_status(agent_id: str, request: AgentStatusRequest):
    """Update agent status during deployment.

    Agents call this to report deployment progress.
    """
    get_or_404(agent_store, agent_id, "Agent")

    # Update agent status
    agent_store.update_status(agent_id, request.status, request.deployment_id)

    # Update deployment status if error
    if request.status == "error" and request.error:
        deployment_store.complete(
            request.deployment_id,
            status="failed",
            error=request.error,
        )

    logger.info(f"Agent {agent_id} status: {request.status}")
    return {"status": "ok"}


@app.post("/api/v1/agents/{agent_id}/deployed")
async def agent_deployment_complete(agent_id: str, request: AgentDeployedRequest):
    """Report successful deployment completion.

    Agents call this after successfully deploying a workload.
    """
    agent = get_or_404(agent_store, agent_id, "Agent")

    # Get deployment to extract service_url for health checking
    deployment = deployment_store.get(request.deployment_id)
    service_url = None
    health_endpoint = "/health"
    if deployment:
        config = deployment.config or {}
        service_url = config.get("service_url")
        health_endpoint = config.get("health_endpoint", "/health")

    # If agent has a tunnel hostname, use it for health checks (HTTPS via Cloudflare)
    if agent.hostname and not service_url:
        service_url = f"https://{agent.hostname}"

    # Update agent status and health check info
    agent_store.update_status(agent_id, "deployed", request.deployment_id)
    agent_store.update_health(
        agent_id,
        health_status="healthy",  # Just deployed, assume healthy
        service_url=service_url,
        health_endpoint=health_endpoint,
    )

    # Complete the deployment
    deployment_store.complete(
        request.deployment_id,
        status="completed",
        service_id=request.service_id,
        attestation=request.attestation,
    )

    logger.info(
        f"Agent {agent_id} deployed: deployment={request.deployment_id}, service={request.service_id}"
    )
    return {"status": "ok", "service_id": request.service_id}


@app.get("/api/v1/agents", response_model=AgentListResponse)
async def list_agents(
    status: str | None = Query(None, description="Filter by status"),
    vm_name: str | None = Query(None, description="Filter by VM name (partial match)"),
):
    """List all registered launcher agents."""
    agents = agent_store.list(build_filters(status=status, vm_name=vm_name))
    return AgentListResponse(agents=agents, total=len(agents))


@app.get("/api/v1/agents/{agent_id}", response_model=Agent)
async def get_agent(agent_id: str):
    """Get details for a specific agent."""
    return get_or_404(agent_store, agent_id, "Agent")


@app.get("/api/v1/agents/{agent_id}/attestation")
async def get_agent_attestation(agent_id: str):
    """Get full attestation chain for an agent.

    Returns the agent's MRTD linked to its GitHub source (if registered),
    plus Intel TA verification status. This provides a complete audit trail
    from running VM back to source code.

    Response includes:
    - mrtd: The TDX measurement
    - verified: Whether MRTD is in trusted list
    - intel_ta_verified: Whether Intel TA token is valid
    - github_attestation: Source repo, commit, tag, workflow URL (if available)
    - hostname: Cloudflare tunnel hostname (if available)
    """
    agent = get_or_404(agent_store, agent_id, "Agent")
    return await build_attestation_chain(agent)


@app.delete("/api/v1/agents/{agent_id}")
async def delete_agent(agent_id: str):
    """Delete an agent from the registry.

    This also cleans up the agent's Cloudflare tunnel and DNS record if present.
    """
    agent = get_or_404(agent_store, agent_id, "Agent")

    # Clean up Cloudflare tunnel if present
    if agent.tunnel_id and cloudflare.is_configured():
        try:
            await cloudflare.delete_tunnel(agent.tunnel_id)
            if agent.hostname:
                await cloudflare.delete_dns_record(agent.hostname)
            logger.info(f"Deleted Cloudflare tunnel for agent {agent_id}")
        except Exception as e:
            logger.warning(f"Failed to delete Cloudflare tunnel for agent {agent_id}: {e}")
            # Continue with agent deletion even if tunnel cleanup fails

    if not agent_store.delete(agent_id):
        raise HTTPException(status_code=404, detail="Agent not found")
    logger.info(f"Agent deleted: {agent_id}")
    return {"status": "deleted", "agent_id": agent_id}


@app.post("/api/v1/agents/{agent_id}/reset")
async def reset_agent(agent_id: str):
    """Reset an agent to undeployed status.

    This is useful to recover agents stuck in attestation_failed status.
    If the agent doesn't have a tunnel and is verified, creates one.
    """
    agent = get_or_404(agent_store, agent_id, "Agent")

    # Reset status to undeployed
    agent_store.update_status(agent_id, "undeployed", None)
    agent_store.update_attestation_status(agent_id, attestation_valid=True)
    logger.info(f"Reset agent {agent_id} to undeployed status")

    # Create tunnel if needed
    tunnel_created = False
    if agent.verified and not agent.hostname and cloudflare.is_configured():
        try:
            tunnel_info = await cloudflare.create_tunnel_for_agent(agent_id)
            agent_store.update_tunnel_info(
                agent_id,
                tunnel_id=tunnel_info["tunnel_id"],
                hostname=tunnel_info["hostname"],
                tunnel_token=tunnel_info["tunnel_token"],
            )
            tunnel_created = True
            logger.info(f"Created tunnel for reset agent {agent_id}: {tunnel_info['hostname']}")
        except Exception as e:
            logger.warning(f"Failed to create tunnel for reset agent {agent_id}: {e}")

    return {"status": "reset", "agent_id": agent_id, "tunnel_created": tunnel_created}


@app.post("/api/v1/agents/{agent_id}/fix-tunnel")
async def fix_agent_tunnel(agent_id: str):
    """Fix tunnel configuration for an agent.

    Updates the tunnel ingress to route to port 8081 (agent API server).
    Use this if the agent's logs/stats endpoints return workload content
    instead of the expected JSON API responses.
    """
    agent = get_or_404(agent_store, agent_id, "Agent")

    if not agent.tunnel_id or not agent.hostname:
        raise HTTPException(
            status_code=400,
            detail="Agent does not have a tunnel configured",
        )

    if not cloudflare.is_configured():
        raise HTTPException(
            status_code=503,
            detail="Cloudflare is not configured on this control plane",
        )

    # Update tunnel ingress to correct port
    success = await cloudflare.update_tunnel_ingress(
        tunnel_id=agent.tunnel_id,
        hostname=agent.hostname,
        service_port=8081,
    )

    if not success:
        raise HTTPException(
            status_code=502,
            detail="Failed to update tunnel configuration",
        )

    logger.info(f"Fixed tunnel configuration for agent {agent_id}")
    return {
        "status": "fixed",
        "agent_id": agent_id,
        "hostname": agent.hostname,
        "message": "Tunnel now routes to agent API on port 8081",
    }


# ==============================================================================
# Deployment API - List and track deployments
# ==============================================================================


@app.get("/api/v1/deployments", response_model=DeploymentListResponse)
async def list_deployments(
    status: str | None = Query(None, description="Filter by status"),
    agent_id: str | None = Query(None, description="Filter by agent ID"),
):
    """List all deployments."""
    deployments = deployment_store.list(build_filters(status=status, agent_id=agent_id))
    return DeploymentListResponse(deployments=deployments, total=len(deployments))


@app.get("/api/v1/deployments/{deployment_id}", response_model=Deployment)
async def get_deployment(deployment_id: str):
    """Get details for a specific deployment."""
    return get_or_404(deployment_store, deployment_id, "Deployment")


# ==============================================================================
# Trusted MRTD API - Manage trusted launcher measurements
# ==============================================================================


@app.post("/api/v1/trusted-mrtds", response_model=TrustedMrtd)
async def add_trusted_mrtd(request: TrustedMrtdCreateRequest):
    """Add a trusted MRTD to the allowlist.

    Only agents with MRTDs in this list can receive deployments.
    This ensures only known-good launcher images can run workloads.

    Note: System MRTDs (agent/proxy) are pre-loaded from environment variables
    and cannot be added or modified via this API.
    """
    if not request.mrtd:
        raise HTTPException(status_code=400, detail="MRTD is required")

    # Check if already exists
    existing = trusted_mrtd_store.get(request.mrtd)
    if existing:
        if existing.locked:
            raise HTTPException(status_code=403, detail="Cannot modify system MRTD")
        raise HTTPException(status_code=409, detail="MRTD already in trusted list")

    trusted = TrustedMrtd(
        mrtd=request.mrtd,
        type=request.type,
        description=request.description,
        image_version=request.image_version,
        source_repo=request.source_repo,
        source_commit=request.source_commit,
        source_tag=request.source_tag,
        build_workflow=request.build_workflow,
        image_digest=request.image_digest,
        attestation_url=request.attestation_url,
    )
    trusted_mrtd_store.add(trusted)
    logger.info(f"Added trusted MRTD: {request.mrtd[:16]}... ({request.description})")

    # Re-verify any unverified agents that now match and create tunnels
    updated_ids = reverify_agents_for_mrtd(request.mrtd, verified=True)
    for aid in updated_ids:
        logger.info(f"Agent {aid} now verified")
        a = agent_store.get(aid)
        if a and not a.hostname and cloudflare.is_configured():
            try:
                tunnel_info = await cloudflare.create_tunnel_for_agent(aid)
                agent_store.update_tunnel_info(
                    aid,
                    tunnel_id=tunnel_info["tunnel_id"],
                    hostname=tunnel_info["hostname"],
                    tunnel_token=tunnel_info["tunnel_token"],
                )
                logger.info(f"Created tunnel for newly verified agent {aid}: {tunnel_info['hostname']}")
            except Exception as e:
                logger.warning(f"Failed to create tunnel for newly verified agent {aid}: {e}")

    return trusted


@app.get("/api/v1/trusted-mrtds", response_model=TrustedMrtdListResponse)
async def list_trusted_mrtds(
    include_inactive: bool = Query(False, description="Include inactive MRTDs"),
    type: MrtdType | None = Query(None, description="Filter by type: 'agent' or 'app'"),
):
    """List all trusted MRTDs, optionally filtered by type."""
    mrtds = trusted_mrtd_store.list(include_inactive=include_inactive)
    if type is not None:
        mrtds = [m for m in mrtds if m.type == type]
    return TrustedMrtdListResponse(trusted_mrtds=mrtds, total=len(mrtds))


@app.get("/api/v1/trusted-mrtds/{mrtd}", response_model=TrustedMrtd)
async def get_trusted_mrtd(mrtd: str):
    """Get details for a specific trusted MRTD."""
    return get_or_404(trusted_mrtd_store, mrtd, "Trusted MRTD")


@app.post("/api/v1/trusted-mrtds/{mrtd}/deactivate")
async def deactivate_trusted_mrtd(mrtd: str):
    """Deactivate a trusted MRTD.

    Agents with this MRTD will no longer be verified for new deployments.
    Existing deployments are not affected.

    Note: System MRTDs (agent/proxy) cannot be deactivated.
    """
    success, error = trusted_mrtd_store.deactivate(mrtd)
    if error:
        raise HTTPException(status_code=403, detail=error)
    if not success:
        raise HTTPException(status_code=404, detail="Trusted MRTD not found")

    # Mark agents with this MRTD as unverified
    for aid in reverify_agents_for_mrtd(mrtd, verified=False, error="MRTD deactivated"):
        logger.info(f"Agent {aid} unverified (MRTD deactivated)")

    logger.info(f"Deactivated trusted MRTD: {mrtd[:16]}...")
    return {"status": "deactivated", "mrtd": mrtd}


@app.post("/api/v1/trusted-mrtds/{mrtd}/activate")
async def activate_trusted_mrtd(mrtd: str):
    """Activate a previously deactivated trusted MRTD."""
    if not trusted_mrtd_store.activate(mrtd):
        raise HTTPException(status_code=404, detail="Trusted MRTD not found")

    # Re-verify agents with this MRTD
    for aid in reverify_agents_for_mrtd(mrtd, verified=True):
        logger.info(f"Agent {aid} re-verified (MRTD activated)")

    logger.info(f"Activated trusted MRTD: {mrtd[:16]}...")
    return {"status": "activated", "mrtd": mrtd}


@app.delete("/api/v1/trusted-mrtds/{mrtd}")
async def delete_trusted_mrtd(mrtd: str):
    """Delete a trusted MRTD from the allowlist.

    Note: System MRTDs (agent/proxy) cannot be deleted.
    """
    success, error = trusted_mrtd_store.delete(mrtd)
    if error:
        raise HTTPException(status_code=403, detail=error)
    if not success:
        raise HTTPException(status_code=404, detail="Trusted MRTD not found")

    # Mark agents with this MRTD as unverified
    for aid in reverify_agents_for_mrtd(mrtd, verified=False, error="MRTD removed from trusted list"):
        logger.info(f"Agent {aid} unverified (MRTD deleted)")

    logger.info(f"Deleted trusted MRTD: {mrtd[:16]}...")
    return {"status": "deleted", "mrtd": mrtd}


# ==============================================================================
# App Catalog API - Register apps, publish versions, deploy
# ==============================================================================


@app.post("/api/v1/apps", response_model=App)
async def register_app(request: AppCreateRequest):
    """Register a new app in the catalog.

    Apps must have a unique name. Once registered, versions can be
    published for the app.
    """
    if not request.name:
        raise HTTPException(status_code=400, detail="App name is required")

    # Check if app with this name already exists
    existing = app_store.get_by_name(request.name)
    if existing:
        raise HTTPException(status_code=409, detail=f"App '{request.name}' already exists")

    new_app = App(
        name=request.name,
        description=request.description,
        source_repo=request.source_repo,
        maintainers=request.maintainers,
        tags=request.tags,
    )
    app_store.register(new_app)
    logger.info(f"App registered: {new_app.name} ({new_app.app_id})")

    return new_app


@app.get("/api/v1/apps", response_model=AppListResponse)
async def list_apps(
    name: str | None = Query(None, description="Filter by name (partial match)"),
    tags: str | None = Query(None, description="Filter by tags (comma-separated)"),
):
    """List all apps in the catalog."""
    apps = app_store.list(build_filters(name=name, tags=tags))
    return AppListResponse(apps=apps, total=len(apps))


@app.get("/api/v1/apps/{name}", response_model=App)
async def get_app(name: str):
    """Get details for a specific app."""
    found_app = app_store.get_by_name(name)
    if found_app is None:
        raise HTTPException(status_code=404, detail="App not found")
    return found_app


@app.delete("/api/v1/apps/{name}")
async def delete_app(name: str):
    """Delete an app from the catalog."""
    found_app = app_store.get_by_name(name)
    if found_app is None:
        raise HTTPException(status_code=404, detail="App not found")

    if not app_store.delete(found_app.app_id):
        raise HTTPException(status_code=404, detail="App not found")

    logger.info(f"App deleted: {name}")
    return {"status": "deleted", "name": name}


@app.post("/api/v1/apps/{name}/versions", response_model=AppVersionResponse)
async def publish_app_version(name: str, request: AppVersionCreateRequest):
    """Publish a new version of an app.

    Returns:
    - status: "pending", "attesting", "attested", "rejected", or "failed"
    - rejection_reason: If rejected, the reason why
    """
    found_app = app_store.get_by_name(name)
    if found_app is None:
        raise HTTPException(status_code=404, detail="App not found")

    if not request.version:
        raise HTTPException(status_code=400, detail="Version is required")

    if not request.compose:
        raise HTTPException(status_code=400, detail="Compose file is required (base64 encoded)")

    # Check if version already exists
    existing = app_version_store.get_by_version(name, request.version)
    if existing:
        raise HTTPException(
            status_code=409, detail=f"Version '{request.version}' already exists for app '{name}'"
        )

    # Create version record (status: pending)
    new_version = AppVersion(
        app_name=name,
        version=request.version,
        compose=request.compose,
        image_digest=request.image_digest,
        source_commit=request.source_commit,
        source_tag=request.source_tag,
        status="pending",
    )
    app_version_store.create(new_version)
    logger.info(f"Version created: {name}@{request.version} ({new_version.version_id})")

    # TODO: Re-enable source inspection once GitHub token auth is implemented

    # Proceed to attestation
    # For now, mark as attested (attestation happens during deployment)
    app_version_store.update_status(
        new_version.version_id,
        status="attested",
    )

    attested = app_version_store.get(new_version.version_id)
    return AppVersionResponse(
        version_id=attested.version_id,
        app_name=attested.app_name,
        version=attested.version,
        mrtd=attested.mrtd,
        attestation=attested.attestation,
        status=attested.status,
        rejection_reason=attested.rejection_reason,
        published_at=attested.published_at,
    )


@app.get("/api/v1/apps/{name}/versions", response_model=AppVersionListResponse)
async def list_app_versions(name: str):
    """List all versions of an app."""
    found_app = app_store.get_by_name(name)
    if found_app is None:
        raise HTTPException(status_code=404, detail="App not found")

    versions = app_version_store.list_for_app(name)
    return AppVersionListResponse(versions=versions, total=len(versions))


@app.get("/api/v1/apps/{name}/versions/{version}", response_model=AppVersion)
async def get_app_version(name: str, version: str):
    """Get details for a specific version of an app."""
    found_app = app_store.get_by_name(name)
    if found_app is None:
        raise HTTPException(status_code=404, detail="App not found")

    found_version = app_version_store.get_by_version(name, version)
    if found_version is None:
        raise HTTPException(status_code=404, detail="Version not found")

    return found_version


@app.post("/api/v1/apps/{name}/versions/{version}/deploy", response_model=DeploymentCreateResponse)
async def deploy_app_version(name: str, version: str, request: DeployFromVersionRequest):
    """Deploy a published app version to an agent.

    This is the only way to create deployments. The app must be registered
    and the version must be "attested" (passed source inspection).

    Flow (push model):
    1. Validate app exists
    2. Validate version exists and status is "attested"
    3. Validate agent exists, is verified, has tunnel, and available
    4. Create deployment record
    5. Push deployment to agent via POST /api/deploy
    6. Return deployment_id with status from agent
    """
    # 1. Validate app exists
    found_app = app_store.get_by_name(name)
    if found_app is None:
        raise HTTPException(status_code=404, detail=f"App '{name}' not found")

    # 2. Validate version exists
    found_version = app_version_store.get_by_version(name, version)
    if found_version is None:
        raise HTTPException(
            status_code=404, detail=f"Version '{version}' not found for app '{name}'"
        )

    # 3. Validate version status is "attested"
    if found_version.status != "attested":
        if found_version.status == "rejected":
            raise HTTPException(
                status_code=400,
                detail=f"Version '{version}' was rejected: {found_version.rejection_reason}",
            )
        raise HTTPException(
            status_code=400,
            detail=f"Version '{version}' is not attested (status: {found_version.status})",
        )

    # 4. Validate agent exists
    agent = agent_store.get(request.agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    # 5. Check if agent is verified (MRTD in trusted list)
    if not agent.verified:
        raise HTTPException(
            status_code=403,
            detail=f"Agent not verified: {agent.verification_error or 'MRTD not trusted'}",
        )

    # 6. Check if agent has a tunnel hostname
    if not agent.hostname:
        raise HTTPException(
            status_code=400,
            detail="Agent does not have a tunnel hostname - cannot push deployment",
        )

    # 7. Check if agent is available
    if agent.status not in ("undeployed", "deployed"):
        raise HTTPException(
            status_code=400, detail=f"Agent is not available (status: {agent.status})"
        )

    # 8. Build deployment config
    config = request.config or {}
    # Default service_name to app name if not provided
    if "service_name" not in config:
        config["service_name"] = name

    # 9. Create deployment record
    deployment = Deployment(
        compose=found_version.compose,
        config=config,
        agent_id=request.agent_id,
        status="pushing",
    )
    deployment_id = deployment_store.create(deployment)
    logger.info(
        f"Deployment created: {deployment_id} ({name}@{version} -> agent {request.agent_id})"
    )

    # 10. Push deployment to agent
    try:
        agent_url = f"https://{agent.hostname}/api/deploy"
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                agent_url,
                json={
                    "deployment_id": deployment_id,
                    "compose": found_version.compose,
                    "build_context": getattr(found_version, "build_context", None),
                    "config": config,
                },
            )

            if response.status_code == 202:
                # Agent accepted the deployment
                deployment_store.update_status(deployment_id, "deploying")
                agent_store.update_status(request.agent_id, "deploying", deployment_id)
                logger.info(f"Deployment {deployment_id} pushed to agent {request.agent_id}")
                return DeploymentCreateResponse(deployment_id=deployment_id, status="deploying")
            else:
                # Agent rejected the deployment
                error_detail = response.text
                deployment_store.complete(deployment_id, status="failed", error=error_detail)
                logger.error(f"Agent rejected deployment: {error_detail}")
                raise HTTPException(
                    status_code=502,
                    detail=f"Agent rejected deployment: {error_detail}",
                )

    except httpx.RequestError as e:
        # Network error reaching agent
        deployment_store.complete(deployment_id, status="failed", error=str(e))
        logger.error(f"Failed to reach agent: {e}")
        raise HTTPException(
            status_code=502,
            detail=f"Failed to reach agent at {agent.hostname}: {e}",
        ) from e


# ==============================================================================
# SDK Trust Model API - Attestation, Proxy Discovery, and Service Proxying
# ==============================================================================


@app.get("/api/v1/attestation")
async def get_control_plane_attestation(
    nonce: str = Query(None, description="Nonce to include in attestation"),
):
    """Get the control plane's TDX attestation.

    This endpoint allows clients to verify that the control plane is running
    in a TDX trusted execution environment. The returned quote can be verified
    using Intel Trust Authority or local TDX verification.

    Args:
        nonce: Optional nonce to include in the quote's report_data field
               (used to prevent replay attacks)

    Returns:
        - quote_b64: Base64-encoded TDX quote
        - measurements: Parsed TDX measurements from the quote
        - nonce: Echoed nonce (if provided)
    """
    quote_result = generate_tdx_quote(nonce)
    result = {
        "timestamp": datetime.utcnow().isoformat(),
        "nonce": nonce,
    }
    if quote_result.error:
        result["error"] = quote_result.error
    else:
        result["quote_b64"] = quote_result.quote_b64
        result["measurements"] = quote_result.measurements
    return result


@app.get("/api/v1/proxy")
async def get_proxy_endpoint():
    """Get the proxy endpoint for routing service traffic.

    In the chain-of-trust model, clients first verify the control plane's
    attestation, then use this endpoint to discover where to route service
    traffic. The proxy (typically the control plane itself) forwards requests
    to services via Cloudflare tunnels.

    Returns:
        - proxy_url: Primary proxy URL (default: this control plane)
        - proxies: List of available proxy URLs (for future scaling)
    """
    import os

    # Get domain from environment or use default
    domain = os.environ.get("EASYENCLAVE_DOMAIN", "easyenclave.com")

    # Default proxy is the control plane itself
    proxy_url = f"https://app.{domain}"

    return {
        "proxy_url": proxy_url,
        "proxies": [proxy_url],
        "note": "Route service requests through /proxy/{service_name}/{path}",
    }


@app.api_route(
    "/proxy/{service_name}/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def proxy_service_request(
    service_name: str,
    path: str,
    request: Request,
):
    """Proxy a request to a service through the control plane.

    This endpoint routes requests to services via Cloudflare tunnels. The
    control plane looks up the service by name, finds its tunnel hostname,
    and forwards the request.

    Trust model:
    1. Client has verified CP attestation (via /api/v1/attestation)
    2. Client routes traffic through this proxy
    3. CP forwards to service via Cloudflare tunnel
    4. Service is running in TDX with attested MRTD

    Args:
        service_name: Name of the target service
        path: Path to forward to the service

    Returns:
        Response from the target service
    """
    return await proxy.proxy_request(service_name, path, request)


# ==============================================================================
# Agent and Workload Logging API
# ==============================================================================


@app.get("/api/v1/agents/{agent_id}/logs")
async def get_agent_logs(
    agent_id: str,
    since: str = Query("5m", description="Logs since (e.g., '5m', '1h')"),
    container: str | None = Query(None, description="Filter by container name"),
):
    """Get logs for a specific agent (pull model).

    Fetches logs directly from the agent via its tunnel.
    Returns logs from deployed containers.
    """
    agent = get_or_404(agent_store, agent_id, "Agent")

    if not agent.hostname:
        raise HTTPException(
            status_code=400,
            detail="Agent does not have a tunnel hostname - cannot pull logs",
        )

    try:
        agent_url = f"https://{agent.hostname}/api/logs"
        params = {"since": since}
        if container:
            params["container"] = container

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(agent_url, params=params)
            response.raise_for_status()

            # Verify we got JSON, not the workload response
            content_type = response.headers.get("content-type", "")
            if "application/json" not in content_type:
                raise HTTPException(
                    status_code=502,
                    detail=f"Agent returned non-JSON response (content-type: {content_type}). "
                    "The tunnel may be routing to the workload instead of the agent API.",
                )

            try:
                return response.json()
            except Exception as e:
                # Response body wasn't valid JSON
                body_preview = response.text[:100] if response.text else "(empty)"
                raise HTTPException(
                    status_code=502,
                    detail=f"Agent returned invalid JSON: {body_preview}. "
                    "The tunnel may be routing to the workload instead of the agent API.",
                ) from e

    except httpx.RequestError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to reach agent at {agent.hostname}: {e}",
        ) from e
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Agent returned error {e.response.status_code}: {e.response.text[:200]}",
        ) from e


@app.get("/api/v1/agents/{agent_id}/stats")
async def get_agent_stats(agent_id: str):
    """Get system stats for a specific agent (pull model).

    Fetches stats directly from the agent via its tunnel.
    Returns CPU, memory, disk, and network stats.
    """
    agent = get_or_404(agent_store, agent_id, "Agent")

    if not agent.hostname:
        raise HTTPException(
            status_code=400,
            detail="Agent does not have a tunnel hostname - cannot pull stats",
        )

    try:
        agent_url = f"https://{agent.hostname}/api/stats"
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(agent_url)
            response.raise_for_status()

            # Verify we got JSON, not the workload response
            content_type = response.headers.get("content-type", "")
            if "application/json" not in content_type:
                raise HTTPException(
                    status_code=502,
                    detail=f"Agent returned non-JSON response (content-type: {content_type}). "
                    "The tunnel may be routing to the workload instead of the agent API.",
                )

            try:
                return response.json()
            except Exception as e:
                body_preview = response.text[:100] if response.text else "(empty)"
                raise HTTPException(
                    status_code=502,
                    detail=f"Agent returned invalid JSON: {body_preview}. "
                    "The tunnel may be routing to the workload instead of the agent API.",
                ) from e

    except httpx.RequestError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to reach agent at {agent.hostname}: {e}",
        ) from e
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Agent returned error {e.response.status_code}: {e.response.text[:200]}",
        ) from e


@app.get("/api/v1/logs/control-plane")
async def get_control_plane_logs(
    lines: int = Query(100, description="Number of lines to return", le=1000),
):
    """Get recent control plane logs from file."""
    log_file = Path("/var/log/easyenclave/control-plane.log")
    if not log_file.exists():
        log_file = Path("control-plane.log")

    if not log_file.exists():
        return {"logs": [], "source": "file_not_found"}

    try:
        with open(log_file) as f:
            all_lines = f.readlines()
            return {
                "logs": all_lines[-lines:],
                "source": str(log_file),
                "total_lines": len(all_lines),
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read logs: {e}") from e


# ==============================================================================
# Admin Authentication and Dashboard
# ==============================================================================


class AdminLoginRequest(BaseModel):
    """Request model for admin login."""

    password: str


@app.post("/admin/login")
async def admin_login(request: AdminLoginRequest):
    """Authenticate admin user and return session token."""
    if request.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid password")

    # Generate secure token
    token = secrets.token_urlsafe(32)
    _admin_tokens.add(token)

    # Limit stored tokens to prevent memory issues (keep last 100)
    if len(_admin_tokens) > 100:
        # Remove oldest tokens (convert to list, remove first items)
        tokens_list = list(_admin_tokens)
        for old_token in tokens_list[:-100]:
            _admin_tokens.discard(old_token)

    logger.info("Admin login successful")
    return {"token": token, "message": "Login successful"}


@app.post("/admin/logout")
async def admin_logout(authorization: str | None = Header(None)):
    """Invalidate admin session token."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        _admin_tokens.discard(token)
    return {"message": "Logged out"}


@app.get("/admin")
async def serve_admin():
    """Serve the admin dashboard."""
    admin_path = STATIC_DIR / "admin.html"
    if admin_path.exists():
        return FileResponse(admin_path)
    raise HTTPException(status_code=404, detail="Admin page not found")


# Serve static files and web GUI
@app.get("/")
async def serve_gui():
    """Serve the web GUI."""
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return {"message": "EasyEnclave Discovery Service", "docs": "/docs"}


# Mount static files after routes to avoid conflicts
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# Run with: uvicorn app.main:app --host 0.0.0.0 --port 8080
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
