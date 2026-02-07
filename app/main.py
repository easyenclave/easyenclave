"""EasyEnclave Discovery Service - FastAPI Application."""

from __future__ import annotations

import asyncio
import collections
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
    extract_rtmrs,
    generate_tdx_quote,
    refresh_agent_attestation,
    verify_agent_registration,
)
from .crud import build_filters, create_transaction, get_or_404
from .database import init_db
from .ita import verify_attestation_token
from .models import (
    Account,
    AccountCreateRequest,
    AccountListResponse,
    AccountResponse,
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
    DepositRequest,
    HealthResponse,
    MeasurementCallbackRequest,
    RateCardResponse,
    Service,
    ServiceListResponse,
    ServiceRegistrationRequest,
    TransactionListResponse,
    TransactionResponse,
    VerificationResponse,
)
from .storage import (
    account_store,
    agent_store,
    app_store,
    app_version_store,
    deployment_store,
    list_trusted_mrtds,
    store,
    transaction_store,
)

logger = logging.getLogger(__name__)


# In-memory log buffer for the admin logs viewer
class _MemoryLogHandler(logging.Handler):
    """Captures recent log records in a bounded deque."""

    def __init__(self, capacity: int = 2000):
        super().__init__()
        self.records: collections.deque[dict] = collections.deque(maxlen=capacity)

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(
            {
                "timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
        )


_log_handler = _MemoryLogHandler()
_log_handler.setLevel(logging.DEBUG)
logging.getLogger().addHandler(_log_handler)


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


# Cached control plane attestation (generated at startup, refreshed periodically)
_cached_attestation: dict | None = None

CP_ATTESTATION_REFRESH_INTERVAL = 300  # 5 minutes


def _refresh_cp_attestation():
    """Generate a fresh TDX quote and cache it."""
    global _cached_attestation
    result = generate_tdx_quote()
    if result.error:
        _cached_attestation = None
        logger.debug(f"CP attestation not available: {result.error}")
    else:
        _cached_attestation = {
            "quote_b64": result.quote_b64,
            "mrtd": result.measurements.get("mrtd") if result.measurements else None,
            "generated_at": datetime.utcnow().isoformat(),
        }
        logger.info("CP attestation quote generated")


async def background_cp_attestation_refresher():
    """Periodically refresh the cached CP attestation quote."""
    while True:
        await asyncio.sleep(CP_ATTESTATION_REFRESH_INTERVAL)
        _refresh_cp_attestation()


MEASUREMENT_CHECK_INTERVAL = 30  # seconds


async def send_measurement_request(measure_url: str, version: AppVersion, callback_base: str):
    """Send a measurement request to the measuring enclave.

    Raises on failure so the caller can avoid marking the version as attesting.
    """
    callback_url = callback_base.rstrip("/") + "/api/v1/internal/measurement-callback"
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            measure_url,
            json={
                "version_id": version.version_id,
                "compose": version.compose,
                "callback_url": callback_url,
            },
        )
        resp.raise_for_status()
        logger.info(f"Sent measurement request for {version.app_name}@{version.version}")


async def background_measurement_processor():
    """Send pending app versions to the measuring enclave for measurement."""
    while True:
        try:
            # Find the measuring enclave service
            measurer = store.get_by_name("measuring-enclave")
            if measurer and measurer.health_status == "healthy":
                # Find pending versions
                pending = app_version_store.list_by_status("pending")
                for version in pending:
                    # Determine callback base URL
                    cp_url = os.environ.get("EASYENCLAVE_CP_URL", "https://app.easyenclave.com")
                    # Send to measurer
                    url = list(measurer.endpoints.values())[0]
                    measure_url = url.rstrip("/") + "/api/measure"
                    try:
                        await send_measurement_request(measure_url, version, cp_url)
                        app_version_store.update_status(version.version_id, status="attesting")
                    except Exception as e:
                        logger.error(
                            f"Failed to send measurement request for {version.version_id}: {e}"
                        )
        except Exception as e:
            logger.error(f"Measurement processor error: {e}")
        await asyncio.sleep(MEASUREMENT_CHECK_INTERVAL)


def _get_proxy_url() -> str:
    """Get the proxy URL for service routing."""
    domain = os.environ.get("EASYENCLAVE_DOMAIN", "easyenclave.com")
    return f"https://app.{domain}"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan - start background tasks."""
    # Initialize database
    init_db()
    logger.info("Database initialized")

    # Configure Cloudflare to allow automated SDK/agent traffic
    if cloudflare.is_configured():
        try:
            await cloudflare.configure_sbfm()
        except Exception as e:
            logger.warning(f"Failed to configure SBFM: {e}")
        try:
            await cloudflare.ensure_waf_skip_rule()
        except Exception as e:
            logger.warning(f"Failed to configure WAF skip rule: {e}")

    # Generate initial CP attestation
    _refresh_cp_attestation()

    # Start background health checkers
    service_health_task = asyncio.create_task(background_health_checker())
    agent_health_task = asyncio.create_task(background_agent_health_checker())
    attestation_task = asyncio.create_task(background_cp_attestation_refresher())
    measurement_task = asyncio.create_task(background_measurement_processor())
    logger.info("Started background tasks (health checkers, measurement processor)")
    yield
    # Shutdown
    service_health_task.cancel()
    agent_health_task.cancel()
    attestation_task.cancel()
    measurement_task.cancel()
    for task in [service_health_task, agent_health_task, attestation_task, measurement_task]:
        try:
            await task
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
    """Health check endpoint with attestation and proxy info."""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.utcnow(),
        attestation=_cached_attestation,
        proxy_url=_get_proxy_url(),
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
        raise HTTPException(status_code=e.status_code, detail=e.detail) from e
    mrtd = verification.mrtd
    intel_ta_token = verification.intel_ta_token

    logger.info(f"Agent Intel TA token verified ({request.vm_name})")
    logger.info(
        f"Agent MRTD verified from Intel TA: {mrtd[:16]}... (type: {verification.mrtd_type})"
    )

    # Both Intel TA and MRTD verified - agent is trusted
    intel_ta_verified = True
    verified = True

    # Extract RTMRs from attestation (if available)
    rtmrs = extract_rtmrs(request.attestation)

    # Create agent record (reuse existing agent_id if recovering from attestation_failed)
    agent_kwargs = {
        "vm_name": request.vm_name,
        "attestation": request.attestation,
        "mrtd": mrtd,
        "rtmrs": rtmrs,
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
            # A tunnelless agent is useless — clean up and fail
            agent_store.delete(agent_id)
            raise HTTPException(
                status_code=502,
                detail=f"Failed to create tunnel: {e}",
            ) from e

    logger.info(
        f"Agent registered: {agent_id} ({request.vm_name}) "
        f"verified={verified} intel_ta={intel_ta_verified}"
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
            raise HTTPException(
                status_code=502,
                detail=f"Failed to create tunnel: {e}",
            ) from e

    return {"status": "reset", "agent_id": agent_id, "tunnel_created": tunnel_created}


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
# Trusted MRTD API - Read-only, loaded from environment variables
# ==============================================================================


@app.get("/api/v1/trusted-mrtds")
async def get_trusted_mrtds():
    """List all trusted MRTDs (loaded from environment variables).

    Trusted MRTDs are configured via TRUSTED_AGENT_MRTDS and TRUSTED_PROXY_MRTDS
    environment variables (comma-separated). To change the trusted list, update
    env vars and redeploy.
    """
    mrtds = list_trusted_mrtds()
    return {
        "trusted_mrtds": [{"mrtd": k, "type": v} for k, v in mrtds.items()],
        "total": len(mrtds),
    }


# ==============================================================================
# Billing API - Accounts, deposits, transactions, rate card
# ==============================================================================

RATE_CARD: dict[str, float] = {
    "cpu_per_vcpu_hr": 0.04,
    "memory_per_gb_hr": 0.005,
    "gpu_per_gpu_hr": 0.50,
    "storage_per_gb_mo": 0.10,
}


@app.post("/api/v1/accounts", response_model=AccountResponse)
async def create_account(request: AccountCreateRequest):
    """Create a new billing account."""
    if request.account_type not in ("deployer", "agent"):
        raise HTTPException(status_code=400, detail="account_type must be 'deployer' or 'agent'")

    if not request.name:
        raise HTTPException(status_code=400, detail="Account name is required")

    existing = account_store.get_by_name(request.name)
    if existing:
        raise HTTPException(status_code=409, detail=f"Account '{request.name}' already exists")

    account = Account(
        name=request.name,
        description=request.description,
        account_type=request.account_type,
    )
    account_store.create(account)
    logger.info(f"Account created: {account.name} ({account.account_id})")

    return AccountResponse(
        account_id=account.account_id,
        name=account.name,
        description=account.description,
        account_type=account.account_type,
        balance=0.0,
        created_at=account.created_at,
    )


@app.get("/api/v1/accounts", response_model=AccountListResponse)
async def list_accounts(
    name: str | None = Query(None, description="Filter by name (partial match)"),
    account_type: str | None = Query(None, description="Filter by account type"),
):
    """List all billing accounts."""
    accounts = account_store.list(build_filters(name=name, account_type=account_type))
    responses = [
        AccountResponse(
            account_id=a.account_id,
            name=a.name,
            description=a.description,
            account_type=a.account_type,
            balance=account_store.get_balance(a.account_id),
            created_at=a.created_at,
        )
        for a in accounts
    ]
    return AccountListResponse(accounts=responses, total=len(responses))


@app.get("/api/v1/accounts/{account_id}", response_model=AccountResponse)
async def get_account(account_id: str):
    """Get a billing account with its current balance."""
    account = get_or_404(account_store, account_id, "Account")
    return AccountResponse(
        account_id=account.account_id,
        name=account.name,
        description=account.description,
        account_type=account.account_type,
        balance=account_store.get_balance(account.account_id),
        created_at=account.created_at,
    )


@app.delete("/api/v1/accounts/{account_id}")
async def delete_account(account_id: str):
    """Delete a billing account (only if balance is zero)."""
    account = get_or_404(account_store, account_id, "Account")
    balance = account_store.get_balance(account_id)
    if balance != 0.0:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete account with non-zero balance ({balance:.2f})",
        )
    account_store.delete(account_id)
    logger.info(f"Account deleted: {account.name} ({account_id})")
    return {"status": "deleted", "account_id": account_id}


@app.post("/api/v1/accounts/{account_id}/deposit", response_model=TransactionResponse)
async def deposit_to_account(account_id: str, request: DepositRequest):
    """Deposit funds into an account."""
    txn = create_transaction(
        account_store,
        transaction_store,
        account_id,
        amount=request.amount,
        tx_type="deposit",
        description=request.description or "Deposit",
    )
    logger.info(f"Deposit: {request.amount:.2f} to account {account_id}")
    return TransactionResponse(
        transaction_id=txn.transaction_id,
        account_id=txn.account_id,
        amount=txn.amount,
        balance_after=txn.balance_after,
        tx_type=txn.tx_type,
        description=txn.description,
        reference_id=txn.reference_id,
        created_at=txn.created_at,
    )


@app.get("/api/v1/accounts/{account_id}/transactions", response_model=TransactionListResponse)
async def list_account_transactions(
    account_id: str,
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
):
    """List transactions for an account (newest first)."""
    get_or_404(account_store, account_id, "Account")
    transactions = transaction_store.list_for_account(account_id, limit=limit, offset=offset)
    total = transaction_store.count_for_account(account_id)
    return TransactionListResponse(
        transactions=[
            TransactionResponse(
                transaction_id=t.transaction_id,
                account_id=t.account_id,
                amount=t.amount,
                balance_after=t.balance_after,
                tx_type=t.tx_type,
                description=t.description,
                reference_id=t.reference_id,
                created_at=t.created_at,
            )
            for t in transactions
        ],
        total=total,
    )


@app.get("/api/v1/billing/rates", response_model=RateCardResponse)
async def get_rate_card():
    """Get the current billing rate card."""
    return RateCardResponse(rates=RATE_CARD)


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

    # Version stays "pending" until the measuring enclave processes it
    return AppVersionResponse(
        version_id=new_version.version_id,
        app_name=new_version.app_name,
        version=new_version.version,
        mrtd=new_version.mrtd,
        attestation=new_version.attestation,
        status=new_version.status,
        rejection_reason=new_version.rejection_reason,
        published_at=new_version.published_at,
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


@app.post("/api/v1/apps/{name}/versions/{version}/attest")
async def manual_attest_version(name: str, version: str, authorization: str | None = Header(None)):
    """Manually attest an app version (admin only).

    Used to bootstrap the measuring enclave itself (chicken-and-egg problem).
    """
    # Require admin auth
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Admin authentication required")
    token = authorization[7:]
    if token not in _admin_tokens:
        raise HTTPException(status_code=401, detail="Invalid admin token")

    found_version = app_version_store.get_by_version(name, version)
    if found_version is None:
        raise HTTPException(status_code=404, detail="Version not found")

    app_version_store.update_status(found_version.version_id, status="attested")
    logger.info(f"Manually attested: {name}@{version}")
    return {"status": "attested", "version_id": found_version.version_id}


@app.post("/api/v1/internal/measurement-callback")
async def measurement_callback(request: MeasurementCallbackRequest):
    """Receive measurement results from the measuring enclave."""
    found_version = app_version_store.get(request.version_id)
    if not found_version:
        raise HTTPException(status_code=404, detail="Version not found")

    if request.status == "success":
        app_version_store.update_status(
            request.version_id,
            status="attested",
            attestation=request.measurement,
        )
        logger.info(f"Measurement success: {found_version.app_name}@{found_version.version}")
    else:
        app_version_store.update_status(
            request.version_id,
            status="failed",
            rejection_reason=request.error,
        )
        logger.warning(
            f"Measurement failed: {found_version.app_name}@{found_version.version}: {request.error}"
        )
    return {"status": "ok"}


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
    """Get the proxy endpoint for routing service traffic."""
    proxy_url = _get_proxy_url()
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
    min_level: str = Query("INFO", description="Minimum log level"),
):
    """Get recent control plane logs from in-memory buffer."""
    level_num = getattr(logging, min_level.upper(), logging.INFO)
    filtered = [
        rec for rec in _log_handler.records if getattr(logging, rec["level"], 0) >= level_num
    ]
    return {"logs": filtered[-lines:], "total": len(filtered)}


@app.get("/api/v1/logs/containers")
async def get_container_logs(
    since: str = Query("5m", description="Logs since (e.g., '5m', '1h')"),
    container: str | None = Query(None, description="Filter by container name"),
    lines: int = Query(200, description="Max lines per container", le=1000),
):
    """Get Docker container logs from the host via mounted docker socket.

    Returns logs from running containers. Requires docker.sock to be mounted.
    Gracefully returns empty if the docker CLI is unavailable.
    """
    import shutil

    if not shutil.which("docker"):
        return {"logs": [], "count": 0, "error": "docker CLI not available"}

    # List running containers
    try:
        ps_proc = await asyncio.create_subprocess_exec(
            "docker",
            "ps",
            "--format",
            "{{.Names}}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        ps_stdout, ps_stderr = await asyncio.wait_for(ps_proc.communicate(), timeout=10)
    except (asyncio.TimeoutError, OSError) as e:
        return {"logs": [], "count": 0, "error": f"Failed to list containers: {e}"}

    if ps_proc.returncode != 0:
        err = ps_stderr.decode(errors="replace").strip()
        return {"logs": [], "count": 0, "error": f"docker ps failed: {err}"}

    container_names = [n for n in ps_stdout.decode().strip().split("\n") if n]
    if container and container_names:
        container_names = [n for n in container_names if container in n]

    all_logs = []
    for name in container_names:
        try:
            log_proc = await asyncio.create_subprocess_exec(
                "docker",
                "logs",
                "--since",
                since,
                "--tail",
                str(lines),
                name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            log_stdout, _ = await asyncio.wait_for(log_proc.communicate(), timeout=10)
            for line in log_stdout.decode(errors="replace").strip().split("\n"):
                if line:
                    all_logs.append({"container": name, "line": line})
        except (asyncio.TimeoutError, OSError):
            all_logs.append({"container": name, "line": "[error fetching logs]"})

    return {"logs": all_logs, "count": len(all_logs)}


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
