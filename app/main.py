"""EasyEnclave Discovery Service - FastAPI Application."""

from __future__ import annotations

import asyncio
import collections
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import cloudflare, proxy
from .attestation import (
    AttestationError,
    build_attestation_chain,
    extract_rtmrs,
    generate_tdx_quote,
    refresh_agent_attestation,
    verify_agent_attestation_only,
    verify_agent_registration,
)
from .auth import (
    create_session_expiry,
    generate_api_key,
    generate_session_token,
    get_admin_password_hash,
    get_key_prefix,
    get_owner_identities,
    get_token_prefix,
    hash_api_key,
    hash_password,
    is_admin_session,
    require_owner_or_admin,
    verify_account_api_key,
    verify_admin_token,
    verify_password,
)
from .billing import (
    background_hourly_charging,
    background_insufficient_funds_terminator,
)
from .crud import build_filters, create_transaction, get_or_404
from .database import init_db
from .db_models import AdminSession, AppRevenueShare
from .ita import verify_attestation_token
from .models import (
    Account,
    AccountCreateRequest,
    AccountLinkIdentityRequest,
    AccountListResponse,
    AccountResponse,
    AdminLoginRequest,
    AdminLoginResponse,
    Agent,
    AgentCapacityDispatchResult,
    AgentCapacityReconcileRequest,
    AgentCapacityReconcileResponse,
    AgentCapacityTargetResult,
    AgentChallengeResponse,
    AgentDeployedRequest,
    AgentHeartbeatRequest,
    AgentListResponse,
    AgentRegistrationRequest,
    AgentRegistrationResponse,
    AgentStatusRequest,
    ApiKeyRotateResponse,
    App,
    AppCreateRequest,
    AppListResponse,
    AppRevenueShareCreateRequest,
    AppRevenueShareListResponse,
    AppRevenueShareResponse,
    AppVersion,
    AppVersionCreateRequest,
    AppVersionListResponse,
    AppVersionResponse,
    CloudResourceAgent,
    CloudResourceCloudSummary,
    CloudResourceInventoryResponse,
    CreatePaymentIntentRequest,
    DeployFromVersionRequest,
    Deployment,
    DeploymentCreateResponse,
    DeploymentListResponse,
    DeploymentPreflightIssue,
    DeploymentPreflightResponse,
    DepositRequest,
    ExternalCloudCleanupRequest,
    ExternalCloudCleanupResponse,
    ExternalCloudInventoryResponse,
    ExternalCloudResource,
    HealthResponse,
    ManualAttestRequest,
    MeasurementCallbackRequest,
    RateCardResponse,
    Service,
    ServiceListResponse,
    ServiceRegistrationRequest,
    SetAgentOwnerRequest,
    TransactionListResponse,
    TransactionResponse,
    VerificationResponse,
)
from .pricing import calculate_deployment_cost_per_hour
from .provisioner import (
    dispatch_external_cleanup,
    dispatch_provision_request,
    fetch_external_inventory,
)
from .settings import (
    SETTING_DEFS,
    delete_setting,
    get_setting,
    get_setting_int,
    get_setting_source,
    list_settings,
    log_settings_sources,
    set_setting,
)
from .storage import (
    account_store,
    admin_session_store,
    agent_store,
    app_revenue_share_store,
    app_store,
    app_version_store,
    deployment_store,
    list_trusted_mrtds,
    load_trusted_mrtds,
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
                "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
        )


_log_handler = _MemoryLogHandler()
_log_handler.setLevel(logging.DEBUG)
logging.getLogger().addHandler(_log_handler)


# Store valid admin tokens (in production, use Redis or similar)
_admin_tokens: set[str] = set()
# Auto-generated admin password (shown on login page when ADMIN_PASSWORD_HASH not set)
_generated_admin_password: str | None = None

# Health check interval in seconds
HEALTH_CHECK_INTERVAL = 60

# Agent health check settings
AGENT_HEALTH_CHECK_INTERVAL = 30  # Check agents every 30 seconds
AGENT_UNHEALTHY_TIMEOUT = timedelta(minutes=5)  # Reassign after 5 minutes unhealthy
AGENT_STALE_CLEANUP_INTERVAL = 3600  # Run cleanup every hour

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


async def background_session_cleanup():
    """Background task to delete expired admin sessions."""
    while True:
        try:
            await asyncio.sleep(3600)  # Check every hour
            count = admin_session_store.delete_expired()
            if count > 0:
                logger.info(f"Cleaned up {count} expired admin sessions")
        except Exception as e:
            logger.error(f"Session cleanup error: {e}")


async def background_nonce_cleanup():
    """Background task to clean up expired nonces."""
    from app.nonce import cleanup_expired_nonces

    while True:
        try:
            await asyncio.sleep(60)  # Check every minute
            cleanup_expired_nonces()
        except Exception as e:
            logger.warning(f"Nonce cleanup error: {e}")


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
                        last_health_check=datetime.now(timezone.utc),
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
            now = datetime.now(timezone.utc)

            # Check all agents with tunnels (not just deployed ones)
            all_agents = agent_store.list()
            for agent in all_agents:
                if not agent.hostname:
                    continue  # Skip agents without tunnels

                try:
                    pull_enabled = (
                        get_setting("operational.agent_attestation_pull_enabled").strip().lower()
                        == "true"
                    )

                    # Default: agent pushes attestation/heartbeats; CP only does fast health pulls.
                    need_attestation = False
                    if pull_enabled:
                        attest_interval = get_setting_int(
                            "operational.agent_attestation_interval", fallback=3600
                        )
                        if attest_interval > 0:
                            last_attest = _agent_last_attestation.get(agent.agent_id)
                            need_attestation = (
                                last_attest is None
                                or (now - last_attest).total_seconds() > attest_interval
                            )

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
            "generated_at": datetime.now(timezone.utc).isoformat(),
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
    """Send pending app versions to the measuring enclave for measurement.

    Groups pending versions by node_size and routes each to the matching
    measuring enclave service (e.g. measuring-enclave-tiny, measuring-enclave-llm).
    Falls back to "measuring-enclave" for versions with empty node_size.
    """
    while True:
        try:
            pending = app_version_store.list_by_status("pending")
            if pending:
                # Group by node_size
                by_size: dict[str, list] = {}
                for version in pending:
                    by_size.setdefault(version.node_size, []).append(version)

                cp_url = os.environ.get("EASYENCLAVE_CP_URL", "https://app.easyenclave.com")

                for node_size, versions in by_size.items():
                    # Determine measurer service name
                    if node_size:
                        measurer_name = f"measuring-enclave-{node_size}"
                    else:
                        measurer_name = "measuring-enclave"

                    measurer = store.get_by_name(measurer_name)
                    if not measurer or measurer.health_status != "healthy":
                        logger.debug(
                            f"No healthy measurer '{measurer_name}' for node_size='{node_size}', "
                            f"skipping {len(versions)} pending version(s)"
                        )
                        continue

                    url = list(measurer.endpoints.values())[0]
                    measure_url = url.rstrip("/") + "/api/measure"

                    for version in versions:
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
    domain = get_setting("cloudflare.domain")
    return f"https://app.{domain}"


def validate_environment():
    """Validate environment configuration on startup."""
    warnings = []

    # Admin authentication — auto-generate password if not configured
    global _generated_admin_password
    if not os.environ.get("ADMIN_PASSWORD_HASH"):
        # Dev convenience: allow setting a plaintext password (hashed on startup).
        # Avoid using this in production; prefer ADMIN_PASSWORD_HASH.
        plaintext_pw = (os.environ.get("ADMIN_PASSWORD") or "").strip()
        if plaintext_pw:
            os.environ["ADMIN_PASSWORD_HASH"] = hash_password(plaintext_pw)
            logger.warning("ADMIN_PASSWORD_HASH not set — using hashed ADMIN_PASSWORD from env")
        else:
            import secrets as _secrets

            generated_pw = _secrets.token_urlsafe(16)
            pw_hash = hash_password(generated_pw)
            os.environ["ADMIN_PASSWORD_HASH"] = pw_hash
            _generated_admin_password = generated_pw
            logger.warning("ADMIN_PASSWORD_HASH not set — auto-generated password")

    # GitHub OAuth (optional but if one is set, all should be set)
    gh_id = get_setting("github_oauth.client_id")
    gh_secret = get_setting("github_oauth.client_secret")
    gh_redirect = get_setting("github_oauth.redirect_uri")

    github_vars = [gh_id, gh_secret, gh_redirect]
    if any(github_vars) and not all(github_vars):
        warnings.append(
            "Partial GitHub OAuth configuration detected. "
            "Set all of: client_id, client_secret, redirect_uri (via Settings or env vars)"
        )

    # Intel Trust Authority (required for attestation)
    if not os.environ.get("ITA_API_KEY"):
        warnings.append(
            "ITA_API_KEY not set - attestation verification will fail. "
            "Get API key from https://www.intel.com/content/www/us/en/security/trust-authority.html"
        )

    # Trusted MRTDs (required for agent verification)
    if not os.environ.get("TRUSTED_AGENT_MRTDS") and not os.environ.get("SYSTEM_AGENT_MRTD"):
        warnings.append(
            "No trusted agent MRTDs configured - agent registration will fail. "
            "Set TRUSTED_AGENT_MRTDS environment variable."
        )

    if not os.environ.get("TRUSTED_PROXY_MRTDS") and not os.environ.get("SYSTEM_PROXY_MRTD"):
        warnings.append(
            "No trusted proxy MRTDs configured - proxy deployments will fail. "
            "Set TRUSTED_PROXY_MRTDS environment variable."
        )

    # Log results
    if warnings:
        logger.warning("Environment warnings:")
        for warn in warnings:
            logger.warning(f"  - {warn}")
    else:
        logger.info("Environment validation passed")


async def background_stale_agent_cleanup():
    """Background task to delete agents that haven't sent a heartbeat in AGENT_STALE_HOURS.

    Cleans up the agent record, Cloudflare tunnel, and DNS record.
    """
    while True:
        await asyncio.sleep(AGENT_STALE_CLEANUP_INTERVAL)
        try:
            stale_hours = get_setting_int("operational.agent_stale_hours", fallback=24)
            stale_agents = agent_store.get_stale_agents(timedelta(hours=stale_hours))
            if not stale_agents:
                continue

            logger.info(f"Found {len(stale_agents)} stale agent(s) to clean up")
            for agent in stale_agents:
                try:
                    # Skip agents with active deployments (let reassignment handle those)
                    if agent.current_deployment_id and agent.status == "deployed":
                        logger.info(
                            f"Skipping stale agent {agent.agent_id} - has active deployment"
                        )
                        continue

                    # Clean up Cloudflare tunnel
                    if agent.tunnel_id and cloudflare.is_configured():
                        try:
                            await cloudflare.delete_tunnel(agent.tunnel_id)
                            if agent.hostname:
                                await cloudflare.delete_dns_record(agent.hostname)
                        except Exception as e:
                            logger.warning(
                                f"Failed to clean up tunnel for stale agent {agent.agent_id}: {e}"
                            )

                    # Delete agent record
                    agent_store.delete(agent.agent_id)
                    logger.info(
                        f"Deleted stale agent {agent.agent_id} "
                        f"(vm={agent.vm_name}, last_heartbeat={agent.last_heartbeat})"
                    )
                except Exception as e:
                    logger.error(f"Failed to clean up stale agent {agent.agent_id}: {e}")
        except Exception as e:
            logger.error(f"Stale agent cleanup error: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan - start background tasks."""
    # Validate environment configuration
    validate_environment()

    # Configure logging level after uvicorn initialization
    logging.getLogger().setLevel(logging.INFO)
    logger.info("Logging configured - INFO level enabled")

    # Initialize database
    init_db()
    logger.info("Database initialized")

    # Load trusted MRTDs (env vars + DB entries)
    load_trusted_mrtds()

    # Log effective settings sources
    log_settings_sources()

    # Generate initial CP attestation
    _refresh_cp_attestation()

    # Start background health checkers
    service_health_task = asyncio.create_task(background_health_checker())
    agent_health_task = asyncio.create_task(background_agent_health_checker())
    attestation_task = asyncio.create_task(background_cp_attestation_refresher())
    measurement_task = asyncio.create_task(background_measurement_processor())

    # Start billing background tasks
    charging_task = asyncio.create_task(background_hourly_charging())
    terminator_task = asyncio.create_task(background_insufficient_funds_terminator())
    session_cleanup_task = asyncio.create_task(background_session_cleanup())

    # Start nonce cleanup task
    nonce_cleanup_task = asyncio.create_task(background_nonce_cleanup())

    # Start stale agent cleanup task
    stale_agent_task = asyncio.create_task(background_stale_agent_cleanup())

    logger.info(
        "Started background tasks (health checkers, measurement processor, billing, session cleanup, nonce cleanup, stale agent cleanup)"
    )
    yield
    # Shutdown
    service_health_task.cancel()
    agent_health_task.cancel()
    attestation_task.cancel()
    measurement_task.cancel()
    charging_task.cancel()
    terminator_task.cancel()
    session_cleanup_task.cancel()
    nonce_cleanup_task.cancel()
    stale_agent_task.cancel()
    for task in [
        service_health_task,
        agent_health_task,
        attestation_task,
        measurement_task,
        charging_task,
        terminator_task,
        session_cleanup_task,
        nonce_cleanup_task,
        stale_agent_task,
    ]:
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
        timestamp=datetime.now(timezone.utc),
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
        last_health_check=datetime.now(timezone.utc),
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
            verification_time=datetime.now(timezone.utc),
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


@app.get("/api/v1/agents/challenge", response_model=AgentChallengeResponse)
async def request_challenge(vm_name: str):
    """Request nonce challenge for agent registration.

    Agents should call this endpoint before registration to get a one-time-use
    nonce that must be included in their TDX quote REPORTDATA field.

    This prevents replay attacks where an attacker captures an old attestation
    quote and reuses it to register a malicious agent.

    Args:
        vm_name: Unique identifier for the VM requesting challenge

    Returns:
        Nonce challenge with expiration time (default 5 minutes)
    """
    from app.nonce import _ttl_seconds, issue_challenge

    if not vm_name:
        raise HTTPException(status_code=400, detail="vm_name required")

    nonce = issue_challenge(vm_name)

    return AgentChallengeResponse(
        nonce=nonce,
        ttl_seconds=_ttl_seconds(),
        issued_at=datetime.now(timezone.utc).isoformat(),
    )


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
    # Only treat verified agents as "fully registered" for early-return.
    # Unverified agents must keep retrying registration so they can become verified
    # after an admin adds their MRTD baseline.
    if existing and existing.verified and existing.status != "attestation_failed":
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
        verification = await verify_agent_registration(
            request.attestation, node_size=request.node_size
        )
    except AttestationError as e:
        # Special-case: if the agent MRTD is simply not trusted yet, record the baseline
        # so CI/admin can add it and the agent can keep retrying registration.
        if "MRTD not in trusted list" in (e.detail or ""):
            try:
                untrusted = await verify_agent_attestation_only(
                    request.attestation, node_size=request.node_size
                )
                rtmrs = extract_rtmrs(request.attestation)
                agent_kwargs = {
                    "vm_name": request.vm_name,
                    "attestation": request.attestation,
                    "mrtd": untrusted.mrtd,
                    "rtmrs": rtmrs,
                    "intel_ta_token": untrusted.intel_ta_token,
                    "version": request.version,
                    "node_size": request.node_size,
                    "datacenter": request.datacenter,
                    "status": "unverified",
                    "verified": False,
                    "verification_error": e.detail,
                    "tcb_status": untrusted.tcb_status,
                    "tcb_verified_at": datetime.now(timezone.utc),
                }
                if existing:
                    agent_kwargs["agent_id"] = existing.agent_id
                agent_store.register(Agent(**agent_kwargs))
                logger.warning(
                    f"Recorded untrusted agent baseline: vm={request.vm_name} mrtd={untrusted.mrtd[:16]}..."
                )
            except Exception as record_exc:
                logger.warning(f"Failed to record untrusted agent baseline: {record_exc}")
        raise HTTPException(status_code=e.status_code, detail=e.detail) from e
    mrtd = verification.mrtd
    intel_ta_token = verification.intel_ta_token
    tcb_status = verification.tcb_status

    logger.info(f"Agent Intel TA token verified ({request.vm_name})")
    logger.info(
        f"Agent MRTD verified from Intel TA: {mrtd[:16]}... (type: {verification.mrtd_type})"
    )
    logger.info(f"Agent TCB status: {tcb_status} ({request.vm_name})")

    # Verify nonce if present (replay attack protection)
    from app.ita import extract_intel_ta_claims
    from app.nonce import _enforcement_mode, verify_nonce

    ita_claims = extract_intel_ta_claims(intel_ta_token)
    nonce_from_quote = ita_claims.get("attester_held_data", "").strip() if ita_claims else ""

    nonce_mode = _enforcement_mode()
    if nonce_from_quote:
        nonce_verified, nonce_error = verify_nonce(request.vm_name, nonce_from_quote)
        if not nonce_verified:
            raise HTTPException(status_code=403, detail=f"Nonce verification failed: {nonce_error}")
        logger.info(f"Nonce verified for {request.vm_name}")
    elif nonce_mode == "required":
        raise HTTPException(
            status_code=400,
            detail="Nonce required. Call GET /api/v1/agents/challenge first",
        )
    elif nonce_mode == "optional":
        logger.warning(f"Agent {request.vm_name} registered without nonce (optional mode)")

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
        "node_size": request.node_size,
        "datacenter": request.datacenter,
        "status": "undeployed",
        "verified": verified,
        "verification_error": None,
        "tcb_status": tcb_status,
        "tcb_verified_at": datetime.now(timezone.utc),
    }
    if existing:
        agent_kwargs["agent_id"] = existing.agent_id
    agent = Agent(**agent_kwargs)
    agent_id = agent_store.register(agent)

    # Create Cloudflare tunnel for verified agents (only if they don't have one)
    tunnel_token = None
    hostname = None
    if verified and cloudflare.is_configured():
        # Reuse existing tunnel if agent already has one
        if existing and existing.hostname:
            tunnel_token = existing.tunnel_token
            hostname = existing.hostname
            logger.info(f"Reusing existing tunnel for agent {agent_id}: {hostname}")
        else:
            # Create new tunnel only if agent doesn't have one
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


@app.post("/api/v1/agents/{agent_id}/heartbeat")
async def agent_heartbeat(agent_id: str, request: AgentHeartbeatRequest):
    """Receive an agent-pushed heartbeat with fresh attestation.

    This is the primary attestation refresh mechanism (agent-driven).
    Control plane may still do health pulls separately.
    """
    agent = get_or_404(agent_store, agent_id, "Agent")

    if (request.vm_name or "").strip() != (agent.vm_name or "").strip():
        raise HTTPException(status_code=400, detail="vm_name does not match agent record")

    intel_ta_token = (request.attestation.get("tdx") or {}).get("intel_ta_token")
    if not intel_ta_token:
        raise HTTPException(status_code=400, detail="attestation.tdx.intel_ta_token is required")

    # Verify token and bind it to this agent's MRTD (prevents cross-agent spoofing).
    ita_result = await verify_attestation_token(intel_ta_token)
    if not ita_result.get("verified"):
        raise HTTPException(
            status_code=403,
            detail=f"Intel TA verification failed: {ita_result.get('error', 'unknown')}",
        )
    details = ita_result.get("details") or {}
    mrtd_from_claims = (details.get("tdx_mrtd") or "") or (
        ((details.get("tdx") or {}).get("tdx_mrtd")) or ""
    )
    if mrtd_from_claims and agent.mrtd and mrtd_from_claims != agent.mrtd:
        raise HTTPException(status_code=403, detail="MRTD does not match agent record")

    # Store full attestation blob for chain/debugging, then run drift checks + update flags.
    agent_store.update_attestation_blob(agent_id, request.attestation)
    await refresh_agent_attestation(agent_id, request.attestation)

    # Optional status update piggy-backed on heartbeat.
    if request.status is not None:
        deployment_id = request.deployment_id
        agent_store.update_status(agent_id, request.status, deployment_id=deployment_id)
    else:
        agent_store.heartbeat(agent_id)

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


def _normalize_statuses(values: list[str]) -> set[str]:
    return {value.strip().lower() for value in values if isinstance(value, str) and value.strip()}


@app.post(
    "/api/v1/admin/agents/capacity/reconcile",
    response_model=AgentCapacityReconcileResponse,
)
async def reconcile_agent_capacity(
    request: AgentCapacityReconcileRequest,
    _admin: bool = Depends(verify_admin_token),
):
    """Compute and optionally dispatch agent capacity shortfalls per datacenter/size."""
    if not request.targets:
        raise HTTPException(status_code=422, detail="At least one target is required")

    allowed_statuses = _normalize_statuses(request.allowed_statuses)
    if not allowed_statuses:
        raise HTTPException(
            status_code=422, detail="allowed_statuses must include at least one status"
        )

    agents = agent_store.list()
    target_results: list[AgentCapacityTargetResult] = []
    dispatch_results: list[AgentCapacityDispatchResult] = []
    total_shortfall = 0
    reason = request.reason.strip() or "agent-capacity-reconcile"

    for target in request.targets:
        target_datacenter = target.datacenter.strip().lower()
        if not target_datacenter:
            raise HTTPException(status_code=422, detail="target.datacenter must be non-empty")
        target_node_size = target.node_size.strip().lower()

        eligible_agent_ids: list[str] = []
        for agent in agents:
            agent_status = (agent.status or "").strip().lower()
            if agent_status not in allowed_statuses:
                continue
            if request.require_verified and not agent.verified:
                continue
            if request.require_healthy and (agent.health_status or "").strip().lower() != "healthy":
                continue
            if request.require_hostname and not (agent.hostname or "").strip():
                continue
            if (agent.datacenter or "").strip().lower() != target_datacenter:
                continue
            if target_node_size and (agent.node_size or "").strip().lower() != target_node_size:
                continue
            eligible_agent_ids.append(agent.agent_id)

        shortfall = max(0, target.min_count - len(eligible_agent_ids))
        total_shortfall += shortfall
        target_results.append(
            AgentCapacityTargetResult(
                datacenter=target_datacenter,
                node_size=target_node_size,
                min_count=target.min_count,
                eligible_count=len(eligible_agent_ids),
                shortfall=shortfall,
                eligible_agent_ids=eligible_agent_ids,
            )
        )

        if request.dispatch and shortfall > 0:
            dispatched, status_code, detail = await dispatch_provision_request(
                datacenter=target_datacenter,
                node_size=target_node_size,
                count=shortfall,
                reason=reason,
            )
            dispatch_results.append(
                AgentCapacityDispatchResult(
                    datacenter=target_datacenter,
                    node_size=target_node_size,
                    requested_count=shortfall,
                    dispatched=dispatched,
                    status_code=status_code,
                    detail=detail,
                )
            )

    return AgentCapacityReconcileResponse(
        eligible=total_shortfall == 0,
        total_shortfall=total_shortfall,
        targets=target_results,
        dispatches=dispatch_results,
    )


@app.get(
    "/api/v1/admin/cloud/resources",
    response_model=CloudResourceInventoryResponse,
)
async def list_cloud_resources(
    _admin: bool = Depends(verify_admin_token),
):
    """List observed cloud resources used by the control plane.

    This is an inventory view derived from registered agents and deployments.
    """
    agents = agent_store.list()
    deployments = deployment_store.list()
    active_statuses = {"pending", "deploying", "running", "in_progress"}

    cloud_rollups: dict[str, dict] = {}
    resource_agents: list[CloudResourceAgent] = []

    for agent in agents:
        datacenter = (agent.datacenter or "").strip().lower()
        cloud = _extract_cloud(datacenter) or "unknown"
        az = _extract_availability_zone(datacenter)
        region = _extract_region_from_zone(az)
        node_size = (agent.node_size or "").strip().lower()
        status = (agent.status or "").strip().lower()
        health_status = (agent.health_status or "").strip().lower()

        resource_agents.append(
            CloudResourceAgent(
                agent_id=agent.agent_id,
                vm_name=agent.vm_name,
                cloud=cloud,
                datacenter=datacenter,
                availability_zone=az,
                region=region,
                node_size=node_size,
                status=status,
                health_status=health_status,
                verified=agent.verified,
                deployed_app=agent.deployed_app,
                hostname=agent.hostname,
            )
        )

        bucket = cloud_rollups.setdefault(
            cloud,
            {
                "total_agents": 0,
                "healthy_agents": 0,
                "verified_agents": 0,
                "undeployed_agents": 0,
                "deployed_agents": 0,
                "deploying_agents": 0,
                "node_size_counts": {},
                "datacenters": set(),
            },
        )
        bucket["total_agents"] += 1
        if health_status == "healthy":
            bucket["healthy_agents"] += 1
        if agent.verified:
            bucket["verified_agents"] += 1
        if status == "undeployed":
            bucket["undeployed_agents"] += 1
        elif status == "deployed":
            bucket["deployed_agents"] += 1
        elif status == "deploying":
            bucket["deploying_agents"] += 1

        if node_size:
            bucket["node_size_counts"][node_size] = bucket["node_size_counts"].get(node_size, 0) + 1
        if datacenter:
            bucket["datacenters"].add(datacenter)

    cloud_summaries: list[CloudResourceCloudSummary] = []
    for cloud, bucket in sorted(cloud_rollups.items(), key=lambda kv: kv[0]):
        cloud_summaries.append(
            CloudResourceCloudSummary(
                cloud=cloud,
                total_agents=bucket["total_agents"],
                healthy_agents=bucket["healthy_agents"],
                verified_agents=bucket["verified_agents"],
                undeployed_agents=bucket["undeployed_agents"],
                deployed_agents=bucket["deployed_agents"],
                deploying_agents=bucket["deploying_agents"],
                node_size_counts=bucket["node_size_counts"],
                datacenters=sorted(bucket["datacenters"]),
            )
        )

    resource_agents.sort(key=lambda a: (a.cloud, a.datacenter, a.node_size, a.vm_name))

    return CloudResourceInventoryResponse(
        generated_at=datetime.now(timezone.utc),
        total_agents=len(resource_agents),
        total_deployments=len(deployments),
        active_deployments=len(
            [
                d
                for d in deployments
                if isinstance(d.status, str) and d.status.strip().lower() in active_statuses
            ]
        ),
        clouds=cloud_summaries,
        agents=resource_agents,
    )


@app.get(
    "/api/v1/admin/cloud/resources/external",
    response_model=ExternalCloudInventoryResponse,
)
async def list_external_cloud_resources(
    _admin: bool = Depends(verify_admin_token),
):
    """List Azure/GCP resources from external provisioner inventory webhook."""
    configured, status_code, detail, payload = await fetch_external_inventory()
    now = datetime.now(timezone.utc)
    if not configured:
        return ExternalCloudInventoryResponse(
            configured=False,
            generated_at=now,
            detail=detail,
        )

    if detail:
        return ExternalCloudInventoryResponse(
            configured=True,
            generated_at=now,
            detail=detail,
        )

    raw_resources = _extract_external_resource_items(payload)
    tracked_agents = agent_store.list()
    agents_by_id = {a.agent_id: a for a in tracked_agents}
    agents_by_vm = {
        (a.vm_name or "").strip().lower(): a for a in tracked_agents if (a.vm_name or "").strip()
    }
    normalized_resources: list[ExternalCloudResource] = []
    for idx, raw in enumerate(raw_resources):
        if not isinstance(raw, dict):
            continue

        provider_raw = str(raw.get("provider") or raw.get("cloud") or "").strip().lower()
        normalized_clouds = _normalize_clouds([provider_raw]) if provider_raw else set()
        cloud = next(iter(normalized_clouds), provider_raw or "unknown")

        resource_id = str(
            raw.get("resource_id") or raw.get("id") or raw.get("instance_id") or ""
        ).strip()
        name = str(raw.get("name") or raw.get("vm_name") or "").strip()
        if not resource_id:
            resource_id = f"resource-{idx + 1}"

        datacenter = str(raw.get("datacenter") or "").strip().lower()
        zone = str(raw.get("availability_zone") or raw.get("zone") or "").strip().lower()
        region = str(raw.get("region") or "").strip().lower()

        if not datacenter and cloud and zone:
            datacenter = f"{cloud}:{zone}"
        if datacenter and not zone:
            zone = _extract_availability_zone(datacenter)
        if not region:
            region = _extract_region_from_zone(zone)

        labels = raw.get("labels") if isinstance(raw.get("labels"), dict) else {}
        metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}

        linked_agent_id = str(
            raw.get("linked_agent_id")
            or raw.get("agent_id")
            or metadata.get("agent_id")
            or labels.get("agent_id")
            or ""
        ).strip()
        linked_vm_name = str(
            raw.get("linked_vm_name")
            or raw.get("vm_name")
            or metadata.get("vm_name")
            or labels.get("vm_name")
            or name
            or ""
        ).strip()

        linked_agent = None
        if linked_agent_id:
            linked_agent = agents_by_id.get(linked_agent_id)
        if not linked_agent and linked_vm_name:
            linked_agent = agents_by_vm.get(linked_vm_name.lower())
            if linked_agent:
                linked_agent_id = linked_agent.agent_id
        if linked_agent and not linked_vm_name:
            linked_vm_name = linked_agent.vm_name

        tracked = bool(raw.get("tracked")) or linked_agent is not None
        orphaned = bool(raw.get("orphaned")) if "orphaned" in raw else not tracked
        if linked_agent is not None:
            orphaned = False
            if not datacenter:
                datacenter = (linked_agent.datacenter or "").strip().lower()
            if not zone:
                zone = _extract_availability_zone(datacenter)
            if not region:
                region = _extract_region_from_zone(zone)

        normalized_resources.append(
            ExternalCloudResource(
                provider=provider_raw or cloud,
                cloud=cloud,
                resource_id=resource_id,
                resource_type=str(raw.get("resource_type") or raw.get("type") or "")
                .strip()
                .lower(),
                name=name,
                datacenter=datacenter,
                availability_zone=zone,
                region=region,
                status=str(raw.get("status") or raw.get("state") or "").strip().lower(),
                labels={str(k): str(v) for k, v in labels.items()},
                metadata=metadata,
                tracked=tracked,
                orphaned=orphaned,
                linked_agent_id=linked_agent_id or None,
                linked_vm_name=linked_vm_name or None,
            )
        )

    normalized_resources.sort(
        key=lambda r: (
            r.cloud,
            r.region,
            r.availability_zone,
            r.resource_type,
            r.name,
            r.resource_id,
        )
    )
    return ExternalCloudInventoryResponse(
        configured=True,
        generated_at=now,
        total_resources=len(normalized_resources),
        tracked_count=sum(1 for r in normalized_resources if r.tracked),
        orphaned_count=sum(1 for r in normalized_resources if r.orphaned),
        detail=_normalize_inventory_detail(payload, status_code),
        resources=normalized_resources,
    )


@app.post(
    "/api/v1/admin/cloud/resources/cleanup",
    response_model=ExternalCloudCleanupResponse,
)
async def cleanup_external_cloud_resources(
    request: ExternalCloudCleanupRequest,
    _admin: bool = Depends(verify_admin_token),
):
    """Dispatch Azure/GCP orphan cleanup through external provisioner webhook."""
    configured, dispatched, status_code, detail, payload = await dispatch_external_cleanup(
        request.model_dump()
    )
    if isinstance(payload.get("dispatched"), bool):
        dispatched = dispatched and bool(payload.get("dispatched"))

    response_detail = detail
    if not response_detail and isinstance(payload.get("detail"), str):
        response_detail = payload.get("detail")
    if not response_detail and isinstance(payload.get("message"), str):
        response_detail = payload.get("message")

    return ExternalCloudCleanupResponse(
        configured=configured,
        dispatched=dispatched,
        dry_run=request.dry_run,
        requested_count=_extract_cleanup_requested_count(payload),
        status_code=status_code,
        detail=response_detail,
    )


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
    agent_store.set_deployed_app(agent_id, None)
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


@app.patch("/api/v1/agents/{agent_id}/owner")
async def set_agent_owner(
    agent_id: str,
    request: SetAgentOwnerRequest,
    session: AdminSession = Depends(verify_admin_token),
):
    """Set or clear the GitHub owner for an agent (admin-only)."""
    if not is_admin_session(session):
        raise HTTPException(status_code=403, detail="Admin access required")
    get_or_404(agent_store, agent_id, "Agent")
    agent_store.set_github_owner(agent_id, request.github_owner)
    logger.info(
        f"Agent {agent_id} owner set to {request.github_owner!r} by {session.github_login or 'admin'}"
    )
    return {"agent_id": agent_id, "github_owner": request.github_owner}


# ==============================================================================
# Owner-scoped API - GitHub owners can manage their agents
# ==============================================================================


@app.get("/api/v1/me/agents")
async def list_my_agents(session: AdminSession = Depends(verify_admin_token)):
    """List agents owned by the current GitHub user (matches login + orgs)."""
    identities = get_owner_identities(session)
    if not identities:
        return {"agents": [], "total": 0}
    agents = agent_store.list_by_owners(identities)
    return {"agents": agents, "total": len(agents)}


@app.get("/api/v1/me/agents/{agent_id}")
async def get_my_agent(agent_id: str, session: AdminSession = Depends(verify_admin_token)):
    """Get a single agent (ownership check)."""
    agent = get_or_404(agent_store, agent_id, "Agent")
    require_owner_or_admin(session, agent)
    return agent


@app.post("/api/v1/me/agents/{agent_id}/reset")
async def reset_my_agent(agent_id: str, session: AdminSession = Depends(verify_admin_token)):
    """Reset an owned agent to undeployed status."""
    agent = get_or_404(agent_store, agent_id, "Agent")
    require_owner_or_admin(session, agent)

    agent_store.update_status(agent_id, "undeployed", None)
    agent_store.update_attestation_status(agent_id, attestation_valid=True)
    agent_store.set_deployed_app(agent_id, None)
    logger.info(f"Owner {session.github_login} reset agent {agent_id}")

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
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Failed to create tunnel: {e}") from e

    return {"status": "reset", "agent_id": agent_id, "tunnel_created": tunnel_created}


@app.get("/api/v1/me/deployments")
async def list_my_deployments(session: AdminSession = Depends(verify_admin_token)):
    """List deployments for agents owned by the current GitHub user."""
    identities = get_owner_identities(session)
    if not identities:
        return {"deployments": [], "total": 0}
    owned_agents = agent_store.list_by_owners(identities)
    owned_agent_ids = {a.agent_id for a in owned_agents}
    all_deployments = deployment_store.list()
    deployments = [d for d in all_deployments if d.agent_id in owned_agent_ids]
    return {"deployments": deployments, "total": len(deployments)}


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
# Trusted MRTD API - Read-only view of effective trust (env vars + DB)
# ==============================================================================


@app.get("/api/v1/trusted-mrtds")
async def get_trusted_mrtds():
    """List all trusted MRTDs (effective trust list).

    Trusted MRTDs can be bootstrapped via environment variables
    (TRUSTED_AGENT_MRTDS / TRUSTED_PROXY_MRTDS, comma-separated) and can also be
    extended at runtime via the admin-only DB-backed API.
    """
    mrtds = list_trusted_mrtds()
    return {
        "trusted_mrtds": [{"mrtd": k, "type": v} for k, v in mrtds.items()],
        "total": len(mrtds),
    }


@app.get("/api/v1/admin/trusted-mrtds")
async def list_trusted_mrtds_admin(session: AdminSession = Depends(verify_admin_token)):
    """Admin-only view of DB-backed trusted MRTDs."""
    if not is_admin_session(session):
        raise HTTPException(status_code=403, detail="Admin access required")
    from .storage import trusted_mrtd_store

    rows = trusted_mrtd_store.list()
    return {
        "trusted_mrtds": [
            {
                "mrtd": r.mrtd,
                "type": r.mrtd_type,
                "note": r.note,
                "added_at": r.added_at.isoformat() if r.added_at else None,
            }
            for r in rows
        ],
        "total": len(rows),
    }


@app.post("/api/v1/admin/trusted-mrtds")
async def add_trusted_mrtd_admin(
    request: dict,
    session: AdminSession = Depends(verify_admin_token),
):
    """Admin-only: add a trusted MRTD baseline without rebooting the control plane.

    Body:
      - mrtd: 96-hex string
      - type: agent|proxy (default: agent)
      - note: optional free-form note
    """
    if not is_admin_session(session):
        raise HTTPException(status_code=403, detail="Admin access required")
    mrtd = str(request.get("mrtd") or "").strip()
    mrtd_type = str(request.get("type") or "agent").strip()
    note = str(request.get("note") or "").strip()
    if not mrtd:
        raise HTTPException(status_code=400, detail="mrtd is required")
    from .storage import trusted_mrtd_store

    try:
        obj = trusted_mrtd_store.upsert(mrtd, mrtd_type=mrtd_type, note=note)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"mrtd": obj.mrtd, "type": obj.mrtd_type, "note": obj.note}


@app.delete("/api/v1/admin/trusted-mrtds/{mrtd}")
async def delete_trusted_mrtd_admin(
    mrtd: str,
    session: AdminSession = Depends(verify_admin_token),
):
    """Admin-only: remove a trusted MRTD baseline."""
    if not is_admin_session(session):
        raise HTTPException(status_code=403, detail="Admin access required")
    from .storage import trusted_mrtd_store

    ok = trusted_mrtd_store.delete(mrtd)
    if not ok:
        raise HTTPException(status_code=404, detail="MRTD not found")
    return {"status": "deleted", "mrtd": mrtd}


# ==============================================================================
# Admin: Settings
# ==============================================================================


@app.get("/api/v1/admin/settings")
async def admin_list_settings(
    group: str | None = Query(None),
    _admin: bool = Depends(verify_admin_token),
):
    """List all settings with values, sources, and metadata."""
    return {"settings": list_settings(group=group)}


@app.put("/api/v1/admin/settings/{key:path}")
async def admin_update_setting(
    key: str,
    body: dict,
    _admin: bool = Depends(verify_admin_token),
):
    """Save a setting value to the database."""
    if key not in SETTING_DEFS:
        raise HTTPException(status_code=404, detail=f"Unknown setting: {key}")
    value = body.get("value")
    if value is None:
        raise HTTPException(status_code=422, detail="Missing 'value' field")
    set_setting(key, str(value))
    logger.info(f"Setting updated: {key}")
    return {"key": key, "status": "saved"}


@app.delete("/api/v1/admin/settings/{key:path}")
async def admin_reset_setting(
    key: str,
    _admin: bool = Depends(verify_admin_token),
):
    """Remove a setting from DB (reverts to env var or default)."""
    if key not in SETTING_DEFS:
        raise HTTPException(status_code=404, detail=f"Unknown setting: {key}")
    deleted = delete_setting(key)
    logger.info(f"Setting reset: {key} (was_in_db={deleted})")
    return {"key": key, "status": "reset"}


@app.get("/api/v1/admin/stripe/status")
async def admin_stripe_status(
    validate: bool = Query(False),
    _admin: bool = Depends(verify_admin_token),
):
    """Return basic Stripe integration status for the admin UI.

    If validate=true, attempts a lightweight Stripe API call to confirm the key works.
    """
    from .billing import _ensure_stripe, _stripe_mod

    secret_key = get_setting("stripe.secret_key")
    webhook_secret = get_setting("stripe.webhook_secret")

    mode = ""
    if secret_key.startswith("sk_test_"):
        mode = "test"
    elif secret_key.startswith("sk_live_"):
        mode = "live"

    stripe_available = _stripe_mod is not None
    stripe_enabled = _ensure_stripe()

    validation = {"attempted": bool(validate), "ok": None, "error": None}
    if validate:
        if not stripe_enabled:
            validation["ok"] = False
            validation["error"] = (
                "Stripe not enabled (missing STRIPE_SECRET_KEY or SDK unavailable)"
            )
        else:
            try:
                # A small, read-only call that works in test mode too.
                _stripe_mod.Balance.retrieve()
                validation["ok"] = True
            except Exception as e:
                # Return a safe summary; avoid leaking request details.
                validation["ok"] = False
                validation["error"] = f"{type(e).__name__}: {str(e)[:200]}"

    return {
        "stripe_available": stripe_available,
        "stripe_enabled": stripe_enabled,
        "mode": mode,
        "secret_key_configured": bool(secret_key),
        "secret_key_source": get_setting_source("stripe.secret_key"),
        "webhook_secret_configured": bool(webhook_secret),
        "webhook_secret_source": get_setting_source("stripe.webhook_secret"),
        "webhook_path": "/api/v1/webhooks/stripe",
        "validation": validation,
    }


# ==============================================================================
# Admin: Cloudflare Management
# ==============================================================================


@app.get("/api/v1/admin/cloudflare/status")
async def cloudflare_status(_admin: bool = Depends(verify_admin_token)):
    """Check if Cloudflare is configured and return domain info."""
    return {
        "configured": cloudflare.is_configured(),
        "domain": cloudflare.get_domain(),
    }


@app.get("/api/v1/admin/cloudflare/tunnels")
async def cloudflare_tunnels(_admin: bool = Depends(verify_admin_token)):
    """List Cloudflare tunnels cross-referenced with agents."""
    if not cloudflare.is_configured():
        raise HTTPException(status_code=400, detail="Cloudflare not configured")

    tunnels = await cloudflare.list_tunnels()
    agents = agent_store.list()

    # Build lookup: tunnel_id -> agent
    tunnel_to_agent = {}
    for agent in agents:
        if agent.tunnel_id:
            tunnel_to_agent[agent.tunnel_id] = agent

    enriched = []
    orphaned_count = 0
    for t in tunnels:
        agent = tunnel_to_agent.get(t["tunnel_id"])
        is_orphaned = agent is None
        if is_orphaned:
            orphaned_count += 1
        enriched.append(
            {
                **t,
                "agent_id": agent.agent_id if agent else None,
                "agent_vm_name": agent.vm_name if agent else None,
                "agent_status": agent.status if agent else None,
                "orphaned": is_orphaned,
            }
        )

    return {
        "tunnels": enriched,
        "total": len(enriched),
        "orphaned_count": orphaned_count,
        "connected_count": sum(1 for t in enriched if t["has_connections"]),
    }


@app.get("/api/v1/admin/cloudflare/dns")
async def cloudflare_dns(_admin: bool = Depends(verify_admin_token)):
    """List Cloudflare DNS CNAME records cross-referenced with tunnels."""
    if not cloudflare.is_configured():
        raise HTTPException(status_code=400, detail="Cloudflare not configured")

    records = await cloudflare.list_dns_records()
    tunnels = await cloudflare.list_tunnels()

    # Build lookup: tunnel_id -> tunnel
    tunnel_ids = {t["tunnel_id"] for t in tunnels}

    enriched = []
    orphaned_count = 0
    for r in records:
        content = r.get("content", "")
        # CNAME records for tunnels point to <tunnel_id>.cfargotunnel.com
        is_tunnel_record = content.endswith(".cfargotunnel.com")
        linked_tunnel_id = None
        if is_tunnel_record:
            linked_tunnel_id = content.replace(".cfargotunnel.com", "")

        is_orphaned = is_tunnel_record and linked_tunnel_id not in tunnel_ids
        if is_orphaned:
            orphaned_count += 1

        enriched.append(
            {
                **r,
                "is_tunnel_record": is_tunnel_record,
                "linked_tunnel_id": linked_tunnel_id,
                "orphaned": is_orphaned,
            }
        )

    return {
        "records": enriched,
        "total": len(enriched),
        "orphaned_count": orphaned_count,
        "tunnel_record_count": sum(1 for r in enriched if r["is_tunnel_record"]),
    }


@app.delete("/api/v1/admin/cloudflare/tunnels/{tunnel_id}")
async def cloudflare_delete_tunnel(tunnel_id: str, _admin: bool = Depends(verify_admin_token)):
    """Delete a Cloudflare tunnel and clear the agent's tunnel fields."""
    if not cloudflare.is_configured():
        raise HTTPException(status_code=400, detail="Cloudflare not configured")

    deleted = await cloudflare.delete_tunnel(tunnel_id)

    # Clear tunnel info from any agent that references this tunnel
    for agent in agent_store.list():
        if agent.tunnel_id == tunnel_id:
            agent_store.clear_tunnel_info(agent.agent_id)
            logger.info(f"Cleared tunnel info for agent {agent.agent_id}")

    return {"deleted": deleted, "tunnel_id": tunnel_id}


@app.delete("/api/v1/admin/cloudflare/dns/{record_id}")
async def cloudflare_delete_dns(record_id: str, _admin: bool = Depends(verify_admin_token)):
    """Delete a Cloudflare DNS record by ID."""
    if not cloudflare.is_configured():
        raise HTTPException(status_code=400, detail="Cloudflare not configured")

    deleted = await cloudflare.delete_dns_record_by_id(record_id)
    return {"deleted": deleted, "record_id": record_id}


@app.post("/api/v1/admin/cloudflare/cleanup")
async def cloudflare_cleanup(_admin: bool = Depends(verify_admin_token)):
    """Bulk delete all orphaned tunnels and DNS records."""
    if not cloudflare.is_configured():
        raise HTTPException(status_code=400, detail="Cloudflare not configured")

    # Get current tunnels and agents
    tunnels = await cloudflare.list_tunnels()
    agents = agent_store.list()
    tunnel_to_agent = {}
    for agent in agents:
        if agent.tunnel_id:
            tunnel_to_agent[agent.tunnel_id] = agent

    orphan_tunnel_ids = [
        tunnel["tunnel_id"]
        for tunnel in tunnels
        if tunnel.get("tunnel_id") and tunnel["tunnel_id"] not in tunnel_to_agent
    ]

    tunnel_results = await _cloudflare_delete_many(
        ids=orphan_tunnel_ids,
        delete_fn=cloudflare.delete_tunnel,
        concurrency=8,
    )
    tunnels_deleted = tunnel_results["deleted"]
    tunnels_failed = tunnel_results["failed"]

    # Get DNS records and infer remaining tunnels from deletion results.
    # This avoids another list_tunnels() call during large cleanups.
    records = await cloudflare.list_dns_records()
    initial_tunnel_ids = {tunnel.get("tunnel_id") for tunnel in tunnels if tunnel.get("tunnel_id")}
    remaining_ids = initial_tunnel_ids - set(tunnel_results["deleted_ids"])

    orphan_dns_record_ids = []
    for record in records:
        content = (record.get("content") or "").strip()
        if not content.endswith(".cfargotunnel.com"):
            continue
        linked_id = content.replace(".cfargotunnel.com", "")
        if linked_id not in remaining_ids and record.get("record_id"):
            orphan_dns_record_ids.append(record["record_id"])

    dns_results = await _cloudflare_delete_many(
        ids=orphan_dns_record_ids,
        delete_fn=cloudflare.delete_dns_record_by_id,
        concurrency=8,
    )
    dns_deleted = dns_results["deleted"]
    dns_failed = dns_results["failed"]

    logger.info(
        "Cloudflare cleanup complete: "
        f"tunnels_deleted={tunnels_deleted}/{len(orphan_tunnel_ids)} "
        f"dns_deleted={dns_deleted}/{len(orphan_dns_record_ids)} "
        f"tunnels_failed={tunnels_failed} dns_failed={dns_failed}"
    )
    return {
        "tunnels_deleted": tunnels_deleted,
        "dns_deleted": dns_deleted,
        "tunnels_candidates": len(orphan_tunnel_ids),
        "dns_candidates": len(orphan_dns_record_ids),
        "tunnels_failed": tunnels_failed,
        "dns_failed": dns_failed,
    }


# ==============================================================================
# Admin Authentication
# ==============================================================================


@app.post("/admin/login", response_model=AdminLoginResponse)
async def admin_login(request: AdminLoginRequest, req: Request):
    """Admin login endpoint - creates a session token."""
    if get_setting("auth.password_login_enabled").lower() != "true":
        raise HTTPException(status_code=403, detail="Password login is disabled. Use GitHub OAuth.")

    password_hash = get_admin_password_hash()
    if not password_hash:
        raise HTTPException(
            status_code=500,
            detail="Admin password not configured. Set ADMIN_PASSWORD_HASH environment variable.",
        )

    # Verify password
    if not verify_password(request.password, password_hash):
        logger.warning(
            f"Failed admin login attempt from {req.client.host if req.client else 'unknown'}"
        )
        raise HTTPException(status_code=401, detail="Invalid password")

    # Create session
    from app.db_models import AdminSession

    token = generate_session_token()
    token_hash_val = hash_api_key(token)  # Reuse API key hashing
    token_prefix = get_token_prefix(token)
    expires_at = create_session_expiry(hours=24)

    session = AdminSession(
        token_hash=token_hash_val,
        token_prefix=token_prefix,
        expires_at=expires_at,
        ip_address=req.client.host if req.client else None,
    )

    admin_session_store.create(session)

    # Debug: verify session was persisted (investigating token-immediately-invalid bug)
    readback = admin_session_store.get_by_prefix(token_prefix)
    if readback:
        logger.info(
            f"Admin login: session persisted OK, prefix={token_prefix!r}, "
            f"session_id={session.session_id}"
        )
    else:
        logger.error(
            f"Admin login: session NOT found after create! prefix={token_prefix!r}, "
            f"session_id={session.session_id}"
        )

    logger.info(f"Admin logged in from {req.client.host if req.client else 'unknown'}")

    return AdminLoginResponse(
        token=token,
        expires_at=expires_at,
    )


@app.get("/auth/methods")
async def auth_methods():
    """Return which login methods are available (public, no auth required)."""
    from .oauth import _client_id

    password_enabled = get_setting("auth.password_login_enabled").lower() == "true"
    github_enabled = bool(_client_id())
    result = {"password": password_enabled, "github": github_enabled}
    if _generated_admin_password:
        result["generated_password"] = _generated_admin_password
    return result


@app.get("/auth/github")
async def github_oauth_start():
    """Initiate GitHub OAuth flow for admin login."""
    from .oauth import _client_id, create_oauth_state, get_github_authorize_url

    if not _client_id():
        raise HTTPException(
            status_code=503, detail="GitHub OAuth not configured. Set GITHUB_OAUTH_CLIENT_ID."
        )

    # Generate CSRF state token
    state = create_oauth_state()
    auth_url = get_github_authorize_url(state)

    return {"auth_url": auth_url, "state": state}


@app.get("/auth/github/callback")
async def github_oauth_callback(
    code: str,
    state: str,
    req: Request,
):
    """Handle GitHub OAuth callback and create admin session."""
    from fastapi.responses import RedirectResponse

    from app.db_models import AdminSession

    from .oauth import (
        exchange_code_for_token,
        get_github_user,
        get_github_user_orgs,
        verify_oauth_state,
    )

    # Verify state (CSRF protection)
    if not verify_oauth_state(state):
        raise HTTPException(status_code=400, detail="Invalid or expired state token")

    # Exchange code for access token
    try:
        access_token = await exchange_code_for_token(code)
        user_info = await get_github_user(access_token)
    except Exception as e:
        logger.error(f"GitHub OAuth error: {e}")
        raise HTTPException(status_code=400, detail="GitHub authentication failed") from e

    # Fetch org memberships
    try:
        github_orgs = await get_github_user_orgs(access_token)
    except Exception as e:
        logger.warning(f"Failed to fetch GitHub orgs: {e}")
        github_orgs = []

    # Create admin session
    token = generate_session_token()
    expires_at = create_session_expiry(hours=24)

    session = AdminSession(
        token_hash=hash_api_key(token),
        token_prefix=get_token_prefix(token),
        expires_at=expires_at,
        ip_address=req.client.host if req.client else None,
        github_id=user_info["github_id"],
        github_login=user_info["github_login"],
        github_email=user_info["github_email"],
        github_avatar_url=user_info.get("github_avatar_url"),
        auth_method="github_oauth",
        github_orgs=github_orgs or None,
    )

    admin_session_store.create(session)
    logger.info(
        f"Admin logged in via GitHub: {user_info['github_login']} from {req.client.host if req.client else 'unknown'}"
    )

    # Redirect to admin UI with token in query param
    return RedirectResponse(url=f"/admin?token={token}", status_code=302)


@app.get("/auth/me")
async def get_current_user(session: AdminSession = Depends(verify_admin_token)):
    """Get current authenticated admin user info."""
    return {
        "authenticated": True,
        "auth_method": session.auth_method,
        "is_admin": is_admin_session(session),
        "github_login": session.github_login,
        "github_email": session.github_email,
        "github_avatar_url": session.github_avatar_url,
        "github_orgs": session.github_orgs or [],
        "created_at": session.created_at.isoformat(),
        "expires_at": session.expires_at.isoformat(),
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


@app.post("/api/v1/accounts")
async def create_account(request: AccountCreateRequest):
    """Create a new billing account and return API key (only shown once)."""
    if request.account_type not in ("deployer", "agent", "contributor"):
        raise HTTPException(
            status_code=400,
            detail="account_type must be 'deployer', 'agent', or 'contributor'",
        )

    if not request.name:
        raise HTTPException(status_code=400, detail="Account name is required")

    existing = account_store.get_by_name(request.name)
    if existing:
        raise HTTPException(status_code=409, detail=f"Account '{request.name}' already exists")

    # Generate API key
    api_key = generate_api_key("live")
    api_key_hash_val = hash_api_key(api_key)
    api_key_prefix = get_key_prefix(api_key)

    account = Account(
        name=request.name,
        description=request.description,
        account_type=request.account_type,
        api_key_hash=api_key_hash_val,
        api_key_prefix=api_key_prefix,
    )
    account_store.create(account)
    logger.info(f"Account created: {account.name} ({account.account_id})")

    return {
        "account_id": account.account_id,
        "name": account.name,
        "description": account.description,
        "account_type": account.account_type,
        "balance": 0.0,
        "created_at": account.created_at,
        "api_key": api_key,  # ONLY returned once!
        "warning": "Save this API key now. It will never be shown again.",
    }


@app.post("/api/v1/accounts/{account_id}/identity", response_model=AccountResponse)
async def link_account_identity(
    account_id: str,
    request: AccountLinkIdentityRequest,
    authenticated_account_id: str = Depends(verify_account_api_key),
):
    """Link an account to contributor identity metadata (GitHub login/org)."""
    if account_id != authenticated_account_id:
        raise HTTPException(status_code=403, detail="Cannot edit identity for other accounts")

    account = get_or_404(account_store, account_id, "Account")
    account = account_store.update_identity(
        account_id=account_id,
        github_login=(request.github_login or "").strip() or None,
        github_org=(request.github_org or "").strip() or None,
        linked_at=datetime.now(timezone.utc),
    )
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    return AccountResponse(
        account_id=account.account_id,
        name=account.name,
        description=account.description,
        account_type=account.account_type,
        github_login=account.github_login,
        github_org=account.github_org,
        balance=account_store.get_balance(account.account_id),
        created_at=account.created_at,
    )


@app.get("/api/v1/accounts", response_model=AccountListResponse)
async def list_accounts(
    name: str | None = Query(None, description="Filter by name (partial match)"),
    account_type: str | None = Query(None, description="Filter by account type"),
    _admin: bool = Depends(verify_admin_token),
):
    """List all billing accounts (admin only)."""
    accounts = account_store.list(build_filters(name=name, account_type=account_type))
    responses = [
        AccountResponse(
            account_id=a.account_id,
            name=a.name,
            description=a.description,
            account_type=a.account_type,
            github_login=a.github_login,
            github_org=a.github_org,
            balance=account_store.get_balance(a.account_id),
            created_at=a.created_at,
        )
        for a in accounts
    ]
    return AccountListResponse(accounts=responses, total=len(responses))


@app.get("/api/v1/accounts/{account_id}", response_model=AccountResponse)
async def get_account(
    account_id: str,
    authenticated_account_id: str = Depends(verify_account_api_key),
):
    """Get a billing account with its current balance (account owner only)."""
    if account_id != authenticated_account_id:
        raise HTTPException(status_code=403, detail="Cannot access other accounts")

    account = get_or_404(account_store, account_id, "Account")
    return AccountResponse(
        account_id=account.account_id,
        name=account.name,
        description=account.description,
        account_type=account.account_type,
        github_login=account.github_login,
        github_org=account.github_org,
        balance=account_store.get_balance(account.account_id),
        created_at=account.created_at,
    )


@app.post("/api/v1/accounts/{account_id}/api-key/rotate", response_model=ApiKeyRotateResponse)
async def rotate_account_api_key(
    account_id: str,
    authenticated_account_id: str = Depends(verify_account_api_key),
):
    """Rotate an account API key (account owner only)."""
    if account_id != authenticated_account_id:
        raise HTTPException(status_code=403, detail="Cannot rotate API key for other accounts")

    get_or_404(account_store, account_id, "Account")

    new_api_key = generate_api_key("live")
    updated = account_store.update_api_credentials(
        account_id=account_id,
        api_key_hash=hash_api_key(new_api_key),
        api_key_prefix=get_key_prefix(new_api_key),
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Account not found")

    return ApiKeyRotateResponse(
        account_id=account_id,
        api_key=new_api_key,
        rotated_at=datetime.now(timezone.utc),
        warning="Save this API key now. Previous key has been revoked.",
    )


@app.delete("/api/v1/accounts/{account_id}")
async def delete_account(
    account_id: str,
    authenticated_account_id: str = Depends(verify_account_api_key),
):
    """Delete a billing account (only if balance is zero, account owner only)."""
    if account_id != authenticated_account_id:
        raise HTTPException(status_code=403, detail="Cannot delete other accounts")

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
async def deposit_to_account(
    account_id: str,
    request: DepositRequest,
    authenticated_account_id: str = Depends(verify_account_api_key),
):
    """Deposit funds into an account (account owner only)."""
    if account_id != authenticated_account_id:
        raise HTTPException(status_code=403, detail="Cannot deposit to other accounts")

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
    authenticated_account_id: str = Depends(verify_account_api_key),
):
    """List transactions for an account (newest first, account owner only)."""
    if account_id != authenticated_account_id:
        raise HTTPException(status_code=403, detail="Cannot access other account transactions")

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


@app.post("/api/v1/accounts/{account_id}/payment-intent")
async def create_payment_intent(
    account_id: str,
    request: CreatePaymentIntentRequest,
    authenticated_account_id: str = Depends(verify_account_api_key),
):
    """Create a Stripe payment intent for depositing funds (account owner only)."""
    if account_id != authenticated_account_id:
        raise HTTPException(
            status_code=403, detail="Cannot create payment intent for other accounts"
        )

    # Import stripe from billing module
    from .billing import _ensure_stripe, _stripe_mod

    if not _ensure_stripe():
        raise HTTPException(
            status_code=503,
            detail="Stripe integration not configured. Set STRIPE_SECRET_KEY environment variable.",
        )

    get_or_404(account_store, account_id, "Account")

    try:
        intent = _stripe_mod.PaymentIntent.create(
            amount=int(request.amount * 100),  # Convert to cents
            currency="usd",
            metadata={"account_id": account_id},
        )

        logger.info(f"Created payment intent for account {account_id}: ${request.amount:.2f}")

        return {
            "client_secret": intent.client_secret,
            "amount": request.amount,
            "payment_intent_id": intent.id,
        }
    except Exception as e:
        logger.error(f"Error creating Stripe payment intent: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to create payment intent: {str(e)}"
        ) from e


@app.post("/api/v1/webhooks/stripe")
async def stripe_webhook(request: Request):
    """Stripe webhook endpoint for payment confirmations."""
    from .billing import _ensure_stripe, _stripe_mod, _webhook_secret

    if not _ensure_stripe():
        raise HTTPException(status_code=503, detail="Stripe integration not configured")

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    if not sig_header:
        raise HTTPException(status_code=400, detail="Missing stripe-signature header")

    try:
        event = _stripe_mod.Webhook.construct_event(payload, sig_header, _webhook_secret())
    except ValueError as e:
        logger.error("Invalid Stripe webhook payload")
        raise HTTPException(status_code=400, detail="Invalid payload") from e
    except _stripe_mod.error.SignatureVerificationError as e:
        logger.error("Invalid Stripe webhook signature")
        raise HTTPException(status_code=400, detail="Invalid signature") from e

    # Handle payment_intent.succeeded
    if event["type"] == "payment_intent.succeeded":
        payment_intent = event["data"]["object"]
        account_id = payment_intent["metadata"].get("account_id")
        amount = payment_intent["amount"] / 100.0  # Convert from cents

        if account_id:
            try:
                create_transaction(
                    account_store,
                    transaction_store,
                    account_id,
                    amount=amount,
                    tx_type="deposit",
                    description="Stripe payment",
                    reference_id=payment_intent["id"],
                )
                logger.info(
                    f"Processed Stripe payment: ${amount:.2f} deposited to account {account_id}"
                )
            except Exception as e:
                logger.error(f"Error processing Stripe payment: {e}")
        else:
            logger.warning(
                f"Stripe payment intent {payment_intent['id']} has no account_id metadata"
            )

    return {"status": "ok"}


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


@app.get("/api/v1/apps/{name}/revenue-shares", response_model=AppRevenueShareListResponse)
async def list_app_revenue_shares(name: str):
    """List contributor revenue-share rules for an app."""
    found_app = app_store.get_by_name(name)
    if found_app is None:
        raise HTTPException(status_code=404, detail="App not found")

    shares = app_revenue_share_store.list_for_app(name)
    response_rows: list[AppRevenueShareResponse] = []
    for share in shares:
        account = account_store.get(share.account_id)
        response_rows.append(
            AppRevenueShareResponse(
                share_id=share.share_id,
                app_name=share.app_name,
                account_id=share.account_id,
                account_name=account.name if account else None,
                github_login=account.github_login if account else None,
                share_bps=share.share_bps,
                share_percent=round(share.share_bps / 100.0, 4),
                label=share.label,
                created_at=share.created_at,
            )
        )

    total_bps = sum(share.share_bps for share in shares)
    return AppRevenueShareListResponse(
        app_name=name,
        total_bps=total_bps,
        total_percent=round(total_bps / 100.0, 4),
        shares=response_rows,
    )


@app.post(
    "/api/v1/apps/{name}/revenue-shares",
    response_model=AppRevenueShareResponse,
)
async def create_app_revenue_share(
    name: str,
    request: AppRevenueShareCreateRequest,
    _admin: bool = Depends(verify_admin_token),
):
    """Create a contributor revenue-share rule for an app (admin only)."""
    found_app = app_store.get_by_name(name)
    if found_app is None:
        raise HTTPException(status_code=404, detail="App not found")

    account = account_store.get(request.account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    if account.account_type not in ("contributor", "agent"):
        raise HTTPException(
            status_code=400,
            detail="Revenue share account_type must be 'contributor' or 'agent'",
        )

    current_total_bps = app_revenue_share_store.total_bps_for_app(name)
    if current_total_bps + request.share_bps > 10000:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Revenue share total exceeds 10000 bps: "
                f"current={current_total_bps}, requested={request.share_bps}"
            ),
        )

    created = AppRevenueShare(
        app_name=name,
        account_id=request.account_id,
        share_bps=request.share_bps,
        label=request.label,
    )
    app_revenue_share_store.create(created)

    return AppRevenueShareResponse(
        share_id=created.share_id,
        app_name=created.app_name,
        account_id=created.account_id,
        account_name=account.name,
        github_login=account.github_login,
        share_bps=created.share_bps,
        share_percent=round(created.share_bps / 100.0, 4),
        label=created.label,
        created_at=created.created_at,
    )


@app.delete("/api/v1/apps/{name}/revenue-shares/{share_id}")
async def delete_app_revenue_share(
    name: str,
    share_id: str,
    _admin: bool = Depends(verify_admin_token),
):
    """Delete a contributor revenue-share rule for an app (admin only)."""
    found_app = app_store.get_by_name(name)
    if found_app is None:
        raise HTTPException(status_code=404, detail="App not found")

    share = app_revenue_share_store.get(share_id)
    if not share or share.app_name != name:
        raise HTTPException(status_code=404, detail="Revenue share not found")

    app_revenue_share_store.delete(share_id)
    return {"status": "deleted", "share_id": share_id, "app_name": name}


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

    # Check if version already exists for this node_size
    existing = app_version_store.get_by_version(name, request.version, request.node_size)
    if existing:
        size_label = f" (node_size='{request.node_size}')" if request.node_size else ""
        raise HTTPException(
            status_code=409,
            detail=f"Version '{request.version}'{size_label} already exists for app '{name}'",
        )

    # Create version record (status: pending)
    new_version = AppVersion(
        app_name=name,
        version=request.version,
        node_size=request.node_size,
        compose=request.compose,
        image_digest=request.image_digest,
        source_commit=request.source_commit,
        source_tag=request.source_tag,
        ingress=request.ingress,
        status="pending",
    )
    app_version_store.create(new_version)
    logger.info(
        f"Version created: {name}@{request.version} node_size='{request.node_size}' "
        f"({new_version.version_id})"
    )

    # Version stays "pending" until the measuring enclave processes it
    return AppVersionResponse(
        version_id=new_version.version_id,
        app_name=new_version.app_name,
        version=new_version.version,
        node_size=new_version.node_size,
        mrtd=new_version.mrtd,
        attestation=new_version.attestation,
        ingress=new_version.ingress,
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
async def get_app_version(name: str, version: str, node_size: str = ""):
    """Get details for a specific version of an app."""
    found_app = app_store.get_by_name(name)
    if found_app is None:
        raise HTTPException(status_code=404, detail="App not found")

    found_version = app_version_store.get_by_version(name, version, node_size)
    if found_version is None:
        raise HTTPException(status_code=404, detail="Version not found")

    return found_version


@app.post("/api/v1/apps/{name}/versions/{version}/attest")
async def manual_attest_version(
    name: str,
    version: str,
    node_size: str = "",
    request: ManualAttestRequest | None = None,
    _admin: bool = Depends(verify_admin_token),
):
    """Manually attest an app version (admin only).

    Used to bootstrap the measuring enclave itself (chicken-and-egg problem).
    """
    found_version = app_version_store.get_by_version(name, version, node_size)
    if found_version is None:
        raise HTTPException(status_code=404, detail="Version not found")

    app_version_store.update_status(
        found_version.version_id,
        status="attested",
        mrtd=request.mrtd if request else None,
        attestation=request.attestation if request else None,
    )
    logger.info(
        f"Manually attested: {name}@{version} node_size='{node_size}' "
        f"(mrtd_set={bool(request and request.mrtd)})"
    )
    return {"status": "attested", "version_id": found_version.version_id}


@app.post("/api/v1/internal/measurement-callback")
async def measurement_callback(request: MeasurementCallbackRequest):
    """Receive measurement results from the measuring enclave."""
    found_version = app_version_store.get(request.version_id)
    if not found_version:
        raise HTTPException(status_code=404, detail="Version not found")

    if request.status == "success":
        mode = get_setting("operational.signature_verification_mode").strip().lower()
        if mode not in {"strict", "warn", "disabled"}:
            logger.warning(f"Invalid SIGNATURE_VERIFICATION_MODE '{mode}', defaulting to 'warn'")
            mode = "warn"

        if mode != "disabled":
            failures: list[str] = []
            measurement = request.measurement if isinstance(request.measurement, dict) else None
            if measurement is None:
                failures.append("measurement payload missing")
            else:
                resolved_images = measurement.get("resolved_images")
                if not isinstance(resolved_images, dict) or not resolved_images:
                    failures.append("resolved_images missing from measurement payload")
                else:
                    for service_name, image_entry in resolved_images.items():
                        if not isinstance(image_entry, dict):
                            failures.append(f"{service_name}: invalid image measurement payload")
                            continue
                        if image_entry.get("signature_verified") is True:
                            continue
                        reason = image_entry.get("signature_error") or "signature not verified"
                        failures.append(f"{service_name}: {reason}")

            if failures:
                summary = "; ".join(failures[:5])
                if len(failures) > 5:
                    summary += f"; ... (+{len(failures) - 5} more)"
                message = (
                    "Image signature verification failed: "
                    f"{summary} (mode={mode}, app={found_version.app_name}@{found_version.version})"
                )
                if mode == "strict":
                    app_version_store.update_status(
                        request.version_id,
                        status="failed",
                        attestation=request.measurement,
                        rejection_reason=message,
                    )
                    logger.warning(message)
                    return {"status": "ok"}
                logger.warning(message)

        measured_mrtd = None
        if isinstance(request.measurement, dict):
            measured_mrtd = request.measurement.get("mrtd")
        app_version_store.update_status(
            request.version_id,
            status="attested",
            mrtd=measured_mrtd,
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


def _normalize_datacenters(values: list[str]) -> set[str]:
    return {value.strip().lower() for value in values if isinstance(value, str) and value.strip()}


def _normalize_clouds(values: list[str]) -> set[str]:
    normalized: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        cloud = value.strip().lower()
        if not cloud:
            continue
        if cloud in ("google", "gcp"):
            normalized.add("gcp")
            continue
        if cloud in ("azure", "az"):
            normalized.add("azure")
            continue
        if cloud in ("bare-metal", "baremetal", "onprem", "on-prem", "self-hosted"):
            normalized.add("baremetal")
            continue
        normalized.add(cloud)
    return normalized


def _extract_cloud(datacenter: str | None) -> str:
    value = (datacenter or "").strip().lower()
    if not value:
        return ""
    prefix = value.split(":", 1)[0].strip()
    return next(iter(_normalize_clouds([prefix])), "")


def _extract_availability_zone(datacenter: str | None) -> str:
    value = (datacenter or "").strip().lower()
    if ":" not in value:
        return ""
    return value.split(":", 1)[1].strip()


def _extract_region_from_zone(zone: str | None) -> str:
    value = (zone or "").strip().lower()
    if not value:
        return ""
    parts = [p for p in value.split("-") if p]
    if len(parts) >= 2:
        last = parts[-1]
        if last.isdigit() or (len(last) == 1 and last.isalpha()):
            return "-".join(parts[:-1])
    return value


def _extract_external_resource_items(payload: dict) -> list[dict]:
    if not isinstance(payload, dict):
        return []
    for key in ("resources", "items", "instances", "vms"):
        maybe_items = payload.get(key)
        if isinstance(maybe_items, list):
            return [item for item in maybe_items if isinstance(item, dict)]
    return []


def _normalize_inventory_detail(payload: dict, status_code: int | None) -> str | None:
    if not isinstance(payload, dict):
        return None
    detail = payload.get("detail") or payload.get("message")
    if isinstance(detail, str) and detail.strip():
        return detail.strip()
    if status_code is not None:
        return f"Inventory webhook returned HTTP {status_code}"
    return None


def _extract_cleanup_requested_count(payload: dict) -> int:
    if not isinstance(payload, dict):
        return 0
    for key in (
        "requested_count",
        "target_count",
        "candidate_count",
        "orphaned_count",
        "deleted_count",
        "resources_count",
    ):
        value = payload.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return max(0, value)
        if isinstance(value, str):
            try:
                parsed = int(value.strip())
            except ValueError:
                continue
            return max(0, parsed)
    return 0


async def _cloudflare_delete_many(
    *,
    ids: list[str],
    delete_fn,
    concurrency: int = 8,
) -> dict[str, object]:
    """Delete many Cloudflare resources with bounded concurrency."""
    if not ids:
        return {"deleted": 0, "failed": 0, "deleted_ids": []}

    semaphore = asyncio.Semaphore(max(1, concurrency))
    deleted_ids: list[str] = []

    async def _delete_one(resource_id: str) -> bool:
        async with semaphore:
            try:
                return bool(await delete_fn(resource_id))
            except Exception as exc:
                logger.warning(f"Cloudflare cleanup delete failed for {resource_id}: {exc}")
                return False

    results = await asyncio.gather(*[_delete_one(resource_id) for resource_id in ids])
    deleted = 0
    for resource_id, result in zip(ids, results, strict=True):
        if result:
            deleted += 1
            deleted_ids.append(resource_id)

    return {"deleted": deleted, "failed": len(ids) - deleted, "deleted_ids": deleted_ids}


def _deploy_issue(
    code: str,
    message: str,
    *,
    agent: Agent | None = None,
    node_size: str | None = None,
    datacenter: str | None = None,
) -> DeploymentPreflightIssue:
    resolved_node_size = node_size
    if resolved_node_size is None and agent:
        resolved_node_size = agent.node_size or ""
    resolved_datacenter = datacenter
    if resolved_datacenter is None and agent:
        resolved_datacenter = agent.datacenter or ""
    return DeploymentPreflightIssue(
        code=code,
        message=message,
        agent_id=agent.agent_id if agent else None,
        node_size=resolved_node_size or None,
        datacenter=resolved_datacenter or None,
    )


def _measurement_error(
    app_name: str,
    app_version: str,
    version_obj: AppVersion,
    target_agent: Agent,
) -> tuple[str, str] | None:
    target_node_size = target_agent.node_size or ""
    measurement = version_obj.attestation if isinstance(version_obj.attestation, dict) else None

    if version_obj.node_size and not measurement:
        return (
            "MISSING_MEASUREMENT_PAYLOAD",
            (
                f"Version '{version_obj.version}' for node_size='{version_obj.node_size}' is "
                "attested but missing measurement payload"
            ),
        )

    if not measurement:
        return None

    measured_node_size = measurement.get("node_size")
    if measured_node_size and measured_node_size != target_node_size:
        return (
            "MEASUREMENT_NODE_SIZE_MISMATCH",
            (
                f"Measurement node_size mismatch for '{app_name}@{app_version}': "
                f"attested '{measured_node_size}', target agent '{target_node_size}'"
            ),
        )

    if measurement.get("measurement_type") == "agent_reference":
        if not version_obj.mrtd:
            return (
                "MEASUREMENT_AGENT_REFERENCE_MISSING_MRTD",
                (
                    f"Version '{version_obj.version}' was attested with measurement_type="
                    "'agent_reference' but has no MRTD recorded"
                ),
            )
        if not measured_node_size:
            return (
                "MEASUREMENT_AGENT_REFERENCE_MISSING_NODE_SIZE",
                (
                    f"Version '{version_obj.version}' uses measurement_type='agent_reference' "
                    "but attestation.node_size is missing"
                ),
            )
        if target_agent.mrtd and version_obj.mrtd != target_agent.mrtd:
            return (
                "MEASUREMENT_MRTD_MISMATCH",
                (
                    f"Measurement MRTD mismatch for '{app_name}@{app_version}': "
                    f"version MRTD {version_obj.mrtd[:16]}..., "
                    f"agent MRTD {target_agent.mrtd[:16]}..."
                ),
            )
    return None


def _version_error(version_obj: AppVersion) -> tuple[str, str] | None:
    if version_obj.status == "attested":
        return None
    if version_obj.status == "rejected":
        return (
            "VERSION_REJECTED",
            f"Version '{version_obj.version}' was rejected: {version_obj.rejection_reason}",
        )
    return (
        "VERSION_NOT_ATTESTED",
        f"Version '{version_obj.version}' is not attested (status: {version_obj.status})",
    )


def _evaluate_deploy_request(
    app_name: str, app_version: str, request: DeployFromVersionRequest
) -> dict[str, object]:
    issues: list[DeploymentPreflightIssue] = []
    selected_agent: Agent | None = None
    selected_version: AppVersion | None = None

    def fail(
        status_code: int, detail: str, *, code: str, agent: Agent | None = None
    ) -> dict[str, object]:
        issues.append(_deploy_issue(code, detail, agent=agent))
        return {
            "selected_agent": selected_agent,
            "selected_version": selected_version,
            "issues": issues,
            "error_status": status_code,
            "error_detail": detail,
        }

    found_app = app_store.get_by_name(app_name)
    if found_app is None:
        return fail(404, f"App '{app_name}' not found", code="APP_NOT_FOUND")

    allowed_datacenters = _normalize_datacenters(request.allowed_datacenters)
    denied_datacenters = _normalize_datacenters(request.denied_datacenters)
    if allowed_datacenters.intersection(denied_datacenters):
        return fail(
            400,
            "Datacenter policy conflict: same datacenter appears in both allowed and denied lists",
            code="DATACENTER_POLICY_CONFLICT",
        )
    allowed_clouds = _normalize_clouds(request.allowed_clouds)
    denied_clouds = _normalize_clouds(request.denied_clouds)
    if allowed_clouds.intersection(denied_clouds):
        return fail(
            400,
            "Cloud policy conflict: same cloud appears in both allowed and denied lists",
            code="CLOUD_POLICY_CONFLICT",
        )

    if request.account_id:
        balance = account_store.get_balance(request.account_id)
        hourly_cost = calculate_deployment_cost_per_hour(
            request.cpu_vcpus,
            request.memory_gb,
            request.gpu_count,
            request.sla_class,
            request.machine_size,
        )
        if balance < hourly_cost:
            return fail(
                402,
                f"Insufficient funds: balance ${balance:.2f} < hourly cost ${hourly_cost:.2f}",
                code="INSUFFICIENT_FUNDS",
            )
        logger.info(f"Prepaid check passed: balance=${balance:.2f}, hourly_cost=${hourly_cost:.2f}")

    if request.agent_id:
        agent = agent_store.get(request.agent_id)
        if agent is None:
            return fail(404, "Agent not found", code="AGENT_NOT_FOUND")

        agent_datacenter = (agent.datacenter or "").strip().lower()
        agent_cloud = _extract_cloud(agent.datacenter)
        if allowed_datacenters and agent_datacenter not in allowed_datacenters:
            return fail(
                400,
                (
                    f"Agent datacenter '{agent.datacenter or 'unknown'}' is not in allowed_datacenters"
                ),
                code="AGENT_DATACENTER_NOT_ALLOWED",
                agent=agent,
            )
        if denied_datacenters and agent_datacenter in denied_datacenters:
            return fail(
                400,
                f"Agent datacenter '{agent.datacenter}' is denied by deployment policy",
                code="AGENT_DATACENTER_DENIED",
                agent=agent,
            )
        if allowed_clouds and agent_cloud not in allowed_clouds:
            return fail(
                400,
                f"Agent cloud '{agent_cloud or 'unknown'}' is not in allowed_clouds",
                code="AGENT_CLOUD_NOT_ALLOWED",
                agent=agent,
            )
        if denied_clouds and agent_cloud in denied_clouds:
            return fail(
                400,
                f"Agent cloud '{agent_cloud}' is denied by deployment policy",
                code="AGENT_CLOUD_DENIED",
                agent=agent,
            )

        is_upgrade = agent.deployed_app == app_name and agent.status == "deployed"
        if not is_upgrade:
            return fail(
                400,
                (
                    "Explicit agent assignment is only allowed for upgrades to the app currently "
                    "running on that agent"
                ),
                code="EXPLICIT_AGENT_NOT_ALLOWED",
                agent=agent,
            )
        selected_agent = agent
    else:
        candidates = []
        for agent in agent_store.list():
            agent_datacenter = (agent.datacenter or "").strip().lower()
            agent_cloud = _extract_cloud(agent.datacenter)
            if not agent.verified:
                issues.append(
                    _deploy_issue("AGENT_NOT_VERIFIED", "Agent is not verified", agent=agent)
                )
                continue
            if not agent.hostname:
                issues.append(
                    _deploy_issue("AGENT_NO_HOSTNAME", "Agent has no hostname", agent=agent)
                )
                continue
            if agent.health_status != "healthy":
                issues.append(_deploy_issue("AGENT_UNHEALTHY", "Agent is not healthy", agent=agent))
                continue
            if agent.status not in ("undeployed", "deployed"):
                issues.append(
                    _deploy_issue(
                        "AGENT_STATUS_NOT_DEPLOYABLE",
                        f"Agent status '{agent.status}' is not deployable",
                        agent=agent,
                    )
                )
                continue
            if request.node_size and (agent.node_size or "") != request.node_size:
                issues.append(
                    _deploy_issue(
                        "AGENT_NODE_SIZE_MISMATCH",
                        (
                            f"Agent node_size '{agent.node_size or ''}' does not match requested "
                            f"'{request.node_size}'"
                        ),
                        agent=agent,
                    )
                )
                continue
            if allowed_datacenters and agent_datacenter not in allowed_datacenters:
                issues.append(
                    _deploy_issue(
                        "AGENT_DATACENTER_NOT_ALLOWED",
                        (
                            f"Agent datacenter '{agent.datacenter or 'unknown'}' is not in "
                            "allowed_datacenters"
                        ),
                        agent=agent,
                    )
                )
                continue
            if denied_datacenters and agent_datacenter in denied_datacenters:
                issues.append(
                    _deploy_issue(
                        "AGENT_DATACENTER_DENIED",
                        f"Agent datacenter '{agent.datacenter}' is denied by deployment policy",
                        agent=agent,
                    )
                )
                continue
            if allowed_clouds and agent_cloud not in allowed_clouds:
                issues.append(
                    _deploy_issue(
                        "AGENT_CLOUD_NOT_ALLOWED",
                        f"Agent cloud '{agent_cloud or 'unknown'}' is not in allowed_clouds",
                        agent=agent,
                    )
                )
                continue
            if denied_clouds and agent_cloud in denied_clouds:
                issues.append(
                    _deploy_issue(
                        "AGENT_CLOUD_DENIED",
                        f"Agent cloud '{agent_cloud}' is denied by deployment policy",
                        agent=agent,
                    )
                )
                continue
            if not request.allow_measuring_enclave_fallback and (
                agent.deployed_app or ""
            ).startswith("measuring-enclave"):
                issues.append(
                    _deploy_issue(
                        "MEASURER_FALLBACK_DISABLED",
                        "Agent is reserved for measuring-enclave and fallback is disabled",
                        agent=agent,
                    )
                )
                continue
            candidates.append(agent)

        candidates.sort(key=lambda a: 0 if a.status == "undeployed" else 1)

        for agent in candidates:
            candidate_node_size = agent.node_size or ""
            version_obj = app_version_store.get_by_version(
                app_name, app_version, candidate_node_size
            )
            if version_obj is None:
                issues.append(
                    _deploy_issue(
                        "VERSION_VARIANT_NOT_FOUND",
                        (
                            f"No version variant for node_size='{candidate_node_size}' "
                            f"on agent {agent.agent_id}"
                        ),
                        agent=agent,
                    )
                )
                continue

            version_error = _version_error(version_obj)
            if version_error:
                code, message = version_error
                issues.append(_deploy_issue(code, message, agent=agent))
                continue

            measurement_error = _measurement_error(app_name, app_version, version_obj, agent)
            if measurement_error:
                code, message = measurement_error
                issues.append(_deploy_issue(code, message, agent=agent))
                continue

            selected_agent = agent
            selected_version = version_obj
            break

        if selected_agent is None:
            summary = "No eligible agents available for deployment"
            if issues:
                summary += f". Last reason: {issues[-1].message}"
            issues.append(_deploy_issue("NO_ELIGIBLE_AGENTS", summary))
            return {
                "selected_agent": None,
                "selected_version": None,
                "issues": issues,
                "error_status": 503,
                "error_detail": summary,
            }

    assert selected_agent is not None
    agent_node_size = selected_agent.node_size or ""
    if request.node_size and request.node_size != agent_node_size:
        return fail(
            400,
            (
                f"Requested node_size '{request.node_size}' does not match selected agent node_size "
                f"'{agent_node_size}'"
            ),
            code="REQUEST_NODE_SIZE_MISMATCH",
            agent=selected_agent,
        )

    if not selected_agent.verified:
        return fail(
            403,
            f"Agent not verified: {selected_agent.verification_error or 'attestation not completed'}",
            code="AGENT_NOT_VERIFIED",
            agent=selected_agent,
        )

    if not selected_agent.hostname:
        return fail(
            400,
            "Agent does not have a tunnel hostname - cannot push deployment",
            code="AGENT_NO_HOSTNAME",
            agent=selected_agent,
        )

    if selected_agent.status not in ("undeployed", "deployed"):
        return fail(
            400,
            f"Agent is not available (status: {selected_agent.status})",
            code="AGENT_STATUS_NOT_DEPLOYABLE",
            agent=selected_agent,
        )

    if selected_version is None:
        selected_version = app_version_store.get_by_version(app_name, app_version, agent_node_size)
    if selected_version is None:
        return fail(
            404,
            (
                f"No attested version '{app_version}' for app '{app_name}' "
                f"with node_size='{agent_node_size}'"
            ),
            code="VERSION_VARIANT_NOT_FOUND",
            agent=selected_agent,
        )

    version_error = _version_error(selected_version)
    if version_error:
        code, message = version_error
        return fail(400, message, code=code, agent=selected_agent)

    measurement_error = _measurement_error(app_name, app_version, selected_version, selected_agent)
    if measurement_error:
        code, message = measurement_error
        return fail(400, message, code=code, agent=selected_agent)

    return {
        "selected_agent": selected_agent,
        "selected_version": selected_version,
        "issues": issues,
        "error_status": None,
        "error_detail": None,
    }


def _build_preflight_response(result: dict[str, object]) -> DeploymentPreflightResponse:
    selected_agent = (
        result["selected_agent"] if isinstance(result["selected_agent"], Agent) else None
    )
    return DeploymentPreflightResponse(
        dry_run=True,
        eligible=result["error_status"] is None,
        selected_agent_id=selected_agent.agent_id if selected_agent else None,
        selected_node_size=(selected_agent.node_size or None) if selected_agent else None,
        selected_datacenter=(selected_agent.datacenter or None) if selected_agent else None,
        selected_cloud=_extract_cloud(selected_agent.datacenter) or None
        if selected_agent
        else None,
        issues=result["issues"],
    )


@app.post(
    "/api/v1/apps/{name}/versions/{version}/deploy/preflight",
    response_model=DeploymentPreflightResponse,
)
async def preflight_deploy_app_version(name: str, version: str, request: DeployFromVersionRequest):
    """Dry-run deployment validation with structured placement/measurement issues."""
    result = _evaluate_deploy_request(name, version, request)
    return _build_preflight_response(result)


@app.post(
    "/api/v1/apps/{name}/versions/{version}/deploy",
    response_model=DeploymentCreateResponse | DeploymentPreflightResponse,
)
async def deploy_app_version(name: str, version: str, request: DeployFromVersionRequest):
    """Deploy a published app version to an agent.

    Set `dry_run=true` to run preflight validation only.
    """
    result = _evaluate_deploy_request(name, version, request)
    if request.dry_run:
        return _build_preflight_response(result)

    error_status = result["error_status"]
    error_detail = result["error_detail"]
    if error_status is not None:
        raise HTTPException(status_code=error_status, detail=error_detail)

    selected_agent = result["selected_agent"]
    selected_version = result["selected_version"]
    assert isinstance(selected_agent, Agent)
    assert isinstance(selected_version, AppVersion)

    config = request.config or {}
    if "service_name" not in config:
        config["service_name"] = name

    deployment = Deployment(
        compose=selected_version.compose,
        config=config,
        agent_id=selected_agent.agent_id,
        status="pushing",
        account_id=request.account_id,
        app_name=name,
        app_version=version,
        sla_class=request.sla_class,
        machine_size=request.machine_size,
        cpu_vcpus=request.cpu_vcpus,
        memory_gb=request.memory_gb,
        gpu_count=request.gpu_count,
    )
    deployment_id = deployment_store.create(deployment)
    logger.info(
        f"Deployment created: {deployment_id} ({name}@{version} -> {selected_agent.agent_id})"
    )

    if request.github_owner:
        agent_store.set_github_owner(selected_agent.agent_id, request.github_owner)

    if selected_version.ingress and selected_agent.tunnel_id and cloudflare.is_configured():
        logger.info(f"Updating tunnel ingress for agent {selected_agent.agent_id}")
        await cloudflare.update_tunnel_ingress(
            selected_agent.tunnel_id,
            selected_agent.hostname,
            selected_version.ingress,
        )

    try:
        agent_url = f"https://{selected_agent.hostname}/api/deploy"
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                agent_url,
                json={
                    "deployment_id": deployment_id,
                    "app_name": name,
                    "datacenter": selected_agent.datacenter,
                    "compose": selected_version.compose,
                    "build_context": getattr(selected_version, "build_context", None),
                    "config": config,
                },
            )

            if response.status_code == 202:
                deployment_store.update_status(deployment_id, "deploying")
                agent_store.update_status(selected_agent.agent_id, "deploying", deployment_id)
                agent_store.set_deployed_app(selected_agent.agent_id, name)
                logger.info(f"Deployment {deployment_id} pushed to agent {selected_agent.agent_id}")
                return DeploymentCreateResponse(
                    deployment_id=deployment_id,
                    agent_id=selected_agent.agent_id,
                    status="deploying",
                )

            error_detail = response.text
            deployment_store.complete(deployment_id, status="failed", error=error_detail)
            logger.error(f"Agent rejected deployment: {error_detail}")
            raise HTTPException(
                status_code=502,
                detail=f"Agent rejected deployment: {error_detail}",
            )
    except httpx.RequestError as e:
        deployment_store.complete(deployment_id, status="failed", error=str(e))
        logger.error(f"Failed to reach agent: {e}")
        raise HTTPException(
            status_code=502,
            detail=f"Failed to reach agent at {selected_agent.hostname}: {e}",
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
        "timestamp": datetime.now(timezone.utc).isoformat(),
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


@app.get("/api/v1/logs/export")
async def export_logs(
    since: str = Query("1h", description="Container logs since (e.g., '5m', '1h')"),
    min_level: str = Query("DEBUG", description="Min level for control-plane logs"),
):
    """Export control plane + container logs as a zip file."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Control-plane logs from in-memory buffer
        level_num = getattr(logging, min_level.upper(), logging.DEBUG)
        filtered = [
            rec for rec in _log_handler.records if getattr(logging, rec["level"], 0) >= level_num
        ]
        cp_lines = [
            f"{rec['timestamp']} {rec['level']:7s} [{rec['logger']}] {rec['message']}"
            for rec in filtered
        ]
        zf.writestr("control-plane.log", "\n".join(cp_lines))

        # Container logs via docker CLI
        container_lines: list[str] = []
        import shutil

        if shutil.which("docker"):
            try:
                ps_proc = await asyncio.create_subprocess_exec(
                    "docker",
                    "ps",
                    "--format",
                    "{{.Names}}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                ps_stdout, _ = await asyncio.wait_for(ps_proc.communicate(), timeout=10)
                container_names = [n for n in ps_stdout.decode().strip().split("\n") if n]

                for name in container_names:
                    try:
                        log_proc = await asyncio.create_subprocess_exec(
                            "docker",
                            "logs",
                            "--since",
                            since,
                            name,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.STDOUT,
                        )
                        log_stdout, _ = await asyncio.wait_for(log_proc.communicate(), timeout=10)
                        for line in log_stdout.decode(errors="replace").strip().split("\n"):
                            if line:
                                container_lines.append(f"[{name}] {line}")
                    except (asyncio.TimeoutError, OSError):
                        container_lines.append(f"[{name}] [error fetching logs]")
            except (asyncio.TimeoutError, OSError):
                container_lines.append("[error] failed to list containers")
        else:
            container_lines.append("[info] docker CLI not available")

        zf.writestr("containers.log", "\n".join(container_lines))

    buf.seek(0)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="easyenclave-logs-{ts}.zip"'},
    )


# ==============================================================================
# Admin Authentication and Dashboard
# ==============================================================================


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
