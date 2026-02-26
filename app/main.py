"""EasyEnclave Discovery Service - FastAPI Application."""

from __future__ import annotations

import asyncio
import base64
import collections
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import urllib.parse
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from . import cloudflare
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
    verify_launcher_api_key,
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
    Agent,
    AgentCapacityDispatchResult,
    AgentCapacityReconcileRequest,
    AgentCapacityReconcileResponse,
    AgentCapacityTarget,
    AgentCapacityTargetResult,
    AgentChallengeResponse,
    AgentConsoleAccessResponse,
    AgentDeployedRequest,
    AgentHeartbeatRequest,
    AgentListResponse,
    AgentRegistrationRequest,
    AgentRegistrationResponse,
    AgentStatusRequest,
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
    CapacityLaunchOrderClaimRequest,
    CapacityLaunchOrderClaimResponse,
    CapacityLaunchOrderListResponse,
    CapacityLaunchOrderUpdateRequest,
    CapacityLaunchOrderView,
    CapacityPoolTargetListResponse,
    CapacityPoolTargetUpsertRequest,
    CapacityPoolTargetView,
    CapacityReservationListResponse,
    CapacityReservationView,
    CloudResourceAgent,
    CloudResourceCloudSummary,
    CloudResourceInventoryResponse,
    DeployFromVersionRequest,
    Deployment,
    DeploymentCreateResponse,
    DeploymentListResponse,
    DeploymentPreflightIssue,
    DeploymentPreflightResponse,
    ExternalCloudInventoryResponse,
    ExternalCloudResource,
    HealthResponse,
    ManualAttestRequest,
    MeasurementCallbackRequest,
    SetAgentOwnerRequest,
)
from .oauth import is_github_oauth_configured
from .pricing import calculate_deployment_cost_per_hour
from .provisioner import (
    dispatch_external_cleanup,
    fetch_external_inventory,
)
from .routes_admin_cloud import register_admin_cloud_routes
from .routes_auth_billing import register_auth_billing_routes
from .routes_misc import register_misc_routes
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
    agent_control_credential_store,
    agent_store,
    app_revenue_share_store,
    app_store,
    app_version_store,
    capacity_launch_order_store,
    capacity_pool_target_store,
    capacity_reservation_store,
    deployment_store,
    list_trusted_mrtds,
    load_trusted_mrtds,
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

# Agent health check settings
AGENT_HEALTH_CHECK_INTERVAL = 30  # Check agents every 30 seconds
AGENT_UNHEALTHY_TIMEOUT = timedelta(minutes=5)  # Reassign after 5 minutes unhealthy
AGENT_STALE_CLEANUP_INTERVAL = 3600  # Run cleanup every hour
CAPACITY_RECONCILE_DEFAULT_INTERVAL = 30

# Track when agents were last attested (for periodic re-attestation)
_agent_last_attestation: dict[str, datetime] = {}
_NODE_SIZE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_DATACENTER_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}:[a-z0-9][a-z0-9._-]{0,95}$")
_PRODUCTION_ENV_NAMES = {"prod", "production"}
_cp_attestation_capability: bool | None = None


def _mint_agent_api_secret() -> str:
    """Mint a per-agent shared secret for CP<->agent control APIs."""
    return secrets.token_urlsafe(48)


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _cp_to_agent_attestation_mode() -> str:
    mode = (get_setting("operational.cp_to_agent_attestation_mode") or "").strip().lower()
    if mode in {"required", "optional", "disabled"}:
        return mode
    return "optional"


def _cp_can_generate_attestation_quote() -> bool:
    """Return whether this control plane can mint TDX quotes."""
    global _cp_attestation_capability
    if _cp_attestation_capability is not None:
        return _cp_attestation_capability

    probe = generate_tdx_quote(nonce="easyenclave-cp-probe")
    _cp_attestation_capability = bool(probe.quote_b64 and not probe.error)
    if not _cp_attestation_capability:
        logger.warning(
            "CP->agent attestation unavailable on this control plane (%s)",
            probe.error or "no quote available",
        )
    return _cp_attestation_capability


async def _build_cp_attestation_headers(
    client: httpx.AsyncClient,
    *,
    hostname: str,
    agent_api_secret: str | None,
) -> dict[str, str]:
    """Build control-plane attestation headers for CP->agent control requests."""
    mode = _cp_to_agent_attestation_mode()
    if mode == "disabled":
        return {}

    if not _cp_can_generate_attestation_quote():
        if mode == "optional":
            return {}
        raise HTTPException(
            status_code=503,
            detail="CP->agent attestation required but control plane cannot mint TDX quotes",
        )

    challenge_headers: dict[str, str] = {}
    if agent_api_secret:
        challenge_headers["X-Agent-Secret"] = agent_api_secret

    challenge_url = f"https://{hostname}/api/control/challenge"
    try:
        challenge_response = await client.get(challenge_url, headers=challenge_headers)
    except httpx.RequestError as exc:
        if mode == "optional":
            logger.warning("Skipping CP->agent attestation challenge for %s: %s", hostname, exc)
            return {}
        raise HTTPException(
            status_code=502,
            detail=f"Failed CP->agent attestation challenge for {hostname}: {exc}",
        ) from exc

    if challenge_response.status_code >= 400:
        detail = challenge_response.text[:240]
        if mode == "optional":
            logger.warning(
                "Skipping CP->agent attestation; challenge endpoint rejected request for %s: "
                "HTTP %s %s",
                hostname,
                challenge_response.status_code,
                detail,
            )
            return {}
        raise HTTPException(
            status_code=502,
            detail=(
                "CP->agent attestation challenge failed "
                f"(HTTP {challenge_response.status_code}): {detail}"
            ),
        )

    try:
        challenge = challenge_response.json()
    except ValueError as exc:
        if mode == "optional":
            logger.warning(
                "Skipping CP->agent attestation; invalid challenge JSON from %s",
                hostname,
            )
            return {}
        raise HTTPException(
            status_code=502, detail="Invalid CP->agent challenge response JSON"
        ) from exc

    nonce = str(challenge.get("nonce") or "").strip()
    if not nonce:
        if mode == "optional":
            logger.warning("Skipping CP->agent attestation; empty nonce from %s", hostname)
            return {}
        raise HTTPException(status_code=502, detail="CP->agent challenge did not include nonce")

    quote = generate_tdx_quote(nonce=nonce)
    if quote.error or not quote.quote_b64:
        if mode == "optional":
            logger.warning(
                "Skipping CP->agent attestation; failed to mint quote for %s: %s",
                hostname,
                quote.error or "unknown error",
            )
            return {}
        raise HTTPException(
            status_code=503,
            detail=f"Failed to mint CP attestation quote: {quote.error or 'unknown error'}",
        )

    envelope = {
        "nonce": nonce,
        "quote_b64": quote.quote_b64,
        "mrtd": (quote.measurements or {}).get("mrtd"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    encoded = _b64url_no_pad(json.dumps(envelope, separators=(",", ":")).encode("utf-8"))
    return {"X-CP-Attestation": encoded}


def _mint_agent_console_relay_token(
    *,
    agent_id: str,
    agent_api_secret: str,
    session: AdminSession,
    ttl_seconds: int,
) -> tuple[str, datetime]:
    ttl = max(60, min(3600, int(ttl_seconds)))
    issued_at = int(datetime.now(timezone.utc).timestamp())
    expires_at = issued_at + ttl

    payload = {
        "v": 1,
        "sub": "agent-admin",
        "agent_id": agent_id,
        "iat": issued_at,
        "exp": expires_at,
        "jti": secrets.token_urlsafe(12),
        "auth_method": session.auth_method or "unknown",
        "github_login": session.github_login or "",
        "github_orgs": session.github_orgs or [],
        "is_admin": is_admin_session(session),
    }
    payload_b64 = _b64url_no_pad(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    sig = hmac.new(agent_api_secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256)
    token = f"eea1.{payload_b64}.{_b64url_no_pad(sig.digest())}"
    return token, datetime.fromtimestamp(expires_at, timezone.utc)


def _mint_agent_console_access_response(
    *,
    agent: Agent,
    session: AdminSession,
    ttl_seconds: int,
) -> AgentConsoleAccessResponse:
    if not agent.hostname:
        raise HTTPException(status_code=400, detail="Agent has no tunnel hostname")

    agent_api_secret = agent_control_credential_store.get_secret(agent.agent_id)
    if not agent_api_secret:
        raise HTTPException(
            status_code=409,
            detail="Agent does not have a control credential; ask agent to re-register",
        )

    token, expires_at = _mint_agent_console_relay_token(
        agent_id=agent.agent_id,
        agent_api_secret=agent_api_secret,
        session=session,
        ttl_seconds=ttl_seconds,
    )
    console_url = f"https://{agent.hostname}/admin?token={urllib.parse.quote(token, safe='')}"
    return AgentConsoleAccessResponse(
        agent_id=agent.agent_id,
        hostname=agent.hostname,
        console_url=console_url,
        token=token,
        expires_at=expires_at.isoformat(),
        auth_mode="cp_relay",
    )


def _extract_bearer_token(authorization: str | None) -> str:
    auth = (authorization or "").strip()
    if not auth.lower().startswith("bearer "):
        return ""
    return auth[7:].strip()


def _require_agent_control_auth(agent_id: str, authorization: str | None) -> None:
    """Require bearer auth for agents with registered control credentials.

    Backward-compatibility: if an older agent has no credential record yet,
    allow the request and log a warning.
    """
    if not agent_control_credential_store.has_secret(agent_id):
        logger.warning(
            "Agent %s has no control credential record; allowing legacy unauthenticated request",
            agent_id,
        )
        return

    token = _extract_bearer_token(authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Missing agent Authorization bearer token")
    if not agent_control_credential_store.verify_secret(agent_id, token):
        raise HTTPException(status_code=401, detail="Invalid agent Authorization bearer token")


def _parse_bool_setting(raw: str, *, fallback: bool) -> bool:
    value = (raw or "").strip().lower()
    if not value:
        return fallback
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return fallback


def _is_production_environment() -> bool:
    env_name = (
        (os.environ.get("EASYENCLAVE_ENV") or os.environ.get("ENVIRONMENT") or "").strip().lower()
    )
    return env_name in _PRODUCTION_ENV_NAMES


def _password_login_allowed() -> bool:
    enabled = _parse_bool_setting(get_setting("auth.password_login_enabled"), fallback=True)
    if not enabled:
        return False
    if not _is_production_environment():
        return True
    allow_in_prod = _parse_bool_setting(
        get_setting("auth.allow_password_login_in_production"),
        fallback=False,
    )
    return allow_in_prod


def require_admin_session(session: AdminSession = Depends(verify_admin_token)) -> AdminSession:
    """Dependency that requires an authenticated *admin* session.

    Note: verify_admin_token only authenticates the session; admin privileges are enforced here.
    """
    if not is_admin_session(session):
        raise HTTPException(status_code=403, detail="Admin access required")
    return session


def _normalize_registration_node_size(raw_value: str) -> str:
    return (raw_value or "").strip().lower()


def _normalize_registration_datacenter(raw_value: str) -> str:
    value = (raw_value or "").strip().lower()
    if not value:
        return ""

    if ":" not in value:
        cloud_aliases = _normalize_clouds([value])
        if cloud_aliases:
            return f"{next(iter(cloud_aliases))}:default"
        return value

    cloud_raw, location_raw = value.split(":", 1)
    cloud_aliases = _normalize_clouds([cloud_raw])
    cloud = next(iter(cloud_aliases), cloud_raw)
    location = location_raw.strip()
    if not location:
        location = "default"
    return f"{cloud}:{location}"


def _capacity_unit_price_monthly_usd(node_size: str) -> float:
    normalized = (node_size or "").strip().lower()
    setting_keys = {
        "tiny": "billing.capacity_price_tiny_monthly_usd",
        "standard": "billing.capacity_price_standard_monthly_usd",
        "llm": "billing.capacity_price_llm_monthly_usd",
    }
    defaults = {
        "tiny": 25.0,
        "standard": 100.0,
        "llm": 500.0,
    }
    key = setting_keys.get(normalized, "billing.capacity_price_tiny_monthly_usd")
    default = defaults.get(normalized, defaults["tiny"])
    raw = get_setting(key).strip()
    try:
        value = float(raw) if raw else default
    except ValueError:
        value = default
    return max(0.0, value)


def _ensure_default_gcp_tiny_capacity_target() -> None:
    if not _parse_bool_setting(
        get_setting("operational.default_gcp_tiny_capacity_enabled"),
        fallback=False,
    ):
        return

    datacenter = _normalize_registration_datacenter(
        get_setting("operational.default_gcp_tiny_datacenter")
    )
    if not datacenter or not _DATACENTER_RE.fullmatch(datacenter):
        logger.warning(
            "Skipping default warm tiny capacity target due to invalid datacenter '%s'",
            datacenter,
        )
        return

    min_warm_count = max(
        0,
        get_setting_int("operational.default_gcp_tiny_capacity_count", fallback=0),
    )
    dispatch = _parse_bool_setting(
        get_setting("operational.default_gcp_tiny_capacity_dispatch"),
        fallback=False,
    )
    reason = "default-gcp-tiny-capacity"

    # Respect explicit user-managed target reasons and avoid overriding them.
    existing = next(
        (
            row
            for row in capacity_pool_target_store.list()
            if (row.datacenter or "").strip().lower() == datacenter and row.node_size == "tiny"
        ),
        None,
    )
    if existing and (existing.reason or "").strip().lower() not in {
        "",
        reason,
    }:
        return

    try:
        capacity_pool_target_store.upsert(
            datacenter=datacenter,
            node_size="tiny",
            min_warm_count=min_warm_count,
            enabled=True,
            require_verified=True,
            require_healthy=True,
            require_hostname=True,
            dispatch=dispatch,
            reason=reason,
        )
    except Exception as exc:
        logger.warning(f"Failed to ensure default warm tiny capacity target: {exc}")


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


async def _measure_pending_version_locally(version: AppVersion) -> None:
    """Measure a version inside the control plane and update status to attested/failed.

    This removes the need to deploy a separate "measuring-enclave" workload and pin capacity.
    """
    from .version_measurement import MeasurementError, measure_compose

    mode = get_setting("operational.signature_verification_mode").strip().lower()
    if mode not in {"strict", "warn", "disabled"}:
        logger.warning(f"Invalid SIGNATURE_VERIFICATION_MODE '{mode}', defaulting to 'warn'")
        mode = "warn"

    # Mark as in-progress (best effort). A periodic worker will also retry attesting
    # versions if the process restarts mid-measurement.
    app_version_store.update_status(version.version_id, status="attesting")

    try:
        measurement = await measure_compose(
            version.compose,
            node_size=version.node_size,
            signature_mode=mode,
        )
    except MeasurementError as exc:
        app_version_store.update_status(
            version.version_id,
            status="failed",
            rejection_reason=str(exc),
        )
        logger.warning(
            "Local measurement failed: %s@%s node_size='%s' (%s): %s",
            version.app_name,
            version.version,
            version.node_size,
            version.version_id,
            exc,
        )
        return
    except Exception as exc:
        app_version_store.update_status(
            version.version_id,
            status="failed",
            rejection_reason=str(exc),
        )
        logger.exception(
            "Local measurement crashed: %s@%s node_size='%s' (%s)",
            version.app_name,
            version.version,
            version.node_size,
            version.version_id,
        )
        return

    # Enforce signature verification policy (strict fails the version).
    if mode == "strict":
        failures: list[str] = []
        resolved_images = (
            measurement.get("resolved_images") if isinstance(measurement, dict) else None
        )
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
                f"{summary} (mode={mode}, app={version.app_name}@{version.version})"
            )
            app_version_store.update_status(
                version.version_id,
                status="failed",
                attestation=measurement,
                rejection_reason=message,
            )
            logger.warning(message)
            return

    app_version_store.update_status(
        version.version_id,
        status="attested",
        attestation=measurement,
    )
    logger.info(
        "Local measurement success: %s@%s node_size='%s' (%s)",
        version.app_name,
        version.version,
        version.node_size,
        version.version_id,
    )


async def background_measurement_processor():
    """Measure pending app versions.

    The control plane performs digest resolution and optional signature verification
    directly, so deployments don't need to keep a dedicated "measuring-enclave" node.
    """
    while True:
        try:
            candidates = app_version_store.list_by_status(
                "pending"
            ) + app_version_store.list_by_status("attesting")
            if candidates:
                for version in candidates:
                    # Idempotency guard: if something already wrote an attestation payload,
                    # don't overwrite it.
                    if isinstance(version.attestation, dict) and version.attestation:
                        continue
                    await _measure_pending_version_locally(version)
        except Exception as e:
            logger.error(f"Measurement processor error: {e}")
        await asyncio.sleep(MEASUREMENT_CHECK_INTERVAL)


def _get_proxy_url() -> str:
    """Get the proxy URL for service routing."""
    domain = get_setting("cloudflare.domain")
    env_name = (
        (os.environ.get("EASYENCLAVE_ENV") or os.environ.get("ENVIRONMENT") or "").strip().lower()
    )
    alias_label = "app-staging" if env_name == "staging" else "app"
    return f"https://{alias_label}.{domain}"


def validate_environment():
    """Validate environment configuration on startup."""
    warnings = []
    in_production = _is_production_environment()
    require_github_in_prod = _parse_bool_setting(
        get_setting("auth.require_github_oauth_in_production"),
        fallback=True,
    )

    # Admin authentication - enforce GitHub OAuth policy in production.
    github_oauth_ready = is_github_oauth_configured()
    if in_production and require_github_in_prod and not github_oauth_ready:
        raise RuntimeError(
            "Production mode requires GitHub OAuth. Configure "
            "GITHUB_OAUTH_CLIENT_ID, GITHUB_OAUTH_CLIENT_SECRET, and "
            "GITHUB_OAUTH_REDIRECT_URI."
        )

    # If GitHub OAuth is configured and an explicit admin allowlist exists, never auto-generate
    # a password. In that mode, OAuth is the intended admin access path.
    github_admin_allowlist = bool((os.environ.get("ADMIN_GITHUB_LOGINS") or "").strip())
    github_admin_mode = bool(github_oauth_ready and github_admin_allowlist)

    # Password admin login is optional. If no hash is configured, we allow an explicit plaintext
    # ADMIN_PASSWORD (hashed on startup) for CI/dev. We never auto-generate a password when GitHub
    # OAuth is configured and an admin allowlist exists.
    global _generated_admin_password
    if _password_login_allowed():
        if not os.environ.get("ADMIN_PASSWORD_HASH"):
            plaintext_pw = (os.environ.get("ADMIN_PASSWORD") or "").strip()
            if plaintext_pw:
                os.environ["ADMIN_PASSWORD_HASH"] = hash_password(plaintext_pw)
                logger.warning("ADMIN_PASSWORD_HASH not set — using hashed ADMIN_PASSWORD from env")
                _generated_admin_password = None
            elif not github_admin_mode:
                import secrets as _secrets

                generated_pw = _secrets.token_urlsafe(16)
                pw_hash = hash_password(generated_pw)
                os.environ["ADMIN_PASSWORD_HASH"] = pw_hash
                _generated_admin_password = generated_pw
                logger.warning("ADMIN_PASSWORD_HASH not set — auto-generated password")
            else:
                _generated_admin_password = None
    else:
        _generated_admin_password = None

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

    # Intel Trust Authority
    # The control plane only verifies Intel-signed tokens via JWKS (no API key required).
    # CP-native provisioning (e.g., GCP capacity fulfillment) may optionally inject an ITA API key into provisioned
    # agent VMs so they can mint tokens for registration.
    ita_agent_key = (
        os.environ.get("EE_AGENT_ITA_API_KEY")
        or os.environ.get("ITA_API_KEY")
        or os.environ.get("INTEL_API_KEY")
        or ""
    ).strip()
    if (
        os.environ.get("GCP_PROJECT_ID")
        and os.environ.get("GCP_SERVICE_ACCOUNT_KEY")
        and not ita_agent_key
    ):
        warnings.append(
            "EE_AGENT_ITA_API_KEY not set - CP-native GCP provisioning will create agent VMs that cannot register "
            "(agents must mint Intel Trust Authority tokens)."
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
                    capacity_reservation_store.expire_open_for_agent(agent.agent_id)
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

    # Ensure baseline warm-capacity policy exists before controllers start.
    _ensure_default_gcp_tiny_capacity_target()

    # Generate initial CP attestation
    _refresh_cp_attestation()

    # Start background tasks
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
    capacity_pool_task = asyncio.create_task(background_capacity_pool_controller())
    capacity_fulfill_task = asyncio.create_task(background_capacity_launch_order_fulfiller())

    logger.info(
        "Started background tasks (measurement processor, billing, session cleanup, nonce cleanup, stale agent cleanup, capacity pool)"
    )
    yield
    # Shutdown
    agent_health_task.cancel()
    attestation_task.cancel()
    measurement_task.cancel()
    charging_task.cancel()
    terminator_task.cancel()
    session_cleanup_task.cancel()
    nonce_cleanup_task.cancel()
    stale_agent_task.cancel()
    capacity_pool_task.cancel()
    capacity_fulfill_task.cancel()
    for task in [
        agent_health_task,
        attestation_task,
        measurement_task,
        charging_task,
        terminator_task,
        session_cleanup_task,
        nonce_cleanup_task,
        stale_agent_task,
        capacity_pool_task,
        capacity_fulfill_task,
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
    boot_id = (os.environ.get("EASYENCLAVE_BOOT_ID") or "").strip() or None
    git_sha = (os.environ.get("EASYENCLAVE_GIT_SHA") or "").strip() or None
    gcp_project_configured = bool((os.environ.get("GCP_PROJECT_ID") or "").strip())
    gcp_service_account_key_configured = bool(
        (os.environ.get("GCP_SERVICE_ACCOUNT_KEY") or "").strip()
    )
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc),
        boot_id=boot_id,
        git_sha=git_sha,
        attestation=_cached_attestation,
        proxy_url=_get_proxy_url(),
        gcp_project_configured=gcp_project_configured,
        gcp_service_account_key_configured=gcp_service_account_key_configured,
        gcp_capacity_fulfiller_enabled=(
            gcp_project_configured and gcp_service_account_key_configured
        ),
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

    vm_name = (request.vm_name or "").strip()
    if not vm_name:
        raise HTTPException(status_code=400, detail="Registration requires vm_name")
    node_size = _normalize_registration_node_size(request.node_size)
    if not node_size:
        raise HTTPException(status_code=400, detail="Registration requires node_size")
    if not _NODE_SIZE_RE.fullmatch(node_size):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid node_size '{request.node_size}'. "
                "Expected lowercase token like tiny, standard, llm"
            ),
        )
    datacenter = _normalize_registration_datacenter(request.datacenter)
    if not datacenter:
        raise HTTPException(status_code=400, detail="Registration requires datacenter")
    if not _DATACENTER_RE.fullmatch(datacenter):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid datacenter '{request.datacenter}'. "
                "Expected '<cloud>:<zone>' (for example gcp:us-central1-a)"
            ),
        )

    # Check if agent with this vm_name already exists
    existing = agent_store.get_by_vm_name(vm_name)
    # If agent is in attestation_failed status, allow full re-registration with fresh attestation.
    if existing and existing.status == "attestation_failed":
        logger.info(f"Agent {existing.agent_id} re-registering after attestation failure")

    # Always verify attestation (Intel TA token + MRTD trusted list), including re-registration.
    try:
        verification = await verify_agent_registration(request.attestation, node_size=node_size)
    except AttestationError as e:
        # Special-case: if the agent MRTD is simply not trusted yet, record the baseline
        # so CI/admin can add it and the agent can keep retrying registration.
        if "MRTD not in trusted list" in (e.detail or ""):
            try:
                # Never downgrade an already-verified agent to "unverified" on a failed re-registration.
                if existing and existing.verified:
                    logger.warning(
                        "Rejected re-registration for verified agent "
                        f"{existing.agent_id} ({vm_name}) due to untrusted MRTD"
                    )
                else:
                    untrusted = await verify_agent_attestation_only(
                        request.attestation, node_size=node_size
                    )
                    rtmrs = extract_rtmrs(request.attestation)
                    dedupe_unverified = (
                        existing
                        or agent_store.get_recent_unverified_by_mrtd_datacenter(
                            mrtd=untrusted.mrtd,
                            datacenter=datacenter,
                            within=timedelta(hours=6),
                        )
                    )
                    agent_kwargs = {
                        "vm_name": vm_name,
                        "attestation": request.attestation,
                        "mrtd": untrusted.mrtd,
                        "rtmrs": rtmrs,
                        "intel_ta_token": untrusted.intel_ta_token,
                        "version": request.version,
                        "node_size": node_size,
                        "datacenter": datacenter,
                        "status": "unverified",
                        "verified": False,
                        "verification_error": e.detail,
                        "tcb_status": untrusted.tcb_status,
                        "tcb_verified_at": datetime.now(timezone.utc),
                    }
                    if dedupe_unverified:
                        agent_kwargs["agent_id"] = dedupe_unverified.agent_id
                    agent_store.register(Agent(**agent_kwargs))
                    logger.warning(
                        f"Recorded untrusted agent baseline: vm={vm_name} mrtd={untrusted.mrtd[:16]}..."
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
        nonce_verified, nonce_error = verify_nonce(vm_name, nonce_from_quote)
        if not nonce_verified:
            raise HTTPException(status_code=403, detail=f"Nonce verification failed: {nonce_error}")
        logger.info(f"Nonce verified for {vm_name}")
    elif nonce_mode == "required":
        raise HTTPException(
            status_code=400,
            detail="Nonce required. Call GET /api/v1/agents/challenge first",
        )
    elif nonce_mode == "optional":
        logger.warning(f"Agent {vm_name} registered without nonce (optional mode)")

    # Re-registration must preserve stable identity metadata for the vm_name.
    if existing and existing.verified and existing.status != "attestation_failed":
        if existing.mrtd and existing.mrtd != mrtd:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Re-registration rejected: MRTD changed for existing vm_name "
                    f"('{existing.mrtd[:16]}...' -> '{mrtd[:16]}...')"
                ),
            )
        existing_node_size = (existing.node_size or "").strip().lower()
        if existing_node_size and existing_node_size != node_size:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Re-registration rejected: node_size changed for existing vm_name "
                    f"('{existing.node_size}' -> '{node_size}')"
                ),
            )
        existing_datacenter = (existing.datacenter or "").strip().lower()
        if existing_datacenter and existing_datacenter != datacenter:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Re-registration rejected: datacenter changed for existing vm_name "
                    f"('{existing.datacenter}' -> '{datacenter}')"
                ),
            )

        # Verified existing agent with matching identity metadata.
        # Update heartbeat and return existing identity without reissuing tunnel token.
        agent_store.heartbeat(existing.agent_id)
        agent_api_secret = _mint_agent_api_secret()
        agent_control_credential_store.upsert_secret(existing.agent_id, agent_api_secret)
        logger.info(f"Agent re-registered after attestation check: {existing.agent_id} ({vm_name})")
        return AgentRegistrationResponse(
            agent_id=existing.agent_id,
            poll_interval=30,
            agent_api_secret=agent_api_secret,
            hostname=existing.hostname,
        )

    # Both Intel TA and MRTD verified - agent is trusted
    intel_ta_verified = True
    verified = True

    # Extract RTMRs from attestation (if available)
    rtmrs = extract_rtmrs(request.attestation)

    # Create agent record (reuse existing agent_id if recovering from attestation_failed)
    agent_kwargs = {
        "vm_name": vm_name,
        "attestation": request.attestation,
        "mrtd": mrtd,
        "rtmrs": rtmrs,
        "intel_ta_token": intel_ta_token,
        "version": request.version,
        "node_size": node_size,
        "datacenter": datacenter,
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
        f"Agent registered: {agent_id} ({vm_name}) verified={verified} intel_ta={intel_ta_verified}"
    )

    agent_api_secret = _mint_agent_api_secret()
    agent_control_credential_store.upsert_secret(agent_id, agent_api_secret)

    return AgentRegistrationResponse(
        agent_id=agent_id,
        poll_interval=30,
        agent_api_secret=agent_api_secret,
        tunnel_token=tunnel_token,
        hostname=hostname,
    )


@app.post("/api/v1/agents/{agent_id}/status")
async def update_agent_status(
    agent_id: str,
    request: AgentStatusRequest,
    authorization: str | None = Header(None),
):
    """Update agent status during deployment.

    Agents call this to report deployment progress.
    """
    get_or_404(agent_store, agent_id, "Agent")
    _require_agent_control_auth(agent_id, authorization)

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
async def agent_heartbeat(
    agent_id: str,
    request: AgentHeartbeatRequest,
    authorization: str | None = Header(None),
):
    """Receive an agent-pushed heartbeat with fresh attestation.

    This is the primary attestation refresh mechanism (agent-driven).
    Control plane may still do health pulls separately.
    """
    agent = get_or_404(agent_store, agent_id, "Agent")
    _require_agent_control_auth(agent_id, authorization)

    if (request.vm_name or "").strip() != (agent.vm_name or "").strip():
        raise HTTPException(status_code=400, detail="vm_name does not match agent record")

    intel_ta_token = (request.attestation.get("tdx") or {}).get("intel_ta_token")
    if not intel_ta_token:
        raise HTTPException(
            status_code=400,
            detail="attestation.tdx.intel_ta_token is required",
        )

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
async def agent_deployment_complete(
    agent_id: str,
    request: AgentDeployedRequest,
    authorization: str | None = Header(None),
):
    """Report successful deployment completion.

    Agents call this after successfully deploying a workload.
    """
    agent = get_or_404(agent_store, agent_id, "Agent")
    _require_agent_control_auth(agent_id, authorization)

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


def _normalize_pool_key(datacenter: str, node_size: str = "") -> tuple[str, str]:
    return ((datacenter or "").strip().lower(), (node_size or "").strip().lower())


def _agent_matches_capacity_target(
    agent: Agent,
    *,
    datacenter: str,
    node_size: str,
    require_verified: bool,
    require_healthy: bool,
    require_hostname: bool,
    allowed_statuses: set[str] | None = None,
) -> bool:
    agent_status = (agent.status or "").strip().lower()
    if allowed_statuses is not None and agent_status not in allowed_statuses:
        return False
    if require_verified and not agent.verified:
        return False
    if require_healthy and (agent.health_status or "").strip().lower() != "healthy":
        return False
    if require_hostname and not (agent.hostname or "").strip():
        return False
    if (agent.datacenter or "").strip().lower() != datacenter:
        return False
    if node_size and (agent.node_size or "").strip().lower() != node_size:
        return False
    return True


async def reconcile_capacity_targets_once() -> dict[str, int]:
    """Reconcile open warm-capacity reservations to configured pool targets."""
    capacity_launch_order_store.release_expired_claims()
    targets = capacity_pool_target_store.list(enabled_only=True)
    if not targets:
        return {"targets": 0, "created": 0, "expired": 0, "shortfall": 0, "dispatched": 0}

    agents = agent_store.list()
    totals = {"targets": len(targets), "created": 0, "expired": 0, "shortfall": 0, "dispatched": 0}
    for target in targets:
        target_datacenter, target_node_size = _normalize_pool_key(
            target.datacenter, target.node_size
        )
        if not target_datacenter:
            continue

        eligible_agents = [
            agent
            for agent in agents
            if _agent_matches_capacity_target(
                agent,
                datacenter=target_datacenter,
                node_size=target_node_size,
                require_verified=target.require_verified,
                require_healthy=target.require_healthy,
                require_hostname=target.require_hostname,
                allowed_statuses={"undeployed"},
            )
        ]
        eligible_agent_ids = {agent.agent_id for agent in eligible_agents}

        open_reservations = capacity_reservation_store.list_open_by_pool(
            target_datacenter, target_node_size
        )
        valid_open_agent_ids: list[str] = []
        for reservation in open_reservations:
            if (
                reservation.agent_id in eligible_agent_ids
                and reservation.agent_id not in valid_open_agent_ids
            ):
                valid_open_agent_ids.append(reservation.agent_id)

        keep_open_agent_ids = set(valid_open_agent_ids[: target.min_warm_count])
        totals["expired"] += capacity_reservation_store.expire_open_for_pool_except(
            datacenter=target_datacenter,
            node_size=target_node_size,
            keep_agent_ids=keep_open_agent_ids,
        )

        open_count = len(keep_open_agent_ids)
        if open_count < target.min_warm_count:
            for agent in eligible_agents:
                if open_count >= target.min_warm_count:
                    break
                if agent.agent_id in keep_open_agent_ids:
                    continue
                if capacity_reservation_store.has_open_for_agent(agent.agent_id):
                    continue
                capacity_reservation_store.create_open(
                    agent_id=agent.agent_id,
                    datacenter=target_datacenter,
                    node_size=target_node_size,
                    note=f"warm-capacity:{target_datacenter}:{target_node_size or 'default'}",
                )
                keep_open_agent_ids.add(agent.agent_id)
                totals["created"] += 1
                open_count += 1

        shortfall = max(0, target.min_warm_count - open_count)
        totals["shortfall"] += shortfall

        if shortfall <= 0 or not target.dispatch:
            continue

        reason = (target.reason or "").strip() or "capacity-pool-controller"
        known_vm_names = {
            (a.vm_name or "").strip().lower()
            for a in agents
            if (a.vm_name or "").strip()
            and (a.datacenter or "").strip().lower() == target_datacenter
            and (not target_node_size or (a.node_size or "").strip().lower() == target_node_size)
        }
        pending_fulfilled = capacity_launch_order_store.count_recent_fulfilled_without_agent(
            datacenter=target_datacenter,
            node_size=target_node_size,
            known_vm_names=known_vm_names,
            grace_seconds=get_setting_int(
                "operational.capacity_fulfilled_grace_seconds",
                fallback=1800,
            ),
        )
        dispatch_shortfall = max(0, shortfall - pending_fulfilled)
        created_orders = capacity_launch_order_store.create_missing_for_shortfall(
            datacenter=target_datacenter,
            node_size=target_node_size,
            shortfall=dispatch_shortfall,
            reason=reason,
        )
        totals["dispatched"] += len(created_orders)

    return totals


async def background_capacity_pool_controller():
    """Background controller that keeps warm-capacity reservations in sync with targets."""
    while True:
        interval_seconds = max(
            5,
            get_setting_int(
                "operational.capacity_reconcile_interval_seconds",
                fallback=CAPACITY_RECONCILE_DEFAULT_INTERVAL,
            ),
        )
        try:
            stats = await reconcile_capacity_targets_once()
            if stats["targets"] > 0:
                logger.info(
                    "Capacity reconcile: targets=%d created=%d expired=%d shortfall=%d dispatched=%d",
                    stats["targets"],
                    stats["created"],
                    stats["expired"],
                    stats["shortfall"],
                    stats["dispatched"],
                )
        except Exception as e:
            logger.error(f"Capacity pool reconcile error: {e}")
        await asyncio.sleep(interval_seconds)


def _utc_aware(dt: datetime | None) -> datetime:
    if dt is None:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_gcp_timestamp(value: str | None) -> datetime | None:
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        return datetime.fromisoformat(raw).astimezone(timezone.utc)
    except Exception:
        return None


def _sanitize_scope_label(value: str | None) -> str:
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    cleaned = re.sub(r"[^a-z0-9-_]", "-", raw)
    cleaned = re.sub(r"[-_]{2,}", "-", cleaned).strip("-_")
    return cleaned


async def reclaim_stale_fulfilled_gcp_orders(
    *,
    internal_launcher_id: str,
    delete_gcp_instance,
) -> int:
    """Delete stale fulfilled GCP VMs that never produced a usable agent."""
    now = datetime.now(timezone.utc)
    grace_seconds = max(
        300,
        get_setting_int("operational.capacity_fulfilled_grace_seconds", fallback=1800),
    )
    stale_agent_hours = max(
        1,
        get_setting_int("operational.agent_stale_hours", fallback=24),
    )
    stale_agent_timeout = timedelta(hours=stale_agent_hours)
    cutoff = now - timedelta(seconds=grace_seconds)

    active_deploy_statuses = {"pending", "deploying", "running", "in_progress", "reassigning"}
    active_agent_ids = {
        (d.agent_id or "").strip()
        for d in deployment_store.list()
        if (d.status or "").strip().lower() in active_deploy_statuses
    }
    agents_by_vm = {
        (a.vm_name or "").strip().lower(): a
        for a in agent_store.list()
        if (a.vm_name or "").strip()
    }

    reclaimed = 0
    for order in capacity_launch_order_store.list("fulfilled"):
        datacenter = (order.datacenter or "").strip().lower()
        if datacenter != "gcp" and not datacenter.startswith("gcp:"):
            continue

        claimed_by = (order.claimed_by_account_id or "").strip()
        if claimed_by and claimed_by != internal_launcher_id:
            continue

        vm_name = (order.vm_name or "").strip()
        if not vm_name:
            continue

        fulfilled_at = _utc_aware(order.fulfilled_at or order.updated_at or order.created_at)
        if fulfilled_at > cutoff:
            continue

        agent = agents_by_vm.get(vm_name.lower())
        if agent:
            if (agent.agent_id or "").strip() in active_agent_ids:
                continue
            heartbeat_ref = _utc_aware(
                agent.last_heartbeat or agent.last_health_check or agent.updated_at
            )
            if now - heartbeat_ref < stale_agent_timeout:
                continue

        try:
            deleted = await delete_gcp_instance(datacenter=datacenter, instance_name=vm_name)
        except Exception as exc:
            logger.warning(
                "Failed stale GCP reclaim for order=%s vm=%s: %s",
                order.order_id,
                vm_name,
                exc,
            )
            continue

        capacity_launch_order_store.update_status(
            order_id=order.order_id,
            launcher_account_id=internal_launcher_id,
            status="failed",
            error="stale fulfilled order reclaimed; vm deleted or missing",
        )

        if agent and (agent.agent_id or "").strip() not in active_agent_ids:
            agent_store.delete(agent.agent_id)

        logger.warning(
            "Reclaimed stale GCP capacity order=%s vm=%s deleted=%s",
            order.order_id,
            vm_name,
            deleted,
        )
        reclaimed += 1

    return reclaimed


async def reclaim_orphaned_managed_gcp_instances(
    *,
    delete_gcp_instance,
    list_managed_gcp_instances,
) -> int:
    """Delete stale CP-managed GCP instances that have no active agent signal.

    When both EASYENCLAVE_NETWORK_NAME and EASYENCLAVE_ENV are set, inventory
    broadens to all EasyEnclave-managed instances in the project and this reaper
    deletes stale orphaned instances from older networks in the same environment.
    This keeps one environment from accumulating stranded VMs across rollouts
    while preserving staging/production separation.
    """
    now = datetime.now(timezone.utc)
    grace_seconds = max(
        300,
        get_setting_int("operational.capacity_fulfilled_grace_seconds", fallback=1800),
    )
    stale_agent_hours = max(
        1,
        get_setting_int("operational.agent_stale_hours", fallback=24),
    )
    stale_agent_timeout = timedelta(hours=stale_agent_hours)
    cutoff = now - timedelta(seconds=grace_seconds)

    active_deploy_statuses = {"pending", "deploying", "running", "in_progress", "reassigning"}
    active_agent_ids = {
        (d.agent_id or "").strip()
        for d in deployment_store.list()
        if (d.status or "").strip().lower() in active_deploy_statuses
    }
    agents_by_vm = {
        (a.vm_name or "").strip().lower(): a
        for a in agent_store.list()
        if (a.vm_name or "").strip()
    }

    expected_network = _sanitize_scope_label(os.environ.get("EASYENCLAVE_NETWORK_NAME"))
    expected_env = _sanitize_scope_label(
        os.environ.get("EASYENCLAVE_ENV") or os.environ.get("ENVIRONMENT")
    )
    # If we can scope by both network + env labels, inventory all managed instances
    # and let this reaper clean same-env orphaned older networks.
    owned_only = not (expected_network and expected_env)
    try:
        try:
            instances = await list_managed_gcp_instances(owned_only=owned_only)
        except TypeError:
            instances = await list_managed_gcp_instances()
    except Exception as exc:
        logger.warning("Failed managed GCP instance inventory for orphan reap: %s", exc)
        return 0

    reclaimed = 0
    for inst in instances:
        vm_name = str(inst.get("name") or "").strip()
        if not vm_name or not vm_name.startswith("ee-"):
            continue
        datacenter = str(inst.get("datacenter") or "").strip().lower()
        if datacenter != "gcp" and not datacenter.startswith("gcp:"):
            continue

        labels = inst.get("labels") if isinstance(inst.get("labels"), dict) else {}
        inst_network = _sanitize_scope_label(str(labels.get("ee-network") or ""))
        inst_env = _sanitize_scope_label(str(labels.get("ee-env") or ""))

        # Never cross environments (staging/prod isolation).
        if expected_env and inst_env != expected_env:
            continue
        # In cross-network mode, require a labeled network and allow only
        # same-env networks that differ from the current network.
        cross_network = False
        if not owned_only:
            if not inst_network:
                continue
            cross_network = inst_network != expected_network

        created_at = _parse_gcp_timestamp(str(inst.get("creation_timestamp") or ""))
        if created_at and created_at > cutoff:
            continue

        agent = agents_by_vm.get(vm_name.lower())
        if agent:
            if (agent.agent_id or "").strip() in active_agent_ids:
                continue
            heartbeat_ref = _utc_aware(
                agent.last_heartbeat or agent.last_health_check or agent.updated_at
            )
            if now - heartbeat_ref < stale_agent_timeout:
                continue

        try:
            deleted = await delete_gcp_instance(datacenter=datacenter, instance_name=vm_name)
        except Exception as exc:
            logger.warning("Failed orphan GCP reclaim for vm=%s: %s", vm_name, exc)
            continue

        if agent and (agent.agent_id or "").strip() not in active_agent_ids:
            agent_store.delete(agent.agent_id)

        logger.warning(
            "Reclaimed orphan managed GCP instance vm=%s dc=%s network=%s deleted=%s reason=%s",
            vm_name,
            datacenter,
            inst_network or "unknown",
            deleted,
            (
                "orphan-network-no-agent"
                if cross_network and agent is None
                else "orphan-network-stale-agent"
                if cross_network
                else "no-agent"
                if agent is None
                else "stale-agent"
            ),
        )
        reclaimed += 1

    return reclaimed


async def background_capacity_launch_order_fulfiller():
    """CP-native capacity fulfiller (currently: GCP).

    If GCP credentials are configured on the control plane, this task will
    claim open GCP launch orders and provision instances directly via the
    Compute API (no external scripts, no gcloud).
    """
    from app.gcp_capacity import (
        GCPProvisionError,
        create_tdx_instance_for_order,
        delete_instance,
        list_managed_instances,
    )

    internal_launcher_id = "cp-internal-launcher"
    poll_seconds = 5
    warned_missing_gcp_creds = False
    last_reap_at = datetime.fromtimestamp(0, tz=timezone.utc)
    while True:
        try:
            # Avoid claiming and failing orders in a tight loop when the control plane
            # is not configured for GCP provisioning (common in local/CI environments).
            if not os.environ.get("GCP_PROJECT_ID") or not os.environ.get(
                "GCP_SERVICE_ACCOUNT_KEY"
            ):
                if not warned_missing_gcp_creds:
                    warned_missing_gcp_creds = True
                    logger.info(
                        "GCP credentials not configured (missing GCP_PROJECT_ID/GCP_SERVICE_ACCOUNT_KEY); "
                        "skipping CP-native GCP capacity fulfillment"
                    )
                await asyncio.sleep(poll_seconds)
                continue

            reap_interval = max(
                30,
                get_setting_int("operational.gcp_stale_reap_interval_seconds", fallback=60),
            )
            now = datetime.now(timezone.utc)
            if (now - last_reap_at).total_seconds() >= reap_interval:
                reclaimed = await reclaim_stale_fulfilled_gcp_orders(
                    internal_launcher_id=internal_launcher_id,
                    delete_gcp_instance=delete_instance,
                )
                orphan_reclaimed = await reclaim_orphaned_managed_gcp_instances(
                    delete_gcp_instance=delete_instance,
                    list_managed_gcp_instances=list_managed_instances,
                )
                if reclaimed > 0:
                    logger.warning(
                        "Reclaimed %d stale fulfilled GCP order-backed VM(s)",
                        reclaimed,
                    )
                if orphan_reclaimed > 0:
                    logger.warning(
                        "Reclaimed %d orphan managed GCP VM(s)",
                        orphan_reclaimed,
                    )
                last_reap_at = now

            # Find the oldest open GCP order.
            open_orders = capacity_launch_order_store.list("open")
            gcp_order = None
            for order in open_orders:
                dc = (order.datacenter or "").strip().lower()
                if dc == "gcp" or dc.startswith("gcp:"):
                    gcp_order = order
                    break
            if not gcp_order:
                await asyncio.sleep(poll_seconds)
                continue

            claim_ttl = max(
                30,
                get_setting_int("operational.capacity_order_claim_ttl_seconds", fallback=600),
            )
            claimed, bootstrap_token = capacity_launch_order_store.claim_order_with_bootstrap_token(
                order_id=gcp_order.order_id,
                launcher_account_id=internal_launcher_id,
                claim_ttl_seconds=claim_ttl,
            )
            if not claimed:
                await asyncio.sleep(1)
                continue

            capacity_launch_order_store.update_status(
                order_id=claimed.order_id,
                launcher_account_id=internal_launcher_id,
                status="provisioning",
            )

            try:
                vm_name = await create_tdx_instance_for_order(
                    order_id=claimed.order_id,
                    bootstrap_token=bootstrap_token,
                    datacenter=claimed.datacenter,
                    node_size=claimed.node_size or "tiny",
                )
            except GCPProvisionError as exc:
                capacity_launch_order_store.update_status(
                    order_id=claimed.order_id,
                    launcher_account_id=internal_launcher_id,
                    status="failed",
                    error=str(exc)[:450],
                )
                logger.warning(f"GCP fulfill failed for order {claimed.order_id}: {exc}")
                await asyncio.sleep(poll_seconds)
                continue

            capacity_launch_order_store.update_status(
                order_id=claimed.order_id,
                launcher_account_id=internal_launcher_id,
                status="fulfilled",
                vm_name=vm_name,
            )
            logger.info(
                "Fulfilled GCP capacity order=%s dc=%s size=%s vm=%s",
                claimed.order_id,
                claimed.datacenter,
                claimed.node_size,
                vm_name,
            )
        except Exception as exc:
            logger.error(f"Capacity launch order fulfiller error: {exc}")
        await asyncio.sleep(poll_seconds)


def _capacity_pool_target_view(
    *,
    datacenter: str,
    node_size: str,
    min_warm_count: int,
    enabled: bool,
    require_verified: bool,
    require_healthy: bool,
    require_hostname: bool,
    dispatch: bool,
    reason: str,
    agents: list[Agent],
) -> CapacityPoolTargetView:
    eligible = [
        agent
        for agent in agents
        if _agent_matches_capacity_target(
            agent,
            datacenter=datacenter,
            node_size=node_size,
            require_verified=require_verified,
            require_healthy=require_healthy,
            require_hostname=require_hostname,
            allowed_statuses={"undeployed"},
        )
    ]
    open_count = len(capacity_reservation_store.list_open_by_pool(datacenter, node_size))
    return CapacityPoolTargetView(
        datacenter=datacenter,
        node_size=node_size,
        min_warm_count=min_warm_count,
        enabled=enabled,
        require_verified=require_verified,
        require_healthy=require_healthy,
        require_hostname=require_hostname,
        dispatch=dispatch,
        reason=reason,
        eligible_agents=len(eligible),
        open_reservations=open_count,
        shortfall=max(0, min_warm_count - open_count),
    )


def _capacity_launch_order_view(order) -> CapacityLaunchOrderView:
    return CapacityLaunchOrderView(
        order_id=order.order_id,
        datacenter=order.datacenter,
        node_size=order.node_size,
        status=order.status,
        reason=order.reason,
        requested_count=order.requested_count,
        account_id=order.account_id,
        claimed_by_account_id=order.claimed_by_account_id,
        claim_expires_at=order.claim_expires_at,
        claimed_at=order.claimed_at,
        fulfilled_at=order.fulfilled_at,
        vm_name=order.vm_name,
        error=order.error,
        created_at=order.created_at,
        updated_at=order.updated_at,
    )


@app.get(
    "/api/v1/admin/agents/capacity/targets",
    response_model=CapacityPoolTargetListResponse,
)
async def list_capacity_targets(_admin: AdminSession = Depends(require_admin_session)):
    """List warm-capacity targets and current reservation status."""
    targets = capacity_pool_target_store.list()
    agents = agent_store.list()
    views = [
        _capacity_pool_target_view(
            datacenter=(target.datacenter or "").strip().lower(),
            node_size=(target.node_size or "").strip().lower(),
            min_warm_count=target.min_warm_count,
            enabled=target.enabled,
            require_verified=target.require_verified,
            require_healthy=target.require_healthy,
            require_hostname=target.require_hostname,
            dispatch=target.dispatch,
            reason=target.reason,
            agents=agents,
        )
        for target in targets
    ]
    return CapacityPoolTargetListResponse(targets=views, total=len(views))


@app.put(
    "/api/v1/admin/agents/capacity/targets",
    response_model=CapacityPoolTargetView,
)
async def upsert_capacity_target(
    request: CapacityPoolTargetUpsertRequest,
    _admin: AdminSession = Depends(require_admin_session),
):
    """Create or update one warm-capacity target."""
    try:
        target = capacity_pool_target_store.upsert(
            datacenter=request.datacenter,
            node_size=request.node_size,
            min_warm_count=request.min_warm_count,
            enabled=request.enabled,
            require_verified=request.require_verified,
            require_healthy=request.require_healthy,
            require_hostname=request.require_hostname,
            dispatch=request.dispatch,
            reason=request.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    datacenter, node_size = _normalize_pool_key(target.datacenter, target.node_size)
    return _capacity_pool_target_view(
        datacenter=datacenter,
        node_size=node_size,
        min_warm_count=target.min_warm_count,
        enabled=target.enabled,
        require_verified=target.require_verified,
        require_healthy=target.require_healthy,
        require_hostname=target.require_hostname,
        dispatch=target.dispatch,
        reason=target.reason,
        agents=agent_store.list(),
    )


@app.delete("/api/v1/admin/agents/capacity/targets")
async def delete_capacity_target(
    datacenter: str = Query(..., description="Datacenter key (e.g. gcp:us-central1-a)"),
    node_size: str = Query("", description="Node size key (e.g. tiny, llm)"),
    _admin: AdminSession = Depends(require_admin_session),
):
    """Delete one warm-capacity target."""
    if not capacity_pool_target_store.delete_pool(datacenter, node_size):
        raise HTTPException(status_code=404, detail="Capacity target not found")
    return {"status": "deleted", "datacenter": datacenter, "node_size": node_size}


@app.get(
    "/api/v1/admin/agents/capacity/reservations",
    response_model=CapacityReservationListResponse,
)
async def list_capacity_reservations(
    status: str = Query(
        "", description="Filter by reservation status (open/consumed/expired/released)"
    ),
    _admin: AdminSession = Depends(require_admin_session),
):
    """List warm-capacity reservations."""
    normalized_status = (status or "").strip().lower()
    if normalized_status and normalized_status not in {"open", "consumed", "expired", "released"}:
        raise HTTPException(status_code=422, detail="Invalid reservation status filter")
    rows = capacity_reservation_store.list(normalized_status or None)
    reservations = [
        CapacityReservationView(
            reservation_id=row.reservation_id,
            agent_id=row.agent_id,
            datacenter=row.datacenter,
            node_size=row.node_size,
            status=row.status,
            deployment_id=row.deployment_id,
            note=row.note,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )
        for row in rows
    ]
    return CapacityReservationListResponse(reservations=reservations, total=len(reservations))


@app.get(
    "/api/v1/admin/agents/capacity/orders",
    response_model=CapacityLaunchOrderListResponse,
)
async def list_capacity_launch_orders(
    status: str = Query("", description="Filter by order status"),
    datacenter: str = Query("", description="Optional datacenter filter"),
    node_size: str = Query("", description="Optional node_size filter"),
    _admin: AdminSession = Depends(require_admin_session),
):
    """List capacity launch orders queued by the control plane."""
    normalized_status = (status or "").strip().lower()
    if normalized_status and normalized_status not in {
        "open",
        "claimed",
        "provisioning",
        "fulfilled",
        "failed",
    }:
        raise HTTPException(status_code=422, detail="Invalid launch order status filter")

    rows = capacity_launch_order_store.list(
        normalized_status or None,
        datacenter=datacenter,
        node_size=node_size,
    )
    views = [_capacity_launch_order_view(row) for row in rows]
    return CapacityLaunchOrderListResponse(orders=views, total=len(views))


@app.post(
    "/api/v1/launchers/capacity/orders/claim",
    response_model=CapacityLaunchOrderClaimResponse,
)
async def claim_capacity_launch_order(
    request: CapacityLaunchOrderClaimRequest,
    launcher_account_id: str = Depends(verify_launcher_api_key),
):
    """Claim the next open capacity launch order for a launcher account."""
    datacenter = _normalize_registration_datacenter(request.datacenter)
    if datacenter and not _DATACENTER_RE.fullmatch(datacenter):
        raise HTTPException(
            status_code=422,
            detail=(
                "Invalid datacenter. Expected '<cloud>:<zone>' (for example gcp:us-central1-a)"
            ),
        )
    node_size = _normalize_registration_node_size(request.node_size)
    if node_size and node_size not in {"tiny", "standard", "llm"}:
        raise HTTPException(
            status_code=422,
            detail="Invalid node_size. Expected one of: tiny, standard, llm",
        )

    claim_ttl = max(
        30,
        get_setting_int("operational.capacity_order_claim_ttl_seconds", fallback=600),
    )
    order, bootstrap_token = capacity_launch_order_store.claim_next_with_bootstrap_token(
        launcher_account_id=launcher_account_id,
        datacenter=datacenter,
        node_size=node_size,
        claim_ttl_seconds=claim_ttl,
    )
    if not order:
        return CapacityLaunchOrderClaimResponse(claimed=False, order=None, bootstrap_token=None)

    return CapacityLaunchOrderClaimResponse(
        claimed=True,
        order=_capacity_launch_order_view(order),
        bootstrap_token=bootstrap_token,
    )


@app.post(
    "/api/v1/launchers/capacity/orders/{order_id}",
    response_model=CapacityLaunchOrderView,
)
async def update_capacity_launch_order(
    order_id: str,
    request: CapacityLaunchOrderUpdateRequest,
    launcher_account_id: str = Depends(verify_launcher_api_key),
):
    """Update a claimed launch order status from launcher workers."""
    try:
        updated = capacity_launch_order_store.update_status(
            order_id=order_id,
            launcher_account_id=launcher_account_id,
            status=request.status,
            vm_name=request.vm_name,
            error=request.error,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if not updated:
        raise HTTPException(status_code=404, detail="Capacity launch order not found")
    return _capacity_launch_order_view(updated)


@app.post(
    "/api/v1/admin/agents/capacity/reconcile",
    response_model=AgentCapacityReconcileResponse,
)
async def reconcile_agent_capacity(
    request: AgentCapacityReconcileRequest,
    _admin: AdminSession = Depends(require_admin_session),
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
            order_scope_account_id = (request.account_id or "").strip() or None
            known_vm_names = {
                (a.vm_name or "").strip().lower()
                for a in agents
                if (a.vm_name or "").strip()
                and (a.datacenter or "").strip().lower() == target_datacenter
                and (
                    not target_node_size or (a.node_size or "").strip().lower() == target_node_size
                )
            }
            pending_fulfilled = capacity_launch_order_store.count_recent_fulfilled_without_agent(
                datacenter=target_datacenter,
                node_size=target_node_size,
                account_id=order_scope_account_id,
                known_vm_names=known_vm_names,
                grace_seconds=get_setting_int(
                    "operational.capacity_fulfilled_grace_seconds",
                    fallback=1800,
                ),
            )
            in_flight_before = capacity_launch_order_store.count_in_flight(
                datacenter=target_datacenter,
                node_size=target_node_size,
                account_id=order_scope_account_id,
            )
            dispatch_shortfall = max(0, shortfall - pending_fulfilled)
            created_orders = capacity_launch_order_store.create_missing_for_shortfall(
                datacenter=target_datacenter,
                node_size=target_node_size,
                shortfall=dispatch_shortfall,
                reason=reason,
                account_id=order_scope_account_id,
            )
            in_flight_after = capacity_launch_order_store.count_in_flight(
                datacenter=target_datacenter,
                node_size=target_node_size,
                account_id=order_scope_account_id,
            )
            effective_pending = in_flight_after + pending_fulfilled
            dispatched = effective_pending > 0
            status_code = 202 if dispatched else 200
            if created_orders:
                detail = (
                    f"queued {len(created_orders)} launch order(s); "
                    f"in_flight_before={in_flight_before}, in_flight_after={in_flight_after}, "
                    f"pending_fulfilled_unregistered={pending_fulfilled}"
                )
            elif effective_pending > 0:
                detail = (
                    "no new launch orders queued; "
                    f"existing_in_flight={in_flight_after}, "
                    f"pending_fulfilled_unregistered={pending_fulfilled}"
                )
            else:
                detail = "no launch orders available or queued"
            dispatch_results.append(
                AgentCapacityDispatchResult(
                    datacenter=target_datacenter,
                    node_size=target_node_size,
                    requested_count=dispatch_shortfall,
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
    _admin: AdminSession = Depends(require_admin_session),
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
    _admin: AdminSession = Depends(require_admin_session),
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
async def delete_agent(agent_id: str, _admin: AdminSession = Depends(require_admin_session)):
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

    capacity_reservation_store.expire_open_for_agent(agent_id)
    agent_control_credential_store.delete(agent_id)
    if not agent_store.delete(agent_id):
        raise HTTPException(status_code=404, detail="Agent not found")
    logger.info(f"Agent deleted: {agent_id}")
    return {"status": "deleted", "agent_id": agent_id}


@app.post("/api/v1/agents/{agent_id}/reset")
async def reset_agent(agent_id: str, _admin: AdminSession = Depends(require_admin_session)):
    """Reset an agent to undeployed status.

    This is useful to recover agents stuck in attestation_failed status.
    If the agent doesn't have a tunnel and is verified, creates one.
    """
    agent = get_or_404(agent_store, agent_id, "Agent")

    # Reset status to undeployed
    agent_store.update_status(agent_id, "undeployed", None)
    agent_store.set_current_deployment(agent_id, None)
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


@app.post("/api/v1/agents/{agent_id}/undeploy")
async def undeploy_agent(agent_id: str, _admin: AdminSession = Depends(require_admin_session)):
    """Undeploy workload on an agent via the agent API and reset CP state."""
    agent = get_or_404(agent_store, agent_id, "Agent")
    if not agent.hostname:
        raise HTTPException(
            status_code=400,
            detail="Agent does not have a tunnel hostname - cannot call /api/undeploy",
        )

    agent_api_secret = agent_control_credential_store.get_secret(agent_id)
    headers = {}
    if agent_api_secret:
        headers["X-Agent-Secret"] = agent_api_secret
    else:
        logger.warning(
            "Agent %s has no control credential; undeploying without X-Agent-Secret (legacy compatibility)",
            agent_id,
        )

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            headers.update(
                await _build_cp_attestation_headers(
                    client,
                    hostname=agent.hostname,
                    agent_api_secret=agent_api_secret,
                )
            )
            response = await client.post(f"https://{agent.hostname}/api/undeploy", headers=headers)
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to reach agent at {agent.hostname}: {exc}",
        ) from exc

    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail=f"Agent undeploy failed: HTTP {response.status_code} {response.text[:240]}",
        )

    if agent.current_deployment_id:
        deployment_store.complete(agent.current_deployment_id, status="undeployed")

    agent_store.update_status(agent_id, "undeployed", None)
    agent_store.set_current_deployment(agent_id, None)
    agent_store.set_deployed_app(agent_id, None)
    logger.info("Undeployed agent workload via CP proxy: agent=%s", agent_id)
    return {"status": "undeployed", "agent_id": agent_id}


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


@app.post("/api/v1/agents/{agent_id}/console-access", response_model=AgentConsoleAccessResponse)
async def mint_agent_console_access(
    agent_id: str,
    ttl_seconds: int = Query(900, ge=60, le=3600),
    session: AdminSession = Depends(verify_admin_token),
):
    """Mint a short-lived CP-signed agent console token for admin/owner access."""
    agent = get_or_404(agent_store, agent_id, "Agent")
    require_owner_or_admin(session, agent)
    return _mint_agent_console_access_response(
        agent=agent,
        session=session,
        ttl_seconds=ttl_seconds,
    )


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
    agent_store.set_current_deployment(agent_id, None)
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


@app.post(
    "/api/v1/me/agents/{agent_id}/console-access",
    response_model=AgentConsoleAccessResponse,
)
async def mint_my_agent_console_access(
    agent_id: str,
    ttl_seconds: int = Query(900, ge=60, le=3600),
    session: AdminSession = Depends(verify_admin_token),
):
    """Mint a short-lived CP-signed token for an owned agent console."""
    agent = get_or_404(agent_store, agent_id, "Agent")
    require_owner_or_admin(session, agent)
    return _mint_agent_console_access_response(
        agent=agent,
        session=session,
        ttl_seconds=ttl_seconds,
    )


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


async def _delete_managed_gcp_instance(datacenter: str, instance_name: str) -> bool:
    """Best-effort CP-native GCP instance delete used by admin cleanup routes."""
    from app.gcp_capacity import delete_instance

    return await delete_instance(datacenter=datacenter, instance_name=instance_name)


register_admin_cloud_routes(
    app,
    logger=logger,
    verify_admin_token=verify_admin_token,
    require_admin_session=require_admin_session,
    is_admin_session=is_admin_session,
    list_trusted_mrtds_fn=list_trusted_mrtds,
    setting_defs=SETTING_DEFS,
    list_settings_fn=list_settings,
    set_setting_fn=set_setting,
    delete_setting_fn=delete_setting,
    get_setting_fn=get_setting,
    get_setting_source_fn=get_setting_source,
    get_setting_int_fn=get_setting_int,
    cloudflare_module=cloudflare,
    agent_store=agent_store,
    capacity_reservation_store=capacity_reservation_store,
    get_or_404_fn=get_or_404,
    list_external_cloud_resources_fn=list_external_cloud_resources,
    dispatch_external_cleanup_fn=lambda body: dispatch_external_cleanup(body),
    fetch_external_inventory_fn=lambda: fetch_external_inventory(),
    extract_cleanup_requested_count_fn=lambda payload: _extract_cleanup_requested_count(payload),
    cloudflare_delete_many_fn=lambda **kwargs: _cloudflare_delete_many(**kwargs),
    delete_managed_gcp_instance_fn=lambda datacenter, instance_name: _delete_managed_gcp_instance(
        datacenter, instance_name
    ),
)


# ==============================================================================
# Admin Authentication
# ==============================================================================


register_auth_billing_routes(
    app,
    logger=logger,
    verify_admin_token=verify_admin_token,
    require_admin_session=require_admin_session,
    verify_account_api_key=verify_account_api_key,
    is_admin_session=is_admin_session,
    password_login_allowed_fn=_password_login_allowed,
    get_admin_password_hash_fn=get_admin_password_hash,
    generated_admin_password_fn=lambda: _generated_admin_password,
    verify_password_fn=verify_password,
    generate_session_token_fn=generate_session_token,
    create_session_expiry_fn=create_session_expiry,
    hash_api_key_fn=hash_api_key,
    get_token_prefix_fn=get_token_prefix,
    generate_api_key_fn=generate_api_key,
    get_key_prefix_fn=get_key_prefix,
    admin_session_store=admin_session_store,
    account_store=account_store,
    transaction_store=transaction_store,
    capacity_pool_target_store=capacity_pool_target_store,
    capacity_launch_order_store=capacity_launch_order_store,
    agent_store=agent_store,
    build_filters_fn=build_filters,
    create_transaction_fn=create_transaction,
    get_or_404_fn=get_or_404,
    normalize_registration_datacenter_fn=_normalize_registration_datacenter,
    datacenter_re=_DATACENTER_RE,
    normalize_registration_node_size_fn=_normalize_registration_node_size,
    parse_bool_setting_fn=_parse_bool_setting,
    get_setting_fn=get_setting,
    capacity_unit_price_monthly_usd_fn=_capacity_unit_price_monthly_usd,
    reconcile_agent_capacity_fn=reconcile_agent_capacity,
    capacity_pool_target_view_fn=_capacity_pool_target_view,
    capacity_launch_order_view_fn=_capacity_launch_order_view,
)


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
    _admin: AdminSession = Depends(require_admin_session),
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
    _admin: AdminSession = Depends(require_admin_session),
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

    # Kick measurement immediately (best-effort). A periodic background worker will
    # still pick up any pending versions if this task is interrupted.
    try:
        asyncio.create_task(_measure_pending_version_locally(new_version))
    except Exception:
        # Never fail publish due to background scheduling; version remains pending.
        logger.debug("Failed to schedule immediate measurement task", exc_info=True)

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
    _admin: AdminSession = Depends(require_admin_session),
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


def _agent_matches_warm_target(agent: Agent, target: AgentCapacityTarget) -> bool:
    agent_datacenter = (agent.datacenter or "").strip().lower()
    if not agent_datacenter:
        return False
    target_datacenter = (target.datacenter or "").strip().lower()
    if agent_datacenter != target_datacenter:
        return False

    target_node_size = (target.node_size or "").strip().lower()
    if not target_node_size:
        return True
    return (agent.node_size or "").strip().lower() == target_node_size


def _warm_target_applies_to_request(
    target: AgentCapacityTarget,
    *,
    request_node_size: str,
    allowed_datacenters: set[str],
    denied_datacenters: set[str],
    allowed_clouds: set[str],
    denied_clouds: set[str],
) -> bool:
    target_datacenter = (target.datacenter or "").strip().lower()
    if not target_datacenter:
        return False
    if allowed_datacenters and target_datacenter not in allowed_datacenters:
        return False
    if denied_datacenters and target_datacenter in denied_datacenters:
        return False

    target_cloud = _extract_cloud(target_datacenter)
    if allowed_clouds and target_cloud not in allowed_clouds:
        return False
    if denied_clouds and target_cloud in denied_clouds:
        return False

    target_node_size = (target.node_size or "").strip().lower()
    if request_node_size and target_node_size and target_node_size != request_node_size:
        return False
    return True


def _evaluate_deploy_request(
    app_name: str, app_version: str, request: DeployFromVersionRequest
) -> dict[str, object]:
    issues: list[DeploymentPreflightIssue] = []
    selected_agent: Agent | None = None
    selected_version: AppVersion | None = None
    selected_reservation_id: str | None = None
    enabled_warm_targets = capacity_pool_target_store.list(enabled_only=True)

    def fail(
        status_code: int, detail: str, *, code: str, agent: Agent | None = None
    ) -> dict[str, object]:
        issues.append(_deploy_issue(code, detail, agent=agent))
        return {
            "selected_agent": selected_agent,
            "selected_version": selected_version,
            "selected_reservation_id": selected_reservation_id,
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
    request_node_size = (request.node_size or "").strip().lower()
    warm_policy_in_scope = any(
        _warm_target_applies_to_request(
            target,
            request_node_size=request_node_size,
            allowed_datacenters=allowed_datacenters,
            denied_datacenters=denied_datacenters,
            allowed_clouds=allowed_clouds,
            denied_clouds=denied_clouds,
        )
        for target in enabled_warm_targets
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
        verified_policy_agents: list[Agent] = []
        for agent in agent_store.list():
            agent_datacenter = (agent.datacenter or "").strip().lower()
            agent_cloud = _extract_cloud(agent.datacenter)
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
            if agent.verified:
                verified_policy_agents.append(agent)
            else:
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
            candidates.append(agent)

        reservation_by_agent: dict[str, object] = {}
        warm_required_agent_ids: set[str] = set()
        for agent in candidates:
            if any(_agent_matches_warm_target(agent, target) for target in enabled_warm_targets):
                warm_required_agent_ids.add(agent.agent_id)

        if warm_required_agent_ids:
            reservation_by_agent = capacity_reservation_store.list_open_by_agent_ids(
                list(warm_required_agent_ids)
            )

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
            if agent.agent_id in warm_required_agent_ids:
                reservation = reservation_by_agent.get(agent.agent_id)
                if reservation is None:
                    if request.dry_run:
                        issues.append(
                            _deploy_issue(
                                "WARM_RESERVATION_PENDING",
                                (
                                    "Agent is eligible but currently unreserved in a warm-capacity "
                                    "pool; control plane will reserve it during deploy."
                                ),
                                agent=agent,
                            )
                        )
                    else:
                        reservation = capacity_reservation_store.create_open(
                            agent_id=agent.agent_id,
                            datacenter=(agent.datacenter or "").strip().lower(),
                            node_size=(agent.node_size or "").strip().lower(),
                            note="on-demand reservation during deploy placement",
                        )
                        reservation_by_agent[agent.agent_id] = reservation
                if reservation is not None:
                    selected_reservation_id = reservation.reservation_id
            break

        if selected_agent is None:
            if warm_policy_in_scope:
                if not verified_policy_agents:
                    summary = (
                        "No verified capacity available for deployment policy. "
                        "No verified agents match the requested cloud/datacenter/size."
                    )
                    issues.append(_deploy_issue("NO_VERIFIED_CAPACITY", summary))
                    return {
                        "selected_agent": None,
                        "selected_version": None,
                        "selected_reservation_id": None,
                        "issues": issues,
                        "error_status": 503,
                        "error_detail": summary,
                    }
            summary = "No eligible agents available for deployment"
            if issues:
                summary += f". Last reason: {issues[-1].message}"
            issues.append(_deploy_issue("NO_ELIGIBLE_AGENTS", summary))
            return {
                "selected_agent": None,
                "selected_version": None,
                "selected_reservation_id": None,
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
        "selected_reservation_id": selected_reservation_id,
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
    request = request.model_copy(update={"dry_run": True})
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
    selected_reservation_id = (
        str(result["selected_reservation_id"])
        if result.get("selected_reservation_id") is not None
        else None
    )
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
    if request.agent_id is None and selected_reservation_id:
        consumed = capacity_reservation_store.consume(
            selected_reservation_id, deployment.deployment_id
        )
        if not consumed:
            raise HTTPException(
                status_code=503,
                detail=(
                    "Warm capacity reservation is no longer available. "
                    "Retry deployment after capacity reconcile."
                ),
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
        agent_api_secret = agent_control_credential_store.get_secret(selected_agent.agent_id)
        headers = {}
        if agent_api_secret:
            headers["X-Agent-Secret"] = agent_api_secret
        else:
            logger.warning(
                "Agent %s has no control credential; deploying without X-Agent-Secret (legacy compatibility)",
                selected_agent.agent_id,
            )
        async with httpx.AsyncClient(timeout=30.0) as client:
            headers.update(
                await _build_cp_attestation_headers(
                    client,
                    hostname=selected_agent.hostname,
                    agent_api_secret=agent_api_secret,
                )
            )
            response = await client.post(
                agent_url,
                headers=headers,
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
    except HTTPException as e:
        deployment_store.complete(deployment_id, status="failed", error=str(e.detail))
        raise
    except httpx.RequestError as e:
        deployment_store.complete(deployment_id, status="failed", error=str(e))
        logger.error(f"Failed to reach agent: {e}")
        raise HTTPException(
            status_code=502,
            detail=f"Failed to reach agent at {selected_agent.hostname}: {e}",
        ) from e


register_misc_routes(
    app,
    get_proxy_url=_get_proxy_url,
    generate_tdx_quote_fn=generate_tdx_quote,
    get_or_404_fn=get_or_404,
    agent_store=agent_store,
    log_handler=_log_handler,
    admin_tokens=_admin_tokens,
    static_dir=STATIC_DIR,
)


# Mount static files after routes to avoid conflicts
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# Run with: uvicorn app.main:app --host 0.0.0.0 --port 8080
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
