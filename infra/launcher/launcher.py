#!/usr/bin/env python3
"""
TDX Launcher - Runs control plane or agent mode

This launcher supports two modes:
1. CONTROL-PLANE MODE: Runs the EasyEnclave control plane directly
   - Pulls pre-built image and runs docker-compose
   - Bootstraps a new EasyEnclave network

2. AGENT MODE (default): Polls control plane for deployments
   - Registers with the EasyEnclave control plane
   - Polls for deployment configurations
   - Executes deployments (docker compose)
   - Reports status and attestation back to control plane

The mode is determined by config.json provisioned via cloud-init.
"""

import base64
import hashlib
import hmac
import http.server
import json
import logging
import os
import re
import secrets
import shutil
import socketserver
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import zlib
from datetime import datetime, timezone
from pathlib import Path

import requests

try:
    import psutil
except ImportError:
    psutil = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# Compose command detection.
# Some images/environments have the v2 plugin (`docker compose`) while others only ship v1 (`docker-compose`).
_COMPOSE_BASE_CMD: list[str] | None = None


def _compose_base_cmd() -> list[str]:
    global _COMPOSE_BASE_CMD
    if _COMPOSE_BASE_CMD is not None:
        return _COMPOSE_BASE_CMD

    candidates: list[list[str]] = [
        ["docker", "compose"],
        ["docker-compose"],
    ]
    for base in candidates:
        try:
            # `version` should be fast and safe.
            probe = subprocess.run(
                base + ["version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            out = ((probe.stdout or "") + "\n" + (probe.stderr or "")).strip().lower()
            # Guard against misconfigured compose plugin wrappers that end up running `docker version`
            # (which would still exit 0 but is not a functional compose implementation).
            looks_like_compose = "compose" in out and (
                "docker compose" in out or "docker-compose" in out or "compose version" in out
            )
            looks_like_docker_version = "docker version" in out and "compose" not in out

            if probe.returncode == 0 and looks_like_compose and not looks_like_docker_version:
                _COMPOSE_BASE_CMD = base
                logger.info(f"Using compose command: {' '.join(base)}")
                return _COMPOSE_BASE_CMD
        except FileNotFoundError:
            continue
        except Exception:
            # If probing fails for a transient reason, keep trying other candidates.
            continue

    # Default to `docker compose` and let callers surface a useful error.
    _COMPOSE_BASE_CMD = ["docker", "compose"]
    logger.warning("Could not probe docker compose; defaulting to 'docker compose'")
    return _COMPOSE_BASE_CMD


# Configuration
CONTROL_PLANE_URL = os.environ.get("EASYENCLAVE_URL", "https://app.easyenclave.com")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "30"))
# Agent-driven attestation push cadence (control plane also does health pulls).
ATTESTATION_INTERVAL = int(os.environ.get("ATTESTATION_INTERVAL", "3600"))  # default: 1 hour
VERSION = "1.0.0"

# Modes
MODE_CONTROL_PLANE = "control-plane"
MODE_AGENT = "agent"
MODE_MEASURE = "measure"

# Admin server
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "8081"))
_generated_agent_password: str | None = None
if os.environ.get("ADMIN_PASSWORD"):
    ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
else:
    import secrets as _secrets

    ADMIN_PASSWORD = _secrets.token_urlsafe(16)
    _generated_agent_password = ADMIN_PASSWORD
AGENT_ADMIN_AUTH_MODE = (
    os.environ.get("AGENT_ADMIN_AUTH_MODE", "hybrid").strip().lower() or "hybrid"
)
if AGENT_ADMIN_AUTH_MODE not in {"password", "cp", "hybrid"}:
    AGENT_ADMIN_AUTH_MODE = "hybrid"

# Paths — detect verity image (data disk at /data) vs legacy image
_DATA_MOUNT = Path("/data")
if _DATA_MOUNT.is_mount() or _DATA_MOUNT.exists() and (_DATA_MOUNT / "docker").exists():
    WORKLOAD_DIR = _DATA_MOUNT / "workload"
    CONTROL_PLANE_DIR = _DATA_MOUNT / "easyenclave"
else:
    WORKLOAD_DIR = Path("/home/tdx/workload")
    CONTROL_PLANE_DIR = Path("/home/tdx/easyenclave")

TSM_REPORT_PATH = Path("/sys/kernel/config/tsm/report")

# Config file search chain: env override → legacy cloud-init
# (verity images pass config via kernel cmdline instead)
CONFIG_PATHS = [
    Path(os.environ.get("EASYENCLAVE_CONFIG", "/dev/null")),
    Path("/etc/easyenclave/config.json"),  # legacy image (cloud-init)
]

# Log level mapping
LOG_LEVEL_MAP = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}

# Docker Compose template for control plane mode (image pulled from GHCR)
COMPOSE_TEMPLATE = """\
services:
  easyenclave:
    image: {image}
    ports:
      - "{port}:8080"
    environment:
      - ITA_API_URL=${{ITA_API_URL:-https://api.trustauthority.intel.com/appraisal/v2}}
      - EE_AGENT_ITA_API_KEY=${{EE_AGENT_ITA_API_KEY:-}}
      - STRIPE_SECRET_KEY=${{STRIPE_SECRET_KEY:-}}
      - STRIPE_WEBHOOK_SECRET=${{STRIPE_WEBHOOK_SECRET:-}}
      - GITHUB_OAUTH_CLIENT_ID=${{GITHUB_OAUTH_CLIENT_ID:-}}
      - GITHUB_OAUTH_CLIENT_SECRET=${{GITHUB_OAUTH_CLIENT_SECRET:-}}
      - GITHUB_OAUTH_REDIRECT_URI=${{GITHUB_OAUTH_REDIRECT_URI:-}}
      - ADMIN_GITHUB_LOGINS=${{ADMIN_GITHUB_LOGINS:-}}
      - GCP_PROJECT_ID=${{GCP_PROJECT_ID:-}}
      - GCP_WORKLOAD_IDENTITY_PROVIDER=${{GCP_WORKLOAD_IDENTITY_PROVIDER:-}}
      - GCP_SERVICE_ACCOUNT=${{GCP_SERVICE_ACCOUNT:-}}
      - GCP_SERVICE_ACCOUNT_KEY=${{GCP_SERVICE_ACCOUNT_KEY:-}}
      - AZURE_SUBSCRIPTION_ID=${{AZURE_SUBSCRIPTION_ID:-}}
      - AZURE_TENANT_ID=${{AZURE_TENANT_ID:-}}
      - AZURE_CLIENT_ID=${{AZURE_CLIENT_ID:-}}
      - AZURE_CLIENT_SECRET=${{AZURE_CLIENT_SECRET:-}}
      - CLOUDFLARE_API_TOKEN=${{CLOUDFLARE_API_TOKEN:-}}
      - CLOUDFLARE_ACCOUNT_ID=${{CLOUDFLARE_ACCOUNT_ID:-}}
      - CLOUDFLARE_ZONE_ID=${{CLOUDFLARE_ZONE_ID:-}}
      - EASYENCLAVE_DOMAIN=${{EASYENCLAVE_DOMAIN:-easyenclave.com}}
      - EASYENCLAVE_CP_URL=${{EASYENCLAVE_CP_URL:-https://app.easyenclave.com}}
      - EASYENCLAVE_BOOT_ID=${{EASYENCLAVE_BOOT_ID:-}}
      - EASYENCLAVE_GIT_SHA=${{EASYENCLAVE_GIT_SHA:-}}
      - EASYENCLAVE_NETWORK_NAME=${{EASYENCLAVE_NETWORK_NAME:-}}
      - TRUSTED_AGENT_MRTDS=${{TRUSTED_AGENT_MRTDS:-}}
      - TRUSTED_PROXY_MRTDS=${{TRUSTED_PROXY_MRTDS:-}}
      - TRUSTED_AGENT_RTMRS=${{TRUSTED_AGENT_RTMRS:-}}
      - TRUSTED_PROXY_RTMRS=${{TRUSTED_PROXY_RTMRS:-}}
      - TRUSTED_AGENT_RTMRS_BY_SIZE=${{TRUSTED_AGENT_RTMRS_BY_SIZE:-}}
      - TRUSTED_PROXY_RTMRS_BY_SIZE=${{TRUSTED_PROXY_RTMRS_BY_SIZE:-}}
      - EASYENCLAVE_ENV=${{EASYENCLAVE_ENV:-}}
      - TCB_ENFORCEMENT_MODE=${{TCB_ENFORCEMENT_MODE:-warn}}
      - ALLOWED_TCB_STATUSES=${{ALLOWED_TCB_STATUSES:-UpToDate}}
      - NONCE_ENFORCEMENT_MODE=${{NONCE_ENFORCEMENT_MODE:-optional}}
      - NONCE_TTL_SECONDS=${{NONCE_TTL_SECONDS:-300}}
      - NONCE_LENGTH=${{NONCE_LENGTH:-32}}
      - RTMR_ENFORCEMENT_MODE=${{RTMR_ENFORCEMENT_MODE:-warn}}
      - SIGNATURE_VERIFICATION_MODE=${{SIGNATURE_VERIFICATION_MODE:-warn}}
      - CP_TO_AGENT_ATTESTATION_MODE=${{CP_TO_AGENT_ATTESTATION_MODE:-optional}}
      - AUTH_REQUIRE_GITHUB_OAUTH_IN_PRODUCTION=${{AUTH_REQUIRE_GITHUB_OAUTH_IN_PRODUCTION:-true}}
      - PASSWORD_LOGIN_ENABLED=${{PASSWORD_LOGIN_ENABLED:-true}}
      - AUTH_ALLOW_PASSWORD_LOGIN_IN_PRODUCTION=${{AUTH_ALLOW_PASSWORD_LOGIN_IN_PRODUCTION:-false}}
      - BILLING_ENABLED=${{BILLING_ENABLED:-true}}
      - BILLING_CAPACITY_REQUEST_DEV_SIMULATION=${{BILLING_CAPACITY_REQUEST_DEV_SIMULATION:-true}}
      - BILLING_PLATFORM_ACCOUNT_ID=${{BILLING_PLATFORM_ACCOUNT_ID:-}}
      - BILLING_CONTRIBUTOR_POOL_BPS=${{BILLING_CONTRIBUTOR_POOL_BPS:-5000}}
      - DEFAULT_GCP_TINY_CAPACITY_ENABLED=${{DEFAULT_GCP_TINY_CAPACITY_ENABLED:-false}}
      - DEFAULT_GCP_TINY_CAPACITY_COUNT=${{DEFAULT_GCP_TINY_CAPACITY_COUNT:-0}}
      - DEFAULT_GCP_TINY_CAPACITY_DISPATCH=${{DEFAULT_GCP_TINY_CAPACITY_DISPATCH:-false}}
      - AGENT_ATTESTATION_INTERVAL=${{AGENT_ATTESTATION_INTERVAL:-3600}}
      - AGENT_STALE_HOURS=${{AGENT_STALE_HOURS:-24}}
      - ADMIN_PASSWORD_HASH=${{ADMIN_PASSWORD_HASH:-}}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 5s
    restart: unless-stopped
"""

# Global state for admin server
_admin_state = {
    "agent_id": None,
    "vm_name": None,
    "status": "starting",
    "deployment_id": None,
    "deployed_app": None,
    "datacenter": None,
    "attestation": None,
    "attestation_source": None,
    "attestation_updated_at": None,
    "logs": [],
    "max_logs": 1000,
}
_admin_tokens: set = set()


def push_heartbeat_to_control_plane(
    *,
    agent_id: str,
    vm_name: str,
    attestation: dict,
    status: str | None,
    deployment_id: str | None,
):
    """Push a heartbeat + fresh attestation to the control plane."""
    url = f"{CONTROL_PLANE_URL}/api/v1/agents/{agent_id}/heartbeat"
    payload = {
        "vm_name": vm_name,
        "attestation": attestation,
        "status": status,
        "deployment_id": deployment_id,
    }
    headers = {}
    if API_SECRET:
        headers["Authorization"] = f"Bearer {API_SECRET}"
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=30)
        if resp.status_code >= 400:
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
        logger.info("Pushed agent heartbeat/attestation to control plane")
    except Exception as exc:
        logger.warning(f"Failed to push heartbeat to control plane: {exc}")


def start_periodic_attestation_push(*, agent_id: str, vm_name: str, config: dict):
    """Start background thread that periodically pushes fresh Intel TA attestation to the CP."""

    def _loop():
        # Initial delay so startup doesn't immediately double-hit Intel TA.
        time.sleep(max(10, min(ATTESTATION_INTERVAL, 60)))
        while True:
            try:
                attestation = generate_initial_attestation(
                    config, vm_name=vm_name, update_status=False
                )
                _cache_attestation(attestation, "agent_periodic_push")
                push_heartbeat_to_control_plane(
                    agent_id=agent_id,
                    vm_name=vm_name,
                    attestation=attestation,
                    status=_admin_state.get("status"),
                    deployment_id=_admin_state.get("deployment_id"),
                )
            except Exception as exc:
                logger.warning(f"Periodic attestation push failed: {exc}")
            time.sleep(max(60, ATTESTATION_INTERVAL))

    thread = threading.Thread(target=_loop, daemon=True)
    thread.start()
    return thread


def _add_admin_log(level: str, message: str):
    """Add a log entry to admin state."""
    _admin_state["logs"].append(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "message": message,
        }
    )
    # Keep only last max_logs entries
    if len(_admin_state["logs"]) > _admin_state["max_logs"]:
        _admin_state["logs"] = _admin_state["logs"][-_admin_state["max_logs"] :]


def _cache_attestation(attestation: dict, source: str):
    """Cache latest attestation for admin visibility."""
    _admin_state["attestation"] = attestation
    _admin_state["attestation_source"] = source
    _admin_state["attestation_updated_at"] = datetime.now(timezone.utc).isoformat()


def _password_admin_enabled() -> bool:
    return AGENT_ADMIN_AUTH_MODE in {"password", "hybrid"}


def _cp_relay_admin_enabled() -> bool:
    return AGENT_ADMIN_AUTH_MODE in {"cp", "hybrid"}


def _b64url_decode_nopad(value: str) -> bytes:
    padded = value + ("=" * ((4 - len(value) % 4) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _decode_cp_relay_admin_token(token: str) -> dict | None:
    """Decode and verify a CP-issued relay token using the per-agent shared secret."""
    if not API_SECRET:
        return None
    parts = (token or "").split(".")
    if len(parts) != 3 or parts[0] != "eea1":
        return None
    payload_b64 = parts[1]
    sig_b64 = parts[2]
    try:
        expected_sig = hmac.new(
            API_SECRET.encode("utf-8"),
            payload_b64.encode("ascii"),
            hashlib.sha256,
        ).digest()
        provided_sig = _b64url_decode_nopad(sig_b64)
    except Exception:
        return None
    if not hmac.compare_digest(expected_sig, provided_sig):
        return None
    try:
        payload = json.loads(_b64url_decode_nopad(payload_b64).decode("utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _verify_cp_relay_admin_token(token: str) -> bool:
    payload = _decode_cp_relay_admin_token(token)
    if not payload:
        return False
    if payload.get("sub") != "agent-admin":
        return False
    now = int(time.time())
    exp = int(payload.get("exp") or 0)
    if exp <= now:
        return False
    iat = int(payload.get("iat") or 0)
    # Permit small clock skew.
    if iat > now + 300:
        return False
    token_agent_id = str(payload.get("agent_id") or "")
    local_agent_id = str(_admin_state.get("agent_id") or "")
    if token_agent_id and local_agent_id and token_agent_id != local_agent_id:
        return False
    return True


def _cleanup_cp_attestation_challenges() -> None:
    now = time.time()
    expired = [nonce for nonce, deadline in _cp_attestation_challenges.items() if deadline <= now]
    for nonce in expired:
        _cp_attestation_challenges.pop(nonce, None)


def _issue_cp_attestation_challenge() -> str:
    _cleanup_cp_attestation_challenges()
    nonce = secrets.token_hex(32)
    _cp_attestation_challenges[nonce] = time.time() + CP_ATTESTATION_CHALLENGE_TTL
    return nonce


def _consume_cp_attestation_challenge(nonce: str) -> bool:
    _cleanup_cp_attestation_challenges()
    if not nonce:
        return False
    deadline = _cp_attestation_challenges.pop(nonce, None)
    if deadline is None:
        return False
    return deadline > time.time()


def _load_trusted_cp_mrtds(config: dict | None = None) -> None:
    """Load configured trusted CP MRTDs and optional pinned MRDT."""
    global _trusted_cp_mrtds, _trusted_cp_mrtd_pin
    config = config or {}
    values: list[str] = []
    for raw in (
        os.environ.get("TRUSTED_PROXY_MRTDS", ""),
        str(config.get("trusted_proxy_mrtds") or ""),
    ):
        if raw:
            values.extend([v.strip().lower() for v in raw.split(",") if v.strip()])
    _trusted_cp_mrtds = {v for v in values if re.fullmatch(r"[0-9a-f]{96}", v)}
    _trusted_cp_mrtd_pin = ""
    try:
        if _cp_mrtd_pin_file.exists():
            pin = _cp_mrtd_pin_file.read_text(encoding="utf-8").strip().lower()
            if re.fullmatch(r"[0-9a-f]{96}", pin):
                _trusted_cp_mrtd_pin = pin
    except Exception as exc:
        logger.warning("Failed reading pinned control-plane MRTD file: %s", exc)


def _maybe_pin_cp_mrtd(mrtd: str) -> None:
    global _trusted_cp_mrtd_pin
    if _trusted_cp_mrtd_pin:
        return
    if not re.fullmatch(r"[0-9a-f]{96}", mrtd or ""):
        return
    try:
        _cp_mrtd_pin_file.parent.mkdir(parents=True, exist_ok=True)
        _cp_mrtd_pin_file.write_text(mrtd, encoding="utf-8")
        _trusted_cp_mrtd_pin = mrtd
        logger.info("Pinned control-plane MRTD for control channel: %s...", mrtd[:16])
    except Exception as exc:
        logger.warning("Failed to persist pinned control-plane MRTD: %s", exc)


def _verify_control_plane_attestation_header(header_value: str) -> tuple[bool, str]:
    """Verify CP nonce+quote attestation envelope sent on control requests."""
    mode = CP_TO_AGENT_ATTESTATION_MODE
    if mode == "disabled":
        return True, "disabled"
    if not header_value:
        if mode == "optional":
            return True, "optional-missing"
        return False, "missing X-CP-Attestation"

    try:
        payload = json.loads(_b64url_decode_nopad(header_value).decode("utf-8"))
    except Exception:
        if mode == "optional":
            return True, "optional-invalid"
        return False, "invalid X-CP-Attestation encoding"

    nonce = str((payload or {}).get("nonce") or "").strip().lower()
    quote_b64 = str((payload or {}).get("quote_b64") or "").strip()
    if not nonce or not quote_b64:
        if mode == "optional":
            return True, "optional-missing-fields"
        return False, "X-CP-Attestation missing nonce/quote"
    if not _consume_cp_attestation_challenge(nonce):
        if mode == "optional":
            return True, "optional-challenge-miss"
        return False, "attestation challenge missing/expired"

    parsed = parse_tdx_quote(quote_b64)
    if parsed.get("error"):
        if mode == "optional":
            return True, "optional-quote-parse-failed"
        return False, f"invalid CP quote: {parsed['error']}"

    report_data = str(parsed.get("report_data") or "").strip().lower()
    # CP writes nonce bytes into report_data; compare as hex prefix.
    expected_report_prefix = nonce.encode("utf-8").hex()
    if not report_data.startswith(expected_report_prefix):
        if mode == "optional":
            return True, "optional-nonce-mismatch"
        return False, "CP quote report_data nonce mismatch"

    mrtd = str(parsed.get("mrtd") or "").strip().lower()
    if _trusted_cp_mrtds and mrtd not in _trusted_cp_mrtds:
        if mode == "optional":
            return True, "optional-untrusted-mrtd"
        return False, "CP MRTD not in TRUSTED_PROXY_MRTDS"
    if _trusted_cp_mrtd_pin and mrtd and mrtd != _trusted_cp_mrtd_pin:
        if mode == "optional":
            return True, "optional-pin-mismatch"
        return False, "CP MRTD does not match pinned value"
    if not _trusted_cp_mrtds and not _trusted_cp_mrtd_pin and mrtd:
        _maybe_pin_cp_mrtd(mrtd)
    return True, "verified"


# Workload port for proxying
WORKLOAD_PORT = int(os.environ.get("WORKLOAD_PORT", "8080"))

# API authentication - control plane uses this secret to authenticate
API_SECRET = os.environ.get("AGENT_API_SECRET", "")
CP_TO_AGENT_ATTESTATION_MODE = (
    os.environ.get("CP_TO_AGENT_ATTESTATION_MODE", "optional").strip().lower() or "optional"
)
if CP_TO_AGENT_ATTESTATION_MODE not in {"required", "optional", "disabled"}:
    CP_TO_AGENT_ATTESTATION_MODE = "optional"
CP_ATTESTATION_CHALLENGE_TTL = max(
    30,
    int(os.environ.get("CP_ATTESTATION_CHALLENGE_TTL", "180")),
)
_cp_attestation_challenges: dict[str, float] = {}
_trusted_cp_mrtds: set[str] = set()
_trusted_cp_mrtd_pin: str = ""
_cp_mrtd_pin_file = CONTROL_PLANE_DIR / "trusted-control-plane-mrtd.txt"


class AgentAPIHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for agent API (push/pull model).

    Handles:
    - GET /api/health - fast health check
    - GET /api/health?attest=true - health + fresh ITA token
    - POST /api/deploy - receive and execute deployment
    - POST /api/undeploy - stop workload
    - GET /api/logs - return docker logs
    - GET /api/stats - return system metrics
    - GET /admin - admin dashboard
    - /* - proxy to workload on port 8080
    """

    # Reference to launcher config (set by start_agent_api_server)
    launcher_config: dict = {}

    def log_message(self, format, *args):
        """Log to our logger instead of stderr."""
        logger.debug(f"API: {args[0]}")

    def _send_json(self, code: int, data: dict):
        """Send JSON response."""
        content = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _send_html(self, code: int, content: str):
        """Send HTML response."""
        content_bytes = content.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(content_bytes)))
        self.end_headers()
        self.wfile.write(content_bytes)

    def _check_api_auth(self) -> bool:
        """Check API authentication for control plane requests."""
        if not API_SECRET:
            return True  # No secret configured, allow all
        auth = self.headers.get("X-Agent-Secret", "")
        if auth == API_SECRET:
            return True
        bearer = self.headers.get("Authorization", "")
        if bearer.startswith("Bearer "):
            token = bearer[7:].strip()
            return token == API_SECRET
        return False

    def _check_admin_auth(self) -> bool:
        """Check admin authentication."""
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:].strip()
            if token in _admin_tokens:
                return True
            if _cp_relay_admin_enabled() and _verify_cp_relay_admin_token(token):
                return True
        return False

    def _check_cp_attestation(self) -> tuple[bool, str]:
        """Check CP->agent attestation envelope for control-plane write requests."""
        header_value = self.headers.get("X-CP-Attestation", "")
        return _verify_control_plane_attestation_header(header_value)

    def _get_health(
        self,
        include_attestation: bool = False,
        attestation_source: str = "health_check",
    ) -> dict:
        """Get health status, optionally with fresh attestation."""
        result = {
            "status": _admin_state["status"],
            "agent_id": _admin_state["agent_id"],
            "vm_name": _admin_state["vm_name"],
            "deployment_id": _admin_state["deployment_id"],
            "deployed_app": _admin_state.get("deployed_app"),
            "datacenter": _admin_state.get("datacenter"),
            "control_plane": CONTROL_PLANE_URL,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attestation_source": _admin_state.get("attestation_source"),
            "attestation_cached_at": _admin_state.get("attestation_updated_at"),
        }

        # Check container status
        containers = []
        try:
            proc = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in proc.stdout.strip().split("\n"):
                if line:
                    parts = line.split("\t")
                    containers.append(
                        {
                            "name": parts[0] if parts else "unknown",
                            "status": "running"
                            if "Up" in (parts[1] if len(parts) > 1 else "")
                            else "stopped",
                        }
                    )
        except Exception as e:
            logger.debug(f"Failed to get container status: {e}")
        result["containers"] = containers

        # Generate fresh attestation if requested
        if include_attestation:
            try:
                attestation = generate_initial_attestation(
                    self.launcher_config,
                    update_status=False,
                )
                _cache_attestation(attestation, attestation_source)
                result["attestation"] = attestation
                result["attestation_source"] = _admin_state.get("attestation_source")
                result["attestation_cached_at"] = _admin_state.get("attestation_updated_at")
            except Exception as e:
                result["attestation_error"] = str(e)
                logger.warning(f"Failed to generate attestation: {e}")

        return result

    def _get_logs(self, since: str = "5m", container: str = None) -> dict:
        """Get docker logs."""
        logs = []
        try:
            # Get container list
            proc = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            containers = [c for c in proc.stdout.strip().split("\n") if c]

            # Filter to specific container if requested
            if container:
                containers = [c for c in containers if container in c]

            for cname in containers:
                try:
                    log_proc = subprocess.run(
                        ["docker", "logs", "--since", since, "--timestamps", cname],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    for line in (log_proc.stdout + log_proc.stderr).strip().split("\n"):
                        if line:
                            logs.append({"container": cname, "line": line})
                except Exception as e:
                    logger.debug(f"Failed to get logs for {cname}: {e}")

        except Exception as e:
            logger.warning(f"Failed to get logs: {e}")

        return {"logs": logs, "count": len(logs)}

    def _get_stats(self) -> dict:
        """Get system stats."""
        return collect_system_stats()

    def _get_cached_measurements(self) -> dict:
        """Get cached TDX measurements from the latest attestation."""
        measurements = {}
        updated_at = _admin_state.get("attestation_updated_at")
        source = _admin_state.get("attestation_source")
        attestation = _admin_state.get("attestation") or {}
        if isinstance(attestation, dict):
            tdx = attestation.get("tdx") or {}
            if isinstance(tdx, dict):
                raw = tdx.get("measurements") or {}
                if isinstance(raw, dict):
                    for key in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"):
                        value = raw.get(key)
                        if value:
                            measurements[key] = value
            if not updated_at:
                updated_at = attestation.get("timestamp")

        age_seconds = None
        if updated_at:
            try:
                parsed = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
                age_seconds = int((datetime.now(timezone.utc) - parsed).total_seconds())
            except Exception:
                age_seconds = None

        return {
            "measurements": measurements,
            "source": source or "none",
            "updated_at": updated_at,
            "age_seconds": age_seconds,
            "refresh_hint": "GET /api/health?attest=true or POST /api/admin/reattest",
        }

    def _proxy_to_workload(self, body=None):
        """Proxy request to workload on port 8080."""
        import http.client

        try:
            # Read request body if not already provided by caller
            if body is None:
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length) if content_length > 0 else None

            # Connect to workload
            conn = http.client.HTTPConnection("127.0.0.1", WORKLOAD_PORT, timeout=30)

            # Forward headers (except Host)
            headers = {}
            for name, value in self.headers.items():
                if name.lower() not in ("host", "connection"):
                    headers[name] = value

            # Make request
            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()

            # Send response
            self.send_response(resp.status)
            for name, value in resp.getheaders():
                if name.lower() not in ("transfer-encoding", "connection"):
                    self.send_header(name, value)
            self.end_headers()

            # Stream response body
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)

            conn.close()

        except ConnectionRefusedError:
            self._send_json(502, {"error": "Workload not running"})
        except Exception as e:
            self._send_json(502, {"error": f"Proxy error: {e}"})

    def do_GET(self):
        """Handle GET requests."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # API endpoints
        if path == "/api/health":
            include_attest = query.get("attest", ["false"])[0].lower() == "true"
            self._send_json(200, self._get_health(include_attestation=include_attest))
            return

        if path == "/api/logs":
            if not self._check_api_auth():
                self._send_json(401, {"error": "Unauthorized"})
                return
            since = query.get("since", ["5m"])[0]
            container = query.get("container", [None])[0]
            self._send_json(200, self._get_logs(since=since, container=container))
            return

        if path == "/api/stats":
            if not self._check_api_auth():
                self._send_json(401, {"error": "Unauthorized"})
                return
            self._send_json(200, self._get_stats())
            return

        if path == "/api/status":
            # Alias for health without attestation
            self._send_json(200, self._get_health(include_attestation=False))
            return

        if path == "/api/control/challenge":
            if not self._check_api_auth():
                self._send_json(401, {"error": "Unauthorized"})
                return
            nonce = _issue_cp_attestation_challenge()
            self._send_json(
                200,
                {
                    "nonce": nonce,
                    "ttl_seconds": CP_ATTESTATION_CHALLENGE_TTL,
                    "issued_at": datetime.now(timezone.utc).isoformat(),
                },
            )
            return

        if path == "/api/auth/methods":
            result = {
                "password": _password_admin_enabled(),
                "cp_relay": _cp_relay_admin_enabled(),
            }
            if _generated_agent_password and _password_admin_enabled():
                result["generated_password"] = _generated_agent_password
            self._send_json(200, result)
            return

        # Admin endpoints (require admin auth)
        if path == "/admin" or path == "/":
            self._send_html(200, ADMIN_HTML)
            return

        if path == "/api/admin/logs":
            if not self._check_admin_auth():
                self._send_json(401, {"error": "Unauthorized"})
                return
            since = query.get("since", ["5m"])[0]
            self._send_json(200, self._get_logs(since=since))
            return

        if path == "/api/admin/containers":
            if not self._check_admin_auth():
                self._send_json(401, {"error": "Unauthorized"})
                return
            health = self._get_health()
            self._send_json(200, {"containers": health.get("containers", [])})
            return

        if path == "/api/admin/stats":
            if not self._check_admin_auth():
                self._send_json(401, {"error": "Unauthorized"})
                return
            self._send_json(200, self._get_stats())
            return

        if path == "/api/admin/measurements":
            if not self._check_admin_auth():
                self._send_json(401, {"error": "Unauthorized"})
                return
            self._send_json(200, self._get_cached_measurements())
            return

        # Proxy everything else to workload
        self._proxy_to_workload()

    def do_POST(self):
        """Handle POST requests."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        # Admin login (no auth required)
        if path == "/api/login":
            if not _password_admin_enabled():
                self._send_json(
                    403, {"error": "Password login disabled; use control-plane relay auth"}
                )
                return
            try:
                data = json.loads(body)
                if data.get("password") == ADMIN_PASSWORD:
                    token = secrets.token_urlsafe(32)
                    _admin_tokens.add(token)
                    if len(_admin_tokens) > 50:
                        _admin_tokens.pop()
                    self._send_json(200, {"token": token})
                else:
                    self._send_json(401, {"error": "Invalid password"})
            except Exception:
                self._send_json(400, {"error": "Invalid request"})
            return

        if path == "/api/admin/reattest":
            if not self._check_admin_auth():
                self._send_json(401, {"error": "Unauthorized"})
                return
            try:
                health = self._get_health(
                    include_attestation=True,
                    attestation_source="admin_manual",
                )
                if "attestation_error" in health:
                    self._send_json(
                        500,
                        {
                            "status": "error",
                            "error": health["attestation_error"],
                            "measurements": self._get_cached_measurements(),
                        },
                    )
                    return
                self._send_json(
                    200,
                    {
                        "status": "ok",
                        "health": health,
                        "measurements": self._get_cached_measurements(),
                    },
                )
            except Exception as e:
                self._send_json(500, {"status": "error", "error": str(e)})
            return

        # Agent API endpoints requiring auth
        if path == "/api/deploy":
            if not self._check_api_auth():
                self._send_json(401, {"error": "Unauthorized"})
                return
            verified, reason = self._check_cp_attestation()
            if not verified:
                self._send_json(401, {"error": f"Control-plane attestation required: {reason}"})
                return
            try:
                deployment = json.loads(body)
                # Handle deployment in background thread
                thread = threading.Thread(
                    target=self._handle_deploy,
                    args=(deployment,),
                    daemon=True,
                )
                thread.start()
                self._send_json(
                    202, {"status": "accepted", "deployment_id": deployment.get("deployment_id")}
                )
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        if path == "/api/undeploy":
            if not self._check_api_auth():
                self._send_json(401, {"error": "Unauthorized"})
                return
            verified, reason = self._check_cp_attestation()
            if not verified:
                self._send_json(401, {"error": f"Control-plane attestation required: {reason}"})
                return
            try:
                self._handle_undeploy()
                self._send_json(200, {"status": "undeployed"})
            except Exception as e:
                self._send_json(500, {"error": str(e)})
            return

        # Proxy everything else to workload (pass already-read body)
        self._proxy_to_workload(body=body)

    def do_PUT(self):
        """Proxy PUT to workload."""
        self._proxy_to_workload()

    def do_DELETE(self):
        """Proxy DELETE to workload."""
        self._proxy_to_workload()

    def do_PATCH(self):
        """Proxy PATCH to workload."""
        self._proxy_to_workload()

    def _handle_deploy(self, deployment: dict):
        """Handle deployment (runs in background thread)."""
        deployment_id = deployment.get("deployment_id", "unknown")
        deployment_config = deployment.get("config") or {}
        deployed_app = str(
            deployment.get("app_name")
            or deployment_config.get("app_name")
            or deployment_config.get("service_name")
            or ""
        ).strip()
        deployment_datacenter = str(deployment.get("datacenter") or "").strip()
        config = deployment.get("config") or {}

        logger.info(f"Starting deployment: {deployment_id}")
        _admin_state["deployment_id"] = deployment_id
        _admin_state["status"] = "deploying"
        _admin_state["deployed_app"] = None
        if deployment_datacenter:
            _admin_state["datacenter"] = deployment_datacenter

        try:
            # Setup workload from deployment config
            setup_workload_from_deployment(deployment)

            # Run compose
            run_compose(config)

            # Wait for health
            health_status = wait_for_health(config)

            # Generate attestation
            attestation = get_tdx_attestation(self.launcher_config, health_status)

            # Notify control plane of success
            self._notify_deployment_complete(deployment_id, attestation, config)

            _admin_state["status"] = "deployed"
            if deployed_app:
                _admin_state["deployed_app"] = deployed_app
            _cache_attestation(attestation, "deployment")
            logger.info(f"Deployment complete: {deployment_id}")

        except Exception as e:
            logger.error(f"Deployment failed: {e}")
            _admin_state["status"] = "error"
            _admin_state["deployed_app"] = None
            self._notify_deployment_failed(deployment_id, str(e))

    def _handle_undeploy(self):
        """Stop the current workload."""
        logger.info("Undeploying workload...")
        _admin_state["status"] = "undeploying"

        try:
            if WORKLOAD_DIR.exists():
                subprocess.run(
                    _compose_base_cmd() + ["down"],
                    cwd=str(WORKLOAD_DIR),
                    capture_output=True,
                    timeout=60,
                )
            _admin_state["status"] = "undeployed"
            _admin_state["deployment_id"] = None
            _admin_state["deployed_app"] = None
            _admin_state["attestation"] = None
            _admin_state["attestation_source"] = None
            _admin_state["attestation_updated_at"] = None
            logger.info("Workload undeployed")
        except Exception as e:
            logger.error(f"Undeploy failed: {e}")
            _admin_state["status"] = "error"
            raise

    def _notify_deployment_complete(self, deployment_id: str, attestation: dict, config: dict):
        """Notify control plane that deployment is complete."""
        try:
            headers = {}
            if API_SECRET:
                headers["Authorization"] = f"Bearer {API_SECRET}"
            # Notify control plane
            requests.post(
                f"{CONTROL_PLANE_URL}/api/v1/agents/{_admin_state['agent_id']}/deployed",
                json={
                    "deployment_id": deployment_id,
                    "service_id": "",
                    "attestation": attestation,
                },
                headers=headers,
                timeout=30,
            )
        except Exception as e:
            logger.warning(f"Failed to notify deployment complete: {e}")

    def _notify_deployment_failed(self, deployment_id: str, error: str):
        """Notify control plane that deployment failed."""
        try:
            headers = {}
            if API_SECRET:
                headers["Authorization"] = f"Bearer {API_SECRET}"
            requests.post(
                f"{CONTROL_PLANE_URL}/api/v1/agents/{_admin_state['agent_id']}/status",
                json={
                    "status": "error",
                    "deployment_id": deployment_id,
                    "error": error,
                },
                headers=headers,
                timeout=30,
            )
        except Exception as e:
            logger.warning(f"Failed to notify deployment failure: {e}")


def start_agent_api_server(config: dict) -> http.server.HTTPServer:
    """Start the agent API HTTP server.

    Args:
        config: Launcher configuration

    Returns:
        HTTPServer instance
    """
    AgentAPIHandler.launcher_config = config

    class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    server = ThreadedHTTPServer(("0.0.0.0", ADMIN_PORT), AgentAPIHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info(f"Agent API server started on port {ADMIN_PORT}")
    return server


_DEFAULT_ADMIN_HTML = """<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>EasyEnclave Agent</title>
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; }
      code, pre { background: #f6f8fa; padding: 0.2rem 0.4rem; border-radius: 4px; }
      .note { color: #555; }
    </style>
  </head>
  <body>
    <h1>EasyEnclave Agent</h1>
    <p class="note">Admin UI asset (<code>admin.html</code>) is missing on this node. The agent API is still running.</p>
    <p>Try: <code>GET /api/health</code>, <code>GET /api/status</code>, <code>POST /api/deploy</code></p>
  </body>
</html>
"""

try:
    ADMIN_HTML = (Path(__file__).parent / "admin.html").read_text()
except FileNotFoundError:
    # Cloud-init installs only launcher.py by default; keep agent running without UI assets.
    logger.warning("launcher admin.html not found; using built-in minimal admin UI")
    ADMIN_HTML = _DEFAULT_ADMIN_HTML


def collect_system_stats() -> dict:
    """Collect system stats using psutil."""
    if psutil is None:
        return {}

    try:
        # CPU
        cpu_percent = psutil.cpu_percent(interval=0.1)
        load_avg = list(os.getloadavg()) if hasattr(os, "getloadavg") else []

        # Memory
        mem = psutil.virtual_memory()
        memory_percent = mem.percent
        memory_used_gb = mem.used / (1024**3)
        memory_total_gb = mem.total / (1024**3)

        # Disk
        disk = psutil.disk_usage("/")
        disk_percent = disk.percent
        disk_used_gb = disk.used / (1024**3)
        disk_total_gb = disk.total / (1024**3)

        # Network (bytes since boot)
        net = psutil.net_io_counters()
        net_bytes_sent = net.bytes_sent
        net_bytes_recv = net.bytes_recv

        # Uptime
        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time

        return {
            "cpu_percent": round(cpu_percent, 1),
            "load_avg": [round(x, 2) for x in load_avg],
            "memory_percent": round(memory_percent, 1),
            "memory_used_gb": round(memory_used_gb, 2),
            "memory_total_gb": round(memory_total_gb, 2),
            "disk_percent": round(disk_percent, 1),
            "disk_used_gb": round(disk_used_gb, 2),
            "disk_total_gb": round(disk_total_gb, 2),
            "net_bytes_sent": net_bytes_sent,
            "net_bytes_recv": net_bytes_recv,
            "uptime_seconds": int(uptime_seconds),
        }
    except Exception as e:
        logger.debug(f"Failed to collect stats: {e}")
        return {}


def _parse_cmdline_config() -> dict | None:
    """Try to read config from kernel cmdline.

    Supports:
    - easyenclave.config=<base64-json>
    - easyenclave.configz=<base64-zlib-json>

    Returns:
        Parsed config dict, or None if not found/parseable.
    """
    try:
        cmdline = Path("/proc/cmdline").read_text().strip()
    except Exception:
        return None

    def _decode_b64(value: str) -> bytes:
        padded = value + ("=" * ((4 - len(value) % 4) % 4))
        try:
            return base64.b64decode(padded)
        except Exception:
            return base64.urlsafe_b64decode(padded)

    params = cmdline.split()

    # Prefer compressed payload when both are present.
    for key, compressed in (("easyenclave.configz=", True), ("easyenclave.config=", False)):
        for param in params:
            if not param.startswith(key):
                continue
            value = param.split("=", 1)[1]
            try:
                decoded = _decode_b64(value)
                if compressed:
                    decoded = zlib.decompress(decoded)
                config = json.loads(decoded)
                logger.info(
                    f"Loaded config from kernel cmdline: mode={config.get('mode', MODE_AGENT)}"
                )
                return config
            except Exception as e:
                logger.warning(f"Failed to decode kernel cmdline config ({key[:-1]}): {e}")
    return None


def _parse_config_drive() -> dict | None:
    """Try to read config from an attached config-drive ISO.

    This is used as a fallback when the launcher config is too large to fit in the
    kernel cmdline (e.g., when provisioning credentials are large JSON blobs).

    Expected ISO contents:
      - /config.json

    Returns:
        Parsed config dict, or None if not found/parseable.
    """
    import subprocess

    candidates: list[str] = []
    env_dev = (os.environ.get("EASYENCLAVE_CONFIG_DRIVE") or "").strip()
    if env_dev:
        candidates.append(env_dev)
    # Common CD-ROM device names under qemu/libvirt.
    candidates.extend(["/dev/sr0", "/dev/sr1", "/dev/cdrom", "/dev/cdrom0"])

    mount_dir = Path("/tmp/easyenclave-config-drive")
    try:
        mount_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        return None

    for dev in candidates:
        dev_path = Path(dev)
        if not dev or not dev_path.exists():
            continue

        mounted = False
        try:
            # Let mount auto-detect filesystem; iso9660 is the common case.
            subprocess.run(
                ["mount", "-o", "ro", str(dev_path), str(mount_dir)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            mounted = True

            cfg_path = mount_dir / "config.json"
            if cfg_path.exists() and cfg_path.is_file():
                config = json.loads(cfg_path.read_text(encoding="utf-8"))
                logger.info(
                    "Loaded config from config drive: mode=%s",
                    config.get("mode", MODE_AGENT),
                )
                return config
        except Exception:
            continue
        finally:
            if mounted:
                subprocess.run(
                    ["umount", str(mount_dir)],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

    return None


def get_launcher_config() -> dict:
    """Read config from the first available source.

    Search order:
      1. EASYENCLAVE_CONFIG env path / /etc/easyenclave/config.json
      1.5 Config-drive ISO (/config.json)
      2. Kernel cmdline easyenclave.config=<b64> (verity image fallback)

    Returns:
        Config dict with mode and other settings
    """
    # File-based config paths
    for config_path in CONFIG_PATHS:
        if config_path.exists() and config_path.is_file():
            try:
                config = json.loads(config_path.read_text())
                logger.info(
                    f"Loaded config from {config_path}: mode={config.get('mode', MODE_AGENT)}"
                )
                return config
            except Exception as e:
                logger.warning(f"Could not read config from {config_path}: {e}")

    # Config-drive ISO (used when cmdline payloads are too large)
    config = _parse_config_drive()
    if config is not None:
        return config

    # Fallback: kernel cmdline (verity images)
    config = _parse_cmdline_config()
    if config is not None:
        return config

    # Default to agent mode
    logger.warning("No config file found, defaulting to agent mode")
    return {"mode": MODE_AGENT}


def get_vm_name() -> str:
    """Get the VM name from environment or hostname."""
    # Try environment variable first
    vm_name = os.environ.get("VM_NAME")
    if vm_name:
        return vm_name

    # Try to get from libvirt domain name (if available via cloud-init or similar)
    try:
        with open("/etc/hostname") as f:
            hostname = f.read().strip()
            if hostname:
                return hostname
    except Exception:
        pass

    # Fall back to a generated name
    import uuid

    return f"tdx-agent-{uuid.uuid4().hex[:8]}"


def resolve_datacenter_label(config: dict | None = None) -> str:
    """Resolve normalized datacenter label from launcher config."""
    cfg = config or {}
    explicit = str(cfg.get("datacenter", "")).strip()
    if explicit:
        return explicit

    provider_raw = str(cfg.get("cloud_provider", "")).strip().lower()
    az_raw = str(cfg.get("availability_zone") or cfg.get("zone") or "").strip().lower()
    region_raw = str(cfg.get("region", "")).strip().lower()

    provider = provider_raw
    if provider_raw in ("google", "gcp"):
        provider = "gcp"
    elif provider_raw in ("azure", "az"):
        provider = "azure"
    elif provider_raw in ("baremetal", "bare-metal", "onprem", "on-prem", "self-hosted"):
        provider = "baremetal"

    # Treat AZ as datacenter for cloud providers and bare metal topology labels.
    if provider in ("gcp", "azure", "baremetal") and az_raw:
        return f"{provider}:{az_raw}"

    if provider and az_raw:
        return f"{provider}:{az_raw}"
    if provider and region_raw:
        return f"{provider}:{region_raw}"
    if provider == "baremetal":
        return "baremetal:default"
    fallback = str(os.environ.get("EASYENCLAVE_DEFAULT_DATACENTER", "")).strip().lower()
    if fallback:
        return fallback
    return "baremetal:default"


def write_status(status: str):
    """Log status update (agent reports to control plane via API)."""
    logger.info(f"Status: {status}")
    _admin_state["status"] = status


def generate_tdx_quote(user_data: bytes = None) -> str:
    """
    Generate TDX quote via ConfigFS-TSM interface.

    Args:
        user_data: Optional bytes to include in the quote's report_data field

    Returns:
        Base64-encoded TDX quote
    """
    if not TSM_REPORT_PATH.exists():
        raise RuntimeError(f"TDX not available: {TSM_REPORT_PATH} does not exist")

    report_id = f"quote_{os.getpid()}_{time.time_ns()}"
    report_dir = TSM_REPORT_PATH / report_id

    # Clean up stale report dir if it exists (from a previous crash)
    if report_dir.exists():
        try:
            report_dir.rmdir()
        except OSError:
            pass

    try:
        report_dir.mkdir()

        # Must write to inblob to trigger quote generation (even if empty)
        if user_data:
            inblob = user_data.ljust(64, b"\0")[:64]
        else:
            inblob = b"\0" * 64
        (report_dir / "inblob").write_bytes(inblob)

        quote = (report_dir / "outblob").read_bytes()
        return base64.b64encode(quote).decode()
    finally:
        if report_dir.exists():
            report_dir.rmdir()


def parse_tdx_quote(quote_b64: str) -> dict:
    """
    Parse TDX quote binary structure to extract measurements.

    Args:
        quote_b64: Base64-encoded TDX quote

    Returns:
        Dictionary with extracted measurements
    """
    try:
        quote = base64.b64decode(quote_b64)
    except Exception as e:
        logger.warning(f"Invalid base64 quote: {e}")
        return {"error": "Invalid base64 quote"}

    # Minimum TDX quote size (header + TD report)
    if len(quote) < 584:
        return {"error": "Quote too short"}

    # TDX Quote structure:
    # Header: 48 bytes
    # TD Report: 584 bytes starting at offset 48
    td_report_offset = 48

    result = {
        "quote_size": len(quote),
        "version": struct.unpack("<H", quote[0:2])[0],
    }

    # Extract TEE_TCB_SVN (16 bytes at offset 0 of TD Report)
    result["tee_tcb_svn"] = quote[td_report_offset : td_report_offset + 16].hex()

    # MRSEAM (48 bytes at offset 16)
    result["mrseam"] = quote[td_report_offset + 16 : td_report_offset + 64].hex()

    # MRSIGNERSEAM (48 bytes at offset 64)
    result["mrsigner_seam"] = quote[td_report_offset + 64 : td_report_offset + 112].hex()

    # SEAMATTRIBUTES (8 bytes at offset 112)
    result["seam_attributes"] = quote[td_report_offset + 112 : td_report_offset + 120].hex()

    # TDATTRIBUTES (8 bytes at offset 120)
    result["td_attributes"] = quote[td_report_offset + 120 : td_report_offset + 128].hex()

    # XFAM (8 bytes at offset 128)
    result["xfam"] = quote[td_report_offset + 128 : td_report_offset + 136].hex()

    # MRTD (48 bytes at offset 136) - This is the key measurement
    result["mrtd"] = quote[td_report_offset + 136 : td_report_offset + 184].hex()

    # MRCONFIGID (48 bytes at offset 184)
    result["mr_config_id"] = quote[td_report_offset + 184 : td_report_offset + 232].hex()

    # MROWNER (48 bytes at offset 232)
    result["mr_owner"] = quote[td_report_offset + 232 : td_report_offset + 280].hex()

    # MROWNERCONFIG (48 bytes at offset 280)
    result["mr_owner_config"] = quote[td_report_offset + 280 : td_report_offset + 328].hex()

    # RTMR0-3 (48 bytes each, starting at offset 328)
    for i in range(4):
        offset = td_report_offset + 328 + (i * 48)
        result[f"rtmr{i}"] = quote[offset : offset + 48].hex()

    # REPORTDATA (64 bytes at offset 520)
    result["report_data"] = quote[td_report_offset + 520 : td_report_offset + 584].hex()

    return result


def call_intel_trust_authority(quote_b64: str, api_key: str, api_url: str) -> dict:
    """
    Submit quote to Intel Trust Authority and get JWT.

    Args:
        quote_b64: Base64-encoded TDX quote
        api_key: Intel Trust Authority API key
        api_url: Intel Trust Authority API URL

    Returns:
        Response dict containing the attestation token
    """
    api_url = (api_url or "").strip().rstrip("/")
    # Users commonly set ITA_API_URL to ".../appraisal/v2" (compose template).
    # Normalize to the host base and append the stable v1 attest path.
    for suffix in ("/appraisal/v2", "/appraisal/v1", "/appraisal/v1/attest"):
        if api_url.endswith(suffix):
            api_url = api_url[: -len(suffix)].rstrip("/")
            break

    response = requests.post(
        f"{api_url}/appraisal/v1/attest",
        headers={
            "x-api-key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        json={"quote": quote_b64},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def parse_jwt_claims(jwt_token: str) -> dict:
    """Parse JWT to extract TDX measurements from claims."""
    parts = jwt_token.split(".")
    if len(parts) != 3:
        return {}

    # Decode payload (middle part)
    payload = parts[1]
    # Add padding if needed
    padding = 4 - len(payload) % 4
    if padding != 4:
        payload += "=" * padding
    # Handle URL-safe base64
    payload = payload.replace("-", "+").replace("_", "/")

    try:
        claims = json.loads(base64.b64decode(payload))
        tdx = claims.get("tdx") or {}
        return {
            "mrtd": tdx.get("tdx_mrtd"),
            "rtmr0": tdx.get("tdx_rtmr0"),
            "rtmr1": tdx.get("tdx_rtmr1"),
            "rtmr2": tdx.get("tdx_rtmr2"),
            "rtmr3": tdx.get("tdx_rtmr3"),
            "report_data": tdx.get("tdx_report_data"),
            "attester_tcb_status": tdx.get("attester_tcb_status"),
        }
    except Exception as e:
        logger.warning(f"Could not parse JWT claims: {e}")
        return {}


def generate_initial_attestation(
    config: dict,
    vm_name: str = None,
    update_status: bool = True,
    require_ita_token: bool = True,
) -> dict:
    """Generate initial TDX attestation for registration.

    This function generates a TDX quote (optionally embedding a CP-issued nonce),
    optionally mints an Intel Trust Authority (ITA) token, and returns a single
    attestation payload used for registration / heartbeats.

    Implements nonce challenge flow to prevent replay attacks:
    1. Request nonce from control plane
    2. Include nonce in TDX quote REPORTDATA field
    3. Control plane verifies nonce matches expected value

    Args:
        config: Launcher config (bootstrap fields are forwarded during registration)
        vm_name: VM name (required for nonce challenge)
        update_status: Whether to set agent status to "attesting"
        require_ita_token: If true, require ITA_API_KEY and mint intel_ta_token. If false,
            return quote-only attestation (useful for control-plane mode diagnostics).

    Returns:
        Attestation dict with (optional) ITA token + TDX quote + local measurements

    Raises:
        RuntimeError: If TDX quote generation fails
    """
    if update_status:
        write_status("attesting")
    logger.info("Generating initial TDX attestation...")

    api_url = str(os.environ.get("ITA_API_URL") or os.environ.get("INTEL_API_URL") or "").strip()
    if not api_url:
        api_url = "https://api.trustauthority.intel.com"

    # Request nonce challenge for replay attack prevention
    nonce = ""
    nonce_bytes = None
    if vm_name:
        nonce = request_nonce_challenge(vm_name)
        if nonce:
            # Convert hex nonce to bytes for inclusion in quote
            try:
                nonce_bytes = bytes.fromhex(nonce)
                logger.info(f"Including nonce in TDX quote: {nonce[:16]}...")
            except ValueError as e:
                logger.warning(f"Invalid nonce format, proceeding without: {e}")
                nonce_bytes = None

    # Generate TDX quote with nonce
    quote_b64 = generate_tdx_quote(user_data=nonce_bytes)
    measurements = parse_tdx_quote(quote_b64)
    mrtd = measurements.get("mrtd", "unknown")
    logger.info(f"Generated TDX quote, MRTD: {mrtd[:32]}...")

    # Verify nonce was included in REPORTDATA
    if nonce:
        report_data = measurements.get("report_data", "")
        # Nonce should be at the beginning of REPORTDATA (padded with zeros)
        if report_data.startswith(nonce):
            logger.info("Nonce verified in TDX quote REPORTDATA")
        else:
            logger.warning("Nonce not found in REPORTDATA (may cause registration failure)")

    intel_ta_token = ""
    if require_ita_token:
        # Agent operators must provide their own ITA API key. This keeps registration open
        # without requiring the control plane to mint ITA tokens on behalf of the internet.
        api_key = str(config.get("intel_api_key") or "").strip()
        if not api_key:
            api_key = str(
                os.environ.get("ITA_API_KEY") or os.environ.get("INTEL_API_KEY") or ""
            ).strip()
        if not api_key:
            raise RuntimeError(
                "Missing ITA_API_KEY (Intel Trust Authority API key) for agent registration"
            )

        # Mint ITA token from the quote.
        logger.info("Submitting quote to Intel Trust Authority...")
        ita_resp = call_intel_trust_authority(quote_b64=quote_b64, api_key=api_key, api_url=api_url)
        intel_ta_token = str((ita_resp or {}).get("token") or "").strip()
        if not intel_ta_token:
            raise RuntimeError("Intel Trust Authority response did not include token")

    tdx_payload = {
        "quote_b64": quote_b64,
        "measurements": measurements,
    }
    if intel_ta_token:
        tdx_payload["intel_ta_token"] = intel_ta_token

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tdx": tdx_payload,
    }


def request_nonce_challenge(vm_name: str) -> str:
    """Request nonce challenge from control plane for replay attack prevention.

    Args:
        vm_name: VM name for identification

    Returns:
        Nonce string to include in TDX quote

    Raises:
        RuntimeError: If challenge request fails
    """
    logger.info("Requesting nonce challenge from control plane...")

    try:
        response = requests.get(
            f"{CONTROL_PLANE_URL}/api/v1/agents/challenge",
            params={"vm_name": vm_name},
            timeout=30,
        )
        response.raise_for_status()
        result = response.json()

        nonce = result["nonce"]
        ttl_seconds = result.get("ttl_seconds", 300)
        logger.info(f"Received nonce challenge (TTL: {ttl_seconds}s): {nonce[:16]}...")
        return nonce

    except requests.exceptions.RequestException as e:
        logger.warning(f"Failed to request nonce challenge: {e}")
        logger.warning("Proceeding without nonce (may fail if control plane requires it)")
        return ""


def register_with_control_plane(
    attestation: dict, vm_name: str, config: dict | None = None
) -> dict:
    """Register agent with the control plane.

    Args:
        attestation: Initial TDX attestation
        vm_name: VM name for identification
        config: Launcher config (used to forward node_size)

    Returns:
        Registration response dict containing:
        - agent_id: Unique agent identifier
        - poll_interval: Seconds between polls
        - agent_api_secret: Per-agent CP<->agent shared control secret
        - tunnel_token: Cloudflare tunnel token (if configured)
        - hostname: Public hostname (if tunnel configured)
    """
    write_status("registering")
    logger.info(f"Registering with control plane: {CONTROL_PLANE_URL}")

    config = config or {}
    node_size = str(config.get("node_size", "")).strip().lower()
    if not node_size:
        node_size = (
            str(os.environ.get("EASYENCLAVE_DEFAULT_SIZE", "tiny")).strip().lower() or "tiny"
        )
        logger.warning(
            "Launcher config did not include node_size; falling back to "
            f"'{node_size}' for registration"
        )
    datacenter = resolve_datacenter_label(config)
    if not datacenter:
        raise RuntimeError("Unable to resolve datacenter label for registration")
    _admin_state["datacenter"] = datacenter
    logger.info(f"Using datacenter label: {datacenter}")
    logger.info(f"Using node_size: {node_size}")

    response = requests.post(
        f"{CONTROL_PLANE_URL}/api/v1/agents/register",
        json={
            "attestation": attestation,
            "vm_name": vm_name,
            "version": VERSION,
            "node_size": node_size,
            "datacenter": datacenter,
        },
        timeout=30,
    )
    response.raise_for_status()
    result = response.json()

    agent_id = result["agent_id"]
    hostname = result.get("hostname")
    logger.info(f"Registered as agent: {agent_id}")
    if hostname:
        logger.info(f"Assigned hostname: {hostname}")

    return result


def _ensure_cloudflared_installed() -> bool:
    """Best-effort install for cloudflared.

    Our VM images normally include cloudflared at build time, but CI/provisioned
    images can occasionally miss it (transient download/packaging failures).
    If the tunnel connector isn't running, the control plane can't reach the agent.
    """
    if shutil.which("cloudflared"):
        return True

    url = os.environ.get(
        "CLOUDFLARED_URL",
        "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64",
    ).strip()
    dest = Path("/usr/local/bin/cloudflared")

    logger.warning("cloudflared not found; attempting runtime install from %s", url)
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["curl", "-fsSL", url, "-o", str(dest)], check=True, timeout=60)
        subprocess.run(["chmod", "+x", str(dest)], check=True)
        if shutil.which("cloudflared"):
            try:
                out = subprocess.run(
                    ["cloudflared", "--version"], capture_output=True, text=True, timeout=10
                )
                logger.info("cloudflared installed: %s", (out.stdout or out.stderr or "").strip())
            except Exception:
                pass
            return True
    except Exception as exc:
        logger.warning("cloudflared runtime install failed: %s", exc)
    return False


def start_cloudflared(tunnel_token: str) -> subprocess.Popen | None:
    """Start cloudflared tunnel connector.

    Args:
        tunnel_token: Cloudflare tunnel token from registration

    Returns:
        Popen object for the cloudflared process, or None if not available
    """
    # Check if cloudflared is installed
    if not _ensure_cloudflared_installed():
        logger.warning("cloudflared not installed, skipping tunnel setup")
        return None

    logger.info("Starting cloudflared tunnel...")
    try:
        proc = subprocess.Popen(
            ["cloudflared", "tunnel", "run", "--token", tunnel_token],
            # Let output flow to console for visibility
            stdout=None,
            stderr=None,
        )
        logger.info(f"Started cloudflared (PID: {proc.pid})")
        return proc
    except Exception as e:
        logger.error(f"Failed to start cloudflared: {e}")
        return None


def setup_workload_from_deployment(deployment: dict):
    """Setup workload directory from deployment config.

    Args:
        deployment: Deployment dict with compose, build_context, config
    """
    write_status("setup")
    logger.info("Setting up workload from deployment...")

    # Stop any running containers before cleanup
    if WORKLOAD_DIR.exists() and (WORKLOAD_DIR / "docker-compose.yml").exists():
        try:
            subprocess.run(
                _compose_base_cmd() + ["down", "--remove-orphans"],
                cwd=str(WORKLOAD_DIR),
                capture_output=True,
                timeout=60,
            )
        except Exception as e:
            logger.warning(f"Failed to stop existing containers: {e}")

    # Clean up any previous workload
    if WORKLOAD_DIR.exists():
        subprocess.run(["rm", "-rf", str(WORKLOAD_DIR)], check=True)

    WORKLOAD_DIR.mkdir(parents=True)

    # Write compose file
    compose_b64 = deployment["compose"]
    compose_content = base64.b64decode(compose_b64)
    (WORKLOAD_DIR / "docker-compose.yml").write_bytes(compose_content)
    logger.info("Wrote docker-compose.yml")

    # Write build context files
    build_context = deployment.get("build_context") or {}
    for filename, content_b64 in build_context.items():
        content = base64.b64decode(content_b64)
        filepath = WORKLOAD_DIR / filename
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_bytes(content)
        logger.info(f"Wrote {filename}")

    logger.info(f"Workload setup complete: {list(WORKLOAD_DIR.iterdir())}")


def run_compose(config: dict):
    """Run docker compose.

    Args:
        config: Configuration dict with compose_up_args, etc.
    """
    write_status("building")

    compose_args = config.get("compose_up_args", "--build -d").split()
    compose_file = str(WORKLOAD_DIR / "docker-compose.yml")
    cmd = _compose_base_cmd() + ["-f", compose_file, "up"] + compose_args
    logger.info(f"Running: {' '.join(cmd)}")

    def _is_transient_compose_failure(output: str) -> bool:
        text = (output or "").lower()
        transient_markers = [
            "i/o timeout",
            "tls handshake timeout",
            "temporary failure in name resolution",
            "connection reset by peer",
            "connection timed out",
            "failed to do request",
            "net/http: request canceled",
            "context deadline exceeded",
        ]
        return any(m in text for m in transient_markers)

    last_result: subprocess.CompletedProcess | None = None
    for attempt in range(3):
        result = subprocess.run(cmd, cwd=str(WORKLOAD_DIR), capture_output=True, text=True)
        last_result = result
        if result.returncode == 0:
            break

        output = (result.stdout or "") + "\n" + (result.stderr or "")
        if _is_transient_compose_failure(output) and attempt < 2:
            sleep_s = 10 * (attempt + 1)
            logger.warning(
                f"Docker compose failed with a transient network error (attempt {attempt + 1}/3); retrying in {sleep_s}s"
            )
            time.sleep(sleep_s)
            continue
        break

    if last_result is None or last_result.returncode != 0:
        result = last_result
        extra = ""
        if result and result.stdout and result.stdout.strip():
            extra += f"\nstdout:\n{result.stdout.strip()}"
        if result and result.stderr and result.stderr.strip():
            extra += f"\nstderr:\n{result.stderr.strip()}"
        raise RuntimeError(f"Docker compose failed (cmd={' '.join(cmd)}):{extra or ' (no output)'}")

    logger.info("Docker compose completed")


def wait_for_health(config: dict) -> dict:
    """Wait for workload health endpoint.

    Args:
        config: Configuration dict with health_endpoint, health_port

    Returns:
        Health status dict
    """
    write_status("waiting_for_health")

    health_endpoint = config.get("health_endpoint", "/health")
    health_port = config.get("health_port", 8080)
    url = f"http://localhost:{health_port}{health_endpoint}"
    logger.info(f"Waiting for health endpoint: {url}")

    for _attempt in range(60):
        try:
            response = requests.get(url, timeout=5)
            if response.ok:
                logger.info(f"Health check passed: {response.text.strip()}")
                return {"status": "healthy", "response": response.text.strip()}
        except requests.RequestException:
            pass
        time.sleep(2)

    raise RuntimeError(f"Health check timeout after 120s: {url}")


def compute_compose_hash() -> str:
    """Compute SHA256 hash of the docker-compose.yml file."""
    compose_file = WORKLOAD_DIR / "docker-compose.yml"
    if compose_file.exists():
        return hashlib.sha256(compose_file.read_bytes()).hexdigest()
    return ""


def get_tdx_attestation(config: dict, health_status: dict) -> dict:
    """Generate a TDX quote + Intel Trust Authority token for a workload.

    Args:
        config: Launcher config
        health_status: Health status from wait_for_health

    Returns:
        Full attestation dict
    """
    write_status("attesting")
    # Use the same minting path as agent registration for workload attestation.
    attestation = generate_initial_attestation(
        config,
        vm_name=None,
        update_status=False,
        require_ita_token=True,
    )
    attestation["workload"] = {
        "compose_hash": f"sha256:{compute_compose_hash()}",
        "health_status": health_status.get("status", "unknown"),
    }
    return attestation


# ==============================================================================
# Control Plane Mode
# ==============================================================================


def stream_container_logs(cwd: Path, stop_event: threading.Event) -> None:
    """Stream docker compose logs to stdout in a background thread.

    Args:
        cwd: Working directory containing docker-compose.yml
        stop_event: Event to signal when to stop streaming
    """
    try:
        proc = subprocess.Popen(
            _compose_base_cmd() + ["logs", "-f", "--tail", "100"],
            cwd=str(cwd),
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        while not stop_event.is_set():
            if proc.poll() is not None:
                # Process exited, restart it
                time.sleep(1)
                if not stop_event.is_set():
                    proc = subprocess.Popen(
                        _compose_base_cmd() + ["logs", "-f", "--tail", "10"],
                        cwd=str(cwd),
                        stdout=sys.stdout,
                        stderr=sys.stderr,
                    )
            time.sleep(0.5)
        proc.terminate()
    except Exception as e:
        logger.warning(f"Container log streaming error: {e}")


def _control_plane_hostnames(config: dict) -> tuple[str, str]:
    """Return canonical and alias hostnames for the control plane."""
    domain = (config.get("easyenclave_domain") or "easyenclave.com").strip()
    network_name = (
        config.get("easyenclave_network_name")
        or config.get("easyenclave_env")
        or domain
        or "network"
    )
    network_slug = re.sub(r"[^a-z0-9-]+", "-", str(network_name).lower()).strip("-")
    if not network_slug:
        network_slug = "network"
    canonical_hostname = f"{network_slug}.{domain}"
    alias_hostname = f"app.{domain}"
    return canonical_hostname, alias_hostname


def create_control_plane_tunnel(config: dict, port: int) -> subprocess.Popen | None:
    """Create Cloudflare tunnel for the control plane.

    Uses a synchronous HTTP client since this runs before the async app starts.

    Args:
        config: Config dict with Cloudflare credentials
        port: Control plane port

    Returns:
        Popen object for cloudflared process, or None if not configured
    """
    api_token = config.get("cloudflare_api_token")
    account_id = config.get("cloudflare_account_id")
    zone_id = config.get("cloudflare_zone_id")
    canonical_hostname, alias_hostname = _control_plane_hostnames(config)

    if not all([api_token, account_id, zone_id]):
        logger.info("Cloudflare credentials not configured, skipping tunnel setup")
        return None

    if not shutil.which("cloudflared"):
        logger.warning("cloudflared not installed, skipping tunnel setup")
        return None

    import secrets

    # Keep tunnel identity unique per network so staging/prod can share one Cloudflare account.
    network_slug = canonical_hostname.split(".", 1)[0]
    if not network_slug:
        network_slug = "network"
    tunnel_name = f"easyenclave-control-plane-{network_slug}"[:190]
    hostnames: list[str] = []
    for name in (canonical_hostname, alias_hostname):
        if name and name not in hostnames:
            hostnames.append(name)

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    api_url = "https://api.cloudflare.com/client/v4"

    try:
        # Check if tunnel already exists
        logger.info(f"Looking for existing tunnel: {tunnel_name}")
        list_resp = requests.get(
            f"{api_url}/accounts/{account_id}/cfd_tunnel",
            headers=headers,
            params={"name": tunnel_name, "is_deleted": "false"},
            timeout=30,
        )
        list_resp.raise_for_status()
        tunnels = list_resp.json().get("result") or []

        if tunnels:
            # Get existing tunnel token
            tunnel_id = tunnels[0]["id"]
            logger.info(f"Found existing tunnel: {tunnel_id}")
            token_resp = requests.get(
                f"{api_url}/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token",
                headers=headers,
                timeout=30,
            )
            token_resp.raise_for_status()
            tunnel_token = token_resp.json()["result"]
        else:
            # Create new tunnel
            logger.info(f"Creating new tunnel: {tunnel_name}")
            tunnel_secret = base64.b64encode(secrets.token_bytes(32)).decode()
            create_resp = requests.post(
                f"{api_url}/accounts/{account_id}/cfd_tunnel",
                headers=headers,
                json={"name": tunnel_name, "tunnel_secret": tunnel_secret},
                timeout=30,
            )
            create_resp.raise_for_status()
            tunnel_data = create_resp.json()["result"]
            tunnel_id = tunnel_data["id"]
            tunnel_token = tunnel_data["token"]
            logger.info(f"Created tunnel: {tunnel_id}")

        # Always (re)configure ingress to point this tunnel at the local control plane port.
        logger.info(f"Configuring ingress for hostnames: {', '.join(hostnames)}")
        ingress_rules = [
            {"hostname": name, "service": f"http://127.0.0.1:{port}"} for name in hostnames
        ]
        ingress_rules.append({"service": "http_status:404"})
        config_resp = requests.put(
            f"{api_url}/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
            headers=headers,
            json={"config": {"ingress": ingress_rules}},
            timeout=30,
        )
        config_resp.raise_for_status()

        desired_content = f"{tunnel_id}.cfargotunnel.com"
        # Ensure DNS records point at this tunnel. (Idempotent upsert.)
        for hostname in hostnames:
            logger.info(f"Upserting DNS record for {hostname} -> {desired_content}")
            existing_dns = requests.get(
                f"{api_url}/zones/{zone_id}/dns_records",
                headers=headers,
                params={"type": "CNAME", "name": hostname},
                timeout=30,
            )
            existing_dns.raise_for_status()
            records = existing_dns.json().get("result") or []
            if records:
                record_id = records[0]["id"]
                update_resp = requests.put(
                    f"{api_url}/zones/{zone_id}/dns_records/{record_id}",
                    headers=headers,
                    json={
                        "type": "CNAME",
                        "name": hostname,
                        "content": desired_content,
                        "proxied": True,
                    },
                    timeout=30,
                )
                update_resp.raise_for_status()
                continue

            create_dns = requests.post(
                f"{api_url}/zones/{zone_id}/dns_records",
                headers=headers,
                json={
                    "type": "CNAME",
                    "name": hostname,
                    "content": desired_content,
                    "proxied": True,
                },
                timeout=30,
            )
            # If it races, fall back to update.
            if create_dns.status_code == 409:
                existing_dns = requests.get(
                    f"{api_url}/zones/{zone_id}/dns_records",
                    headers=headers,
                    params={"type": "CNAME", "name": hostname},
                    timeout=30,
                )
                existing_dns.raise_for_status()
                records = existing_dns.json().get("result") or []
                if not records:
                    create_dns.raise_for_status()
                record_id = records[0]["id"]
                update_resp = requests.put(
                    f"{api_url}/zones/{zone_id}/dns_records/{record_id}",
                    headers=headers,
                    json={
                        "type": "CNAME",
                        "name": hostname,
                        "content": desired_content,
                        "proxied": True,
                    },
                    timeout=30,
                )
                update_resp.raise_for_status()
            else:
                create_dns.raise_for_status()

        # Start cloudflared
        logger.info("Starting cloudflared for control plane...")
        proc = subprocess.Popen(
            ["cloudflared", "tunnel", "run", "--token", tunnel_token],
            # Let output flow to console for visibility
            stdout=None,
            stderr=None,
        )
        logger.info(f"Started cloudflared (PID: {proc.pid})")
        logger.info(
            "Control plane canonical URL: https://%s (alias: https://%s)",
            canonical_hostname,
            alias_hostname,
        )
        return proc

    except Exception as e:
        logger.error(f"Failed to create control plane tunnel: {e}")
        return None


def run_control_plane_mode(config: dict):
    """Run the control plane directly in this VM.

    This mode is used to bootstrap a new EasyEnclave network.
    The control plane runs via docker-compose with a pre-built image.

    Args:
        config: Launcher config with image, port, Cloudflare creds, etc.
    """
    write_status("control-plane-starting")
    logger.info("Starting in CONTROL PLANE mode")

    port = config.get("port", 8080)
    image = config.get("control_plane_image", "")
    if not image:
        # Do not silently fall back to :latest. CI and production must be pinned to an immutable ref.
        raise RuntimeError(
            "Missing required config 'control_plane_image' (refusing to default to :latest)"
        )

    # Write docker-compose.yml for the control plane container
    compose_file = CONTROL_PLANE_DIR / "docker-compose.yml"
    if not compose_file.exists():
        logger.info(f"Writing docker-compose.yml with image: {image}")
        compose_file.write_text(COMPOSE_TEMPLATE.format(image=image, port=port))

    # Pull the latest image (retry — DNS may not be ready on early boot)
    logger.info(f"Pulling control plane image: {image}")
    for attempt in range(3):
        result = subprocess.run(
            _compose_base_cmd() + ["pull"],
            cwd=str(CONTROL_PLANE_DIR),
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            break
        logger.warning(f"Pull failed (attempt {attempt + 1}/3): {result.stderr.strip()}")
        time.sleep(10)
    else:
        raise RuntimeError(
            f"Failed to pull control plane image after 3 attempts: {result.stderr.strip()}"
        )

    # Generate attestation for the control plane VM
    logger.info("Generating control plane attestation...")
    attestation = generate_initial_attestation(config, require_ita_token=False)

    # Save attestation to a file for reference
    attestation_file = CONTROL_PLANE_DIR / "control-plane-attestation.json"
    attestation_file.write_text(json.dumps(attestation, indent=2))
    logger.info(f"Saved attestation to {attestation_file}")

    # Run docker-compose
    logger.info("Starting control plane via docker-compose...")
    env = os.environ.copy()
    env["PORT"] = str(port)

    # Pass config values to the control plane container via environment
    if config.get("cloudflare_api_token"):
        env["CLOUDFLARE_API_TOKEN"] = config["cloudflare_api_token"]
    if config.get("cloudflare_account_id"):
        env["CLOUDFLARE_ACCOUNT_ID"] = config["cloudflare_account_id"]
    if config.get("cloudflare_zone_id"):
        env["CLOUDFLARE_ZONE_ID"] = config["cloudflare_zone_id"]
    if config.get("easyenclave_domain"):
        env["EASYENCLAVE_DOMAIN"] = config["easyenclave_domain"]
    cp_url_for_agents = (config.get("easyenclave_cp_url") or "").strip()
    if not cp_url_for_agents:
        canonical_hostname, alias_hostname = _control_plane_hostnames(config)
        cp_url_for_agents = f"https://{canonical_hostname or alias_hostname}"
    if cp_url_for_agents:
        env["EASYENCLAVE_CP_URL"] = cp_url_for_agents
        logger.info(
            "Configured CP-native provisioner agent registration URL: %s",
            cp_url_for_agents,
        )
    if config.get("easyenclave_env"):
        env["EASYENCLAVE_ENV"] = config["easyenclave_env"]
    if config.get("easyenclave_network_name"):
        env["EASYENCLAVE_NETWORK_NAME"] = config["easyenclave_network_name"]
    if config.get("easyenclave_boot_id"):
        env["EASYENCLAVE_BOOT_ID"] = config["easyenclave_boot_id"]
    if config.get("easyenclave_git_sha"):
        env["EASYENCLAVE_GIT_SHA"] = config["easyenclave_git_sha"]
    # Control plane does not require an ITA API key to verify agent tokens.
    # Optional: CP-native provisioning can inject a key into provisioned agent VMs.
    if config.get("ee_agent_ita_api_key"):
        env["EE_AGENT_ITA_API_KEY"] = config["ee_agent_ita_api_key"]
    if config.get("stripe_secret_key"):
        env["STRIPE_SECRET_KEY"] = config["stripe_secret_key"]
    if config.get("stripe_webhook_secret"):
        env["STRIPE_WEBHOOK_SECRET"] = config["stripe_webhook_secret"]
    if config.get("github_oauth_client_id"):
        env["GITHUB_OAUTH_CLIENT_ID"] = config["github_oauth_client_id"]
    if config.get("github_oauth_client_secret"):
        env["GITHUB_OAUTH_CLIENT_SECRET"] = config["github_oauth_client_secret"]
    if config.get("github_oauth_redirect_uri"):
        env["GITHUB_OAUTH_REDIRECT_URI"] = config["github_oauth_redirect_uri"]
    if config.get("admin_github_logins"):
        env["ADMIN_GITHUB_LOGINS"] = config["admin_github_logins"]
    if config.get("gcp_project_id"):
        env["GCP_PROJECT_ID"] = config["gcp_project_id"]
    if config.get("gcp_workload_identity_provider"):
        env["GCP_WORKLOAD_IDENTITY_PROVIDER"] = config["gcp_workload_identity_provider"]
    if config.get("gcp_service_account"):
        env["GCP_SERVICE_ACCOUNT"] = config["gcp_service_account"]
    if config.get("gcp_service_account_key"):
        env["GCP_SERVICE_ACCOUNT_KEY"] = config["gcp_service_account_key"]
    if config.get("ee_gcp_image_project"):
        env["EE_GCP_IMAGE_PROJECT"] = config["ee_gcp_image_project"]
    if config.get("ee_gcp_image_family"):
        env["EE_GCP_IMAGE_FAMILY"] = config["ee_gcp_image_family"]
    if config.get("ee_gcp_image_name"):
        env["EE_GCP_IMAGE_NAME"] = config["ee_gcp_image_name"]
    if config.get("azure_subscription_id"):
        env["AZURE_SUBSCRIPTION_ID"] = config["azure_subscription_id"]
    if config.get("azure_tenant_id"):
        env["AZURE_TENANT_ID"] = config["azure_tenant_id"]
    if config.get("azure_client_id"):
        env["AZURE_CLIENT_ID"] = config["azure_client_id"]
    if config.get("azure_client_secret"):
        env["AZURE_CLIENT_SECRET"] = config["azure_client_secret"]
    if config.get("trusted_agent_mrtds"):
        env["TRUSTED_AGENT_MRTDS"] = config["trusted_agent_mrtds"]
    if config.get("trusted_proxy_mrtds"):
        env["TRUSTED_PROXY_MRTDS"] = config["trusted_proxy_mrtds"]
    if config.get("trusted_agent_rtmrs"):
        env["TRUSTED_AGENT_RTMRS"] = config["trusted_agent_rtmrs"]
    if config.get("trusted_proxy_rtmrs"):
        env["TRUSTED_PROXY_RTMRS"] = config["trusted_proxy_rtmrs"]
    if config.get("trusted_agent_rtmrs_by_size"):
        env["TRUSTED_AGENT_RTMRS_BY_SIZE"] = config["trusted_agent_rtmrs_by_size"]
    if config.get("trusted_proxy_rtmrs_by_size"):
        env["TRUSTED_PROXY_RTMRS_BY_SIZE"] = config["trusted_proxy_rtmrs_by_size"]
    if config.get("tcb_enforcement_mode"):
        env["TCB_ENFORCEMENT_MODE"] = config["tcb_enforcement_mode"]
    if config.get("allowed_tcb_statuses"):
        env["ALLOWED_TCB_STATUSES"] = config["allowed_tcb_statuses"]
    if config.get("nonce_enforcement_mode"):
        env["NONCE_ENFORCEMENT_MODE"] = config["nonce_enforcement_mode"]
    if config.get("nonce_ttl_seconds"):
        env["NONCE_TTL_SECONDS"] = str(config["nonce_ttl_seconds"])
    if config.get("rtmr_enforcement_mode"):
        env["RTMR_ENFORCEMENT_MODE"] = config["rtmr_enforcement_mode"]
    if config.get("signature_verification_mode"):
        env["SIGNATURE_VERIFICATION_MODE"] = config["signature_verification_mode"]
    if config.get("cp_to_agent_attestation_mode"):
        env["CP_TO_AGENT_ATTESTATION_MODE"] = config["cp_to_agent_attestation_mode"]
    if config.get("auth_require_github_oauth_in_production"):
        env["AUTH_REQUIRE_GITHUB_OAUTH_IN_PRODUCTION"] = config[
            "auth_require_github_oauth_in_production"
        ]
    if config.get("password_login_enabled"):
        env["PASSWORD_LOGIN_ENABLED"] = config["password_login_enabled"]
    if config.get("auth_allow_password_login_in_production"):
        env["AUTH_ALLOW_PASSWORD_LOGIN_IN_PRODUCTION"] = config[
            "auth_allow_password_login_in_production"
        ]
    if config.get("billing_enabled"):
        env["BILLING_ENABLED"] = config["billing_enabled"]
    if config.get("billing_capacity_request_dev_simulation"):
        env["BILLING_CAPACITY_REQUEST_DEV_SIMULATION"] = config[
            "billing_capacity_request_dev_simulation"
        ]
    if config.get("billing_platform_account_id"):
        env["BILLING_PLATFORM_ACCOUNT_ID"] = config["billing_platform_account_id"]
    if config.get("billing_contributor_pool_bps"):
        env["BILLING_CONTRIBUTOR_POOL_BPS"] = str(config["billing_contributor_pool_bps"])
    if config.get("default_gcp_tiny_capacity_enabled"):
        env["DEFAULT_GCP_TINY_CAPACITY_ENABLED"] = config["default_gcp_tiny_capacity_enabled"]
    if config.get("default_gcp_tiny_capacity_count"):
        env["DEFAULT_GCP_TINY_CAPACITY_COUNT"] = str(config["default_gcp_tiny_capacity_count"])
    if config.get("default_gcp_tiny_capacity_dispatch"):
        env["DEFAULT_GCP_TINY_CAPACITY_DISPATCH"] = config["default_gcp_tiny_capacity_dispatch"]
    if config.get("admin_password_hash"):
        env["ADMIN_PASSWORD_HASH"] = config["admin_password_hash"]

    # Stop any existing containers
    subprocess.run(
        _compose_base_cmd() + ["down"],
        cwd=str(CONTROL_PLANE_DIR),
        capture_output=True,
    )

    # Start the control plane
    result = subprocess.run(
        _compose_base_cmd() + ["up", "-d"],
        cwd=str(CONTROL_PLANE_DIR),
        env=env,
    )

    if result.returncode != 0:
        logger.error("Docker compose up failed, check output above")
        write_status("control-plane-error")
        raise RuntimeError("Failed to start control plane")

    logger.info("Control plane started")
    write_status("control-plane-running")

    # Start streaming container logs in background
    log_stop_event = threading.Event()
    log_thread = threading.Thread(
        target=stream_container_logs,
        args=(CONTROL_PLANE_DIR, log_stop_event),
        daemon=True,
    )
    log_thread.start()
    logger.info("Container log streaming started")

    # Wait for health check
    health_url = f"http://localhost:{port}/health"
    logger.info(f"Waiting for control plane health: {health_url}")

    for _attempt in range(60):
        try:
            response = requests.get(health_url, timeout=5)
            if response.ok:
                logger.info("Control plane is healthy!")
                break
        except requests.RequestException:
            pass
        time.sleep(2)
    else:
        logger.warning("Control plane health check timeout - may still be starting")

    # Create Cloudflare tunnel for the control plane
    cloudflared_proc = create_control_plane_tunnel(config, port)

    # Get the VM's IP for logging (fallback if no tunnel)
    try:
        ip_result = subprocess.run(
            ["hostname", "-I"],
            capture_output=True,
            text=True,
        )
        vm_ip = ip_result.stdout.strip().split()[0]
        logger.info(f"Control plane available at: http://{vm_ip}:{port}")
        logger.info(f"API docs at: http://{vm_ip}:{port}/docs")

        if cloudflared_proc:
            domain = config.get("easyenclave_domain", "easyenclave.com")
            write_status(f"control-plane-ready:app.{domain}")
        else:
            write_status(f"control-plane-ready:{vm_ip}:{port}")
    except Exception as e:
        logger.warning(f"Could not determine control plane URL: {e}")
        write_status("control-plane-ready")

    # Monitor the control plane (restart if it crashes)
    logger.info("Monitoring control plane...")
    while True:
        try:
            # Check if containers are running
            result = subprocess.run(
                _compose_base_cmd() + ["ps", "-q"],
                cwd=str(CONTROL_PLANE_DIR),
                capture_output=True,
                text=True,
            )
            if not result.stdout.strip():
                logger.warning("Control plane container stopped, restarting...")
                subprocess.run(
                    _compose_base_cmd() + ["up", "-d"],
                    cwd=str(CONTROL_PLANE_DIR),
                    capture_output=True,
                )

            # Check if cloudflared is still running
            if cloudflared_proc is not None:
                poll_result = cloudflared_proc.poll()
                if poll_result is not None:
                    logger.warning(f"cloudflared exited with code {poll_result}, restarting...")
                    cloudflared_proc = create_control_plane_tunnel(config, port)

            # Health check
            try:
                response = requests.get(health_url, timeout=10)
                if not response.ok:
                    logger.warning(f"Health check failed: {response.status_code}")
            except requests.RequestException as e:
                logger.warning(f"Health check error: {e}")

        except Exception as e:
            logger.error(f"Monitor error: {e}")

        time.sleep(30)


def run_measure_mode(config: dict):
    """Run in measure mode - generate TDX quote, print measurements, poweroff.

    This mode only requires ConfigFS-TSM. No Docker, network, Intel TA,
    or control plane registration needed. Used by `tdx_cli.py vm measure`
    to capture MRTD and RTMRs from a temporary VM.

    The host parses EASYENCLAVE_MEASUREMENTS=<json> from the serial log.

    Args:
        config: Launcher config (unused, but kept for consistency)
    """
    logger.info("Starting in MEASURE mode")
    logger.info("Generating TDX quote for measurement...")

    try:
        quote_b64 = generate_tdx_quote()
        measurements = parse_tdx_quote(quote_b64)

        if "error" in measurements:
            error_msg = measurements["error"]
            logger.error(f"Failed to parse TDX quote: {error_msg}")
            print(f"EASYENCLAVE_MEASURE_ERROR={error_msg}", flush=True)
            return

        result = {
            "mrtd": measurements.get("mrtd", ""),
            "rtmr0": measurements.get("rtmr0", ""),
            "rtmr1": measurements.get("rtmr1", ""),
            "rtmr2": measurements.get("rtmr2", ""),
            "rtmr3": measurements.get("rtmr3", ""),
        }

        logger.info(f"MRTD: {result['mrtd'][:32]}...")
        print(f"EASYENCLAVE_MEASUREMENTS={json.dumps(result)}", flush=True)
        logger.info("Measurement complete.")

    except Exception as e:
        logger.error(f"Measurement failed: {e}")
        print(f"EASYENCLAVE_MEASURE_ERROR={e}", flush=True)

    finally:
        logger.info("Powering off VM...")
        subprocess.run(["systemctl", "poweroff"], check=False)


def run_agent_mode(config: dict):
    """Run in agent mode - wait for control plane to push deployments.

    This implements the push/pull model:
    1. Agent registers once with control plane (with attestation)
    2. Agent starts HTTP API server on tunnel
    3. Control plane pushes deployments via POST /api/deploy
    4. Control plane pulls logs/stats via GET /api/logs, /api/stats
    5. Control plane checks health via GET /api/health?attest=true

    Args:
        config: Launcher config (may contain control_plane_url override)
    """
    global AGENT_ADMIN_AUTH_MODE, API_SECRET, CONTROL_PLANE_URL, CP_TO_AGENT_ATTESTATION_MODE

    # Override control plane URL if specified in config
    if config.get("control_plane_url"):
        CONTROL_PLANE_URL = config["control_plane_url"]
    config_admin_mode = str(config.get("agent_admin_auth_mode") or "").strip().lower()
    if config_admin_mode in {"password", "cp", "hybrid"}:
        AGENT_ADMIN_AUTH_MODE = config_admin_mode
    config_cp_mode = str(config.get("cp_to_agent_attestation_mode") or "").strip().lower()
    if config_cp_mode in {"required", "optional", "disabled"}:
        CP_TO_AGENT_ATTESTATION_MODE = config_cp_mode
    _load_trusted_cp_mrtds(config)

    # Intentionally do not export any ITA key into the process environment here.
    # generate_initial_attestation reads it from launcher config or env when needed.

    _admin_state["status"] = "starting"

    logger.info("Starting in AGENT mode (push/pull)")
    logger.info(f"Control plane: {CONTROL_PLANE_URL}")
    logger.info(
        "Agent admin auth mode: %s | CP->agent attestation mode: %s",
        AGENT_ADMIN_AUTH_MODE,
        CP_TO_AGENT_ATTESTATION_MODE,
    )

    vm_name = get_vm_name()
    logger.info(f"VM name: {vm_name}")
    _admin_state["vm_name"] = vm_name
    _admin_state["datacenter"] = resolve_datacenter_label(config) or None

    # 1. Generate initial attestation (requires Intel TA - will crash if fails)
    # Pass vm_name for nonce challenge (replay attack prevention)
    attestation = generate_initial_attestation(config, vm_name=vm_name)
    _cache_attestation(attestation, "startup_registration")

    # 2. Register with control plane (with retry)
    agent_id = None
    cloudflared_proc = None
    tunnel_hostname = None

    for attempt in range(10):
        try:
            reg_response = register_with_control_plane(attestation, vm_name, config)
            agent_id = reg_response["agent_id"]
            tunnel_hostname = reg_response.get("hostname")
            api_secret = (reg_response.get("agent_api_secret") or "").strip()
            if not api_secret:
                raise RuntimeError("Registration response missing agent_api_secret")
            API_SECRET = api_secret

            _admin_state["agent_id"] = agent_id
            _admin_state["hostname"] = tunnel_hostname
            logger.info(f"Registered as agent: {agent_id}")

            # Start cloudflared if we got a tunnel token
            if reg_response.get("tunnel_token"):
                cloudflared_proc = start_cloudflared(reg_response["tunnel_token"])
                if cloudflared_proc and tunnel_hostname:
                    logger.info(f"Agent API available at: https://{tunnel_hostname}")

            break

        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 403:
                # MRTD not trusted - fatal error, don't retry
                logger.error(f"Registration rejected (MRTD not trusted): {e.response.text}")
                _admin_state["status"] = "rejected"
                raise RuntimeError("Registration rejected: MRTD not trusted") from e
            detail = ""
            if e.response is not None:
                try:
                    detail = (e.response.text or "").strip()
                except Exception:
                    detail = ""
            if detail:
                logger.warning(
                    f"Registration failed (attempt {attempt + 1}/10): {e} detail={detail[:600]}"
                )
            else:
                logger.warning(f"Registration failed (attempt {attempt + 1}/10): {e}")
        except Exception as e:
            logger.warning(f"Registration failed (attempt {attempt + 1}/10): {e}")

        if attempt < 9:
            time.sleep(10)
    else:
        raise RuntimeError("Failed to register with control plane after 10 attempts")

    # 3. Start API server (handles deployments, logs, stats, health)
    _admin_state["status"] = "undeployed"
    write_status("undeployed")

    start_agent_api_server(config)
    logger.info("Agent ready - waiting for commands from control plane")

    # 4. Agent-driven periodic attestation push (source of truth for attestation freshness).
    # Control plane will still do frequent health pulls, but it no longer needs to pull attestation.
    start_periodic_attestation_push(agent_id=agent_id, vm_name=vm_name, config=config)

    # 5. Monitor loop (just keep cloudflared running)
    while True:
        try:
            # Check if cloudflared is still running
            if cloudflared_proc is not None:
                poll_result = cloudflared_proc.poll()
                if poll_result is not None:
                    logger.warning(f"cloudflared exited with code {poll_result}, restarting...")
                    # Re-register to get fresh tunnel token
                    try:
                        reg_response = register_with_control_plane(attestation, vm_name, config)
                        api_secret = (reg_response.get("agent_api_secret") or "").strip()
                        if api_secret:
                            API_SECRET = api_secret
                        if reg_response.get("tunnel_token"):
                            cloudflared_proc = start_cloudflared(reg_response["tunnel_token"])
                    except Exception as e:
                        logger.error(f"Failed to restart tunnel: {e}")
                        cloudflared_proc = None

        except Exception as e:
            logger.error(f"Monitor error: {e}")

        time.sleep(30)


def main():
    """Main entry point - determines mode and runs accordingly."""
    logger.info("TDX Launcher starting...")
    logger.info(f"Version: {VERSION}")

    # Read config to determine mode
    config = get_launcher_config()
    mode = config.get("mode", MODE_AGENT)

    logger.info(f"Mode: {mode}")

    if mode == MODE_MEASURE:
        # Measure mode doesn't need writable dirs
        run_measure_mode(config)
    else:
        # Ensure writable directories exist (tmpfs /data in verity mode)
        WORKLOAD_DIR.mkdir(parents=True, exist_ok=True)
        CONTROL_PLANE_DIR.mkdir(parents=True, exist_ok=True)

        if mode == MODE_CONTROL_PLANE:
            run_control_plane_mode(config)
        else:
            run_agent_mode(config)


if __name__ == "__main__":
    exit(main() or 0)
