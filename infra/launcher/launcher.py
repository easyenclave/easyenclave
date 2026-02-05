#!/usr/bin/env python3
"""
TDX Launcher - Runs control plane or agent mode

This launcher supports two modes:
1. CONTROL-PLANE MODE: Runs the EasyEnclave control plane directly
   - Clones the easyenclave repo and runs docker-compose
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
import http.server
import json
import logging
import os
import secrets
import shutil
import socketserver
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
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

# Configuration
CONTROL_PLANE_URL = os.environ.get("EASYENCLAVE_URL", "https://app.easyenclave.com")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "30"))
ATTESTATION_INTERVAL = int(os.environ.get("ATTESTATION_INTERVAL", "300"))  # Re-attest every 5 min
VERSION = "1.0.0"

# Modes
MODE_CONTROL_PLANE = "control-plane"
MODE_AGENT = "agent"

# Admin server
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "8081"))
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

# Paths
WORKLOAD_DIR = Path("/home/tdx/workload")
TSM_REPORT_PATH = Path("/sys/kernel/config/tsm/report")
CONTROL_PLANE_DIR = Path("/home/tdx/easyenclave")

# Config file provisioned by cloud-init
CONFIG_FILE = Path("/etc/easyenclave/config.json")

# Log level mapping
LOG_LEVEL_MAP = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}

# Global state for admin server
_admin_state = {
    "agent_id": None,
    "vm_name": None,
    "status": "starting",
    "deployment_id": None,
    "attestation": None,
    "logs": [],
    "max_logs": 1000,
}
_admin_tokens: set = set()


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


# Workload port for proxying
WORKLOAD_PORT = int(os.environ.get("WORKLOAD_PORT", "8080"))

# API authentication - control plane uses this secret to authenticate
API_SECRET = os.environ.get("AGENT_API_SECRET", "")


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
        return auth == API_SECRET

    def _check_admin_auth(self) -> bool:
        """Check admin authentication."""
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
            return token in _admin_tokens
        return False

    def _get_health(self, include_attestation: bool = False) -> dict:
        """Get health status, optionally with fresh attestation."""
        result = {
            "status": _admin_state["status"],
            "agent_id": _admin_state["agent_id"],
            "vm_name": _admin_state["vm_name"],
            "deployment_id": _admin_state["deployment_id"],
            "control_plane": CONTROL_PLANE_URL,
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
                attestation = generate_initial_attestation(self.launcher_config)
                result["attestation"] = attestation
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

    def _proxy_to_workload(self):
        """Proxy request to workload on port 8080."""
        import http.client

        try:
            # Read request body if present
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

        # API endpoints requiring auth
        if not self._check_api_auth():
            self._send_json(401, {"error": "Unauthorized"})
            return

        if path == "/api/deploy":
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
            try:
                self._handle_undeploy()
                self._send_json(200, {"status": "undeployed"})
            except Exception as e:
                self._send_json(500, {"error": str(e)})
            return

        # Proxy everything else to workload
        self._proxy_to_workload()

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
        config = deployment.get("config") or {}

        logger.info(f"Starting deployment: {deployment_id}")
        _admin_state["deployment_id"] = deployment_id
        _admin_state["status"] = "deploying"

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
            _admin_state["attestation"] = attestation
            logger.info(f"Deployment complete: {deployment_id}")

        except Exception as e:
            logger.error(f"Deployment failed: {e}")
            _admin_state["status"] = "error"
            self._notify_deployment_failed(deployment_id, str(e))

    def _handle_undeploy(self):
        """Stop the current workload."""
        logger.info("Undeploying workload...")
        _admin_state["status"] = "undeploying"

        try:
            if WORKLOAD_DIR.exists():
                subprocess.run(
                    ["docker", "compose", "down"],
                    cwd=WORKLOAD_DIR,
                    capture_output=True,
                    timeout=60,
                )
            _admin_state["status"] = "undeployed"
            _admin_state["deployment_id"] = None
            _admin_state["attestation"] = None
            logger.info("Workload undeployed")
        except Exception as e:
            logger.error(f"Undeploy failed: {e}")
            _admin_state["status"] = "error"
            raise

    def _notify_deployment_complete(self, deployment_id: str, attestation: dict, config: dict):
        """Notify control plane that deployment is complete."""
        try:
            # Register service if configured
            service_id = ""
            if config.get("service_name"):
                tunnel_hostname = _admin_state.get("hostname")
                service_id = register_service(config, attestation, tunnel_hostname)

            # Notify control plane
            requests.post(
                f"{CONTROL_PLANE_URL}/api/v1/agents/{_admin_state['agent_id']}/deployed",
                json={
                    "deployment_id": deployment_id,
                    "service_id": service_id,
                    "attestation": attestation,
                },
                timeout=30,
            )
        except Exception as e:
            logger.warning(f"Failed to notify deployment complete: {e}")

    def _notify_deployment_failed(self, deployment_id: str, error: str):
        """Notify control plane that deployment failed."""
        try:
            requests.post(
                f"{CONTROL_PLANE_URL}/api/v1/agents/{_admin_state['agent_id']}/status",
                json={
                    "status": "error",
                    "deployment_id": deployment_id,
                    "error": error,
                },
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


ADMIN_HTML = (Path(__file__).parent / "admin.html").read_text()


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


def get_launcher_config() -> dict:
    """Read config from cloud-init provisioned file.

    Returns:
        Config dict with mode and other settings
    """
    if CONFIG_FILE.exists():
        try:
            config = json.loads(CONFIG_FILE.read_text())
            logger.info(f"Loaded config: mode={config.get('mode', MODE_AGENT)}")
            return config
        except Exception as e:
            logger.warning(f"Could not read config: {e}")

    # Default to agent mode
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


def generate_initial_attestation(config: dict) -> dict:
    """Generate initial TDX attestation for registration.

    This function requires Intel Trust Authority verification. The agent will
    crash if it cannot get a valid Intel TA token.

    Args:
        config: Launcher config with intel_api_key and intel_api_url

    Returns:
        Attestation dict with TDX quote and Intel TA token

    Raises:
        RuntimeError: If TDX quote generation or Intel TA verification fails
    """
    write_status("attesting")
    logger.info("Generating initial TDX attestation...")

    # Get Intel TA credentials from config or environment
    intel_api_key = config.get("intel_api_key") or os.environ.get("INTEL_API_KEY", "")
    intel_api_url = config.get("intel_api_url") or os.environ.get(
        "INTEL_API_URL", "https://api.trustauthority.intel.com"
    )

    if not intel_api_key:
        raise RuntimeError(
            "Intel Trust Authority API key required. "
            "Set intel_api_key in config or INTEL_API_KEY environment variable."
        )

    # Generate TDX quote
    quote_b64 = generate_tdx_quote()
    measurements = parse_tdx_quote(quote_b64)
    mrtd = measurements.get("mrtd", "unknown")
    logger.info(f"Generated TDX quote, MRTD: {mrtd[:32]}...")
    # Log full MRTD for vm_measure command to capture
    print(f"MRTD_FULL={mrtd}", flush=True)

    # Call Intel Trust Authority - this is mandatory
    logger.info("Calling Intel Trust Authority for attestation...")
    try:
        ita_response = call_intel_trust_authority(quote_b64, intel_api_key, intel_api_url)
        intel_ta_token = ita_response.get("token")
        if not intel_ta_token:
            raise RuntimeError("Intel Trust Authority returned no token")
        logger.info("Intel Trust Authority attestation successful")
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Intel Trust Authority request failed: {e}") from e

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tdx": {
            "quote_b64": quote_b64,
            "measurements": measurements,
            "intel_ta_token": intel_ta_token,
        },
    }


def register_with_control_plane(attestation: dict, vm_name: str) -> dict:
    """Register agent with the control plane.

    Args:
        attestation: Initial TDX attestation
        vm_name: VM name for identification

    Returns:
        Registration response dict containing:
        - agent_id: Unique agent identifier
        - poll_interval: Seconds between polls
        - tunnel_token: Cloudflare tunnel token (if configured)
        - hostname: Public hostname (if tunnel configured)
    """
    write_status("registering")
    logger.info(f"Registering with control plane: {CONTROL_PLANE_URL}")

    response = requests.post(
        f"{CONTROL_PLANE_URL}/api/v1/agents/register",
        json={
            "attestation": attestation,
            "vm_name": vm_name,
            "version": VERSION,
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


def start_cloudflared(tunnel_token: str) -> subprocess.Popen | None:
    """Start cloudflared tunnel connector.

    Args:
        tunnel_token: Cloudflare tunnel token from registration

    Returns:
        Popen object for the cloudflared process, or None if not available
    """
    # Check if cloudflared is installed
    if not shutil.which("cloudflared"):
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
    cmd = ["docker", "compose", "-f", "docker-compose.yml", "up"] + compose_args
    logger.info(f"Running: {' '.join(cmd)}")

    result = subprocess.run(cmd, cwd=WORKLOAD_DIR, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"Docker compose failed: {result.stderr}")

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
    """Generate TDX quote and get Intel TA attestation.

    Args:
        config: Configuration dict with intel_api_key, etc.
        health_status: Health status from wait_for_health

    Returns:
        Full attestation dict
    """
    write_status("attesting")

    # Check config first, then fall back to environment variable
    intel_api_key = config.get("intel_api_key") or os.environ.get("INTEL_API_KEY", "")
    intel_api_url = config.get("intel_api_url") or os.environ.get(
        "INTEL_API_URL", "https://api.trustauthority.intel.com"
    )

    if not intel_api_key:
        raise RuntimeError(
            "Intel API key required for attestation. "
            "Set intel_api_key in config or INTEL_API_KEY environment variable."
        )

    # Generate TDX quote
    logger.info("Generating TDX quote...")
    quote_b64 = generate_tdx_quote()

    # Parse local measurements from quote
    measurements = parse_tdx_quote(quote_b64)

    # Call Intel Trust Authority - this is mandatory
    logger.info("Calling Intel Trust Authority...")
    ita_response = call_intel_trust_authority(quote_b64, intel_api_key, intel_api_url)
    intel_ta_token = ita_response.get("token")
    if not intel_ta_token:
        raise RuntimeError("Intel Trust Authority returned no token")

    logger.info("Intel TA attestation successful")

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tdx": {
            "quote_b64": quote_b64,
            "measurements": measurements,
            "intel_ta_token": intel_ta_token,
        },
        "workload": {
            "compose_hash": f"sha256:{compute_compose_hash()}",
            "health_status": health_status.get("status", "unknown"),
        },
    }

    # Parse verified measurements from JWT
    jwt_measurements = parse_jwt_claims(intel_ta_token)
    if jwt_measurements:
        result["tdx"]["verified_measurements"] = jwt_measurements

    return result


def register_service(config: dict, attestation: dict, tunnel_hostname: str | None = None) -> str:
    """Register service with EasyEnclave discovery.

    Args:
        config: Configuration dict with service_name, service_url, etc.
        attestation: Attestation dict with TDX measurements
        tunnel_hostname: Optional Cloudflare tunnel hostname (e.g., agent-xyz.easyenclave.com)

    Returns:
        Service ID from registration
    """
    service_name = config.get("service_name")

    # Explicit service_url in config takes precedence over tunnel hostname
    service_url = config.get("service_url")
    if not service_url and tunnel_hostname:
        service_url = f"https://{tunnel_hostname}"

    if not service_name:
        logger.info("No service_name - skipping registration")
        return ""

    if not service_url:
        logger.info("No service_url or tunnel_hostname - skipping registration")
        return ""

    payload = {
        "name": service_name,
        "description": config.get("service_description", ""),
        "endpoints": {"prod": service_url},
        "source_repo": config.get("source_repo"),
        "source_commit": config.get("source_commit"),
        "tags": config.get("tags") or [],
        "mrtd": attestation["tdx"]["measurements"].get("mrtd", ""),
        "intel_ta_token": attestation["tdx"].get("intel_ta_token"),
    }

    logger.info(f"Registering service: {service_name} at {service_url}")

    response = requests.post(
        f"{CONTROL_PLANE_URL}/api/v1/register",
        json=payload,
        timeout=30,
    )
    if not response.ok:
        logger.error(f"Service registration failed: {response.status_code} {response.text}")
    response.raise_for_status()
    result = response.json()

    service_id = result.get("service_id", "")
    logger.info(f"Registered service: {service_id}")
    return service_id


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
            ["docker", "compose", "logs", "-f", "--tail", "100"],
            cwd=cwd,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        while not stop_event.is_set():
            if proc.poll() is not None:
                # Process exited, restart it
                time.sleep(1)
                if not stop_event.is_set():
                    proc = subprocess.Popen(
                        ["docker", "compose", "logs", "-f", "--tail", "10"],
                        cwd=cwd,
                        stdout=sys.stdout,
                        stderr=sys.stderr,
                    )
            time.sleep(0.5)
        proc.terminate()
    except Exception as e:
        logger.warning(f"Container log streaming error: {e}")


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
    domain = config.get("easyenclave_domain", "easyenclave.com")

    if not all([api_token, account_id, zone_id]):
        logger.info("Cloudflare credentials not configured, skipping tunnel setup")
        return None

    if not shutil.which("cloudflared"):
        logger.warning("cloudflared not installed, skipping tunnel setup")
        return None

    import secrets

    tunnel_name = "easyenclave-control-plane"
    hostname = f"app.{domain}"

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

            # Configure ingress
            logger.info(f"Configuring ingress for {hostname}")
            config_resp = requests.put(
                f"{api_url}/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
                headers=headers,
                json={
                    "config": {
                        "ingress": [
                            {"hostname": hostname, "service": f"http://127.0.0.1:{port}"},
                            {"service": "http_status:404"},
                        ]
                    }
                },
                timeout=30,
            )
            config_resp.raise_for_status()

            # Create DNS record
            logger.info(f"Creating DNS record for {hostname}")
            dns_resp = requests.post(
                f"{api_url}/zones/{zone_id}/dns_records",
                headers=headers,
                json={
                    "type": "CNAME",
                    "name": "app",
                    "content": f"{tunnel_id}.cfargotunnel.com",
                    "proxied": True,
                },
                timeout=30,
            )
            # Ignore if DNS already exists
            if dns_resp.status_code not in (200, 409):
                if "already exists" not in dns_resp.text.lower():
                    dns_resp.raise_for_status()

        # Start cloudflared
        logger.info("Starting cloudflared for control plane...")
        proc = subprocess.Popen(
            ["cloudflared", "tunnel", "run", "--token", tunnel_token],
            # Let output flow to console for visibility
            stdout=None,
            stderr=None,
        )
        logger.info(f"Started cloudflared (PID: {proc.pid})")
        logger.info(f"Control plane available at: https://{hostname}")
        return proc

    except Exception as e:
        logger.error(f"Failed to create control plane tunnel: {e}")
        return None


def run_control_plane_mode(config: dict):
    """Run the control plane directly in this VM.

    This mode is used to bootstrap a new EasyEnclave network.
    The control plane runs via docker-compose.

    Args:
        config: Launcher config with repo URL, port, Cloudflare creds, etc.
    """
    write_status("control-plane-starting")
    logger.info("Starting in CONTROL PLANE mode")

    repo_url = config.get("easyenclave_repo", "https://github.com/easyenclave/easyenclave.git")
    port = config.get("port", 8080)

    # Clone or update the easyenclave repo
    if CONTROL_PLANE_DIR.exists():
        logger.info("Updating easyenclave repo...")
        subprocess.run(
            ["git", "pull"],
            cwd=CONTROL_PLANE_DIR,
            check=True,
            capture_output=True,
        )
    else:
        logger.info(f"Cloning easyenclave repo from {repo_url}...")
        subprocess.run(
            ["git", "clone", repo_url, str(CONTROL_PLANE_DIR)],
            check=True,
            capture_output=True,
        )

    # Generate attestation for the control plane VM
    logger.info("Generating control plane attestation...")
    attestation = generate_initial_attestation(config)

    # Save attestation to a file for reference
    attestation_file = CONTROL_PLANE_DIR / "control-plane-attestation.json"
    attestation_file.write_text(json.dumps(attestation, indent=2))
    logger.info(f"Saved attestation to {attestation_file}")

    # Run docker-compose
    logger.info("Starting control plane via docker-compose...")
    env = os.environ.copy()
    env["PORT"] = str(port)

    # Pass Cloudflare credentials to the control plane container
    if config.get("cloudflare_api_token"):
        env["CLOUDFLARE_API_TOKEN"] = config["cloudflare_api_token"]
    if config.get("cloudflare_account_id"):
        env["CLOUDFLARE_ACCOUNT_ID"] = config["cloudflare_account_id"]
    if config.get("cloudflare_zone_id"):
        env["CLOUDFLARE_ZONE_ID"] = config["cloudflare_zone_id"]
    if config.get("easyenclave_domain"):
        env["EASYENCLAVE_DOMAIN"] = config["easyenclave_domain"]
    if config.get("intel_api_key"):
        env["ITA_API_KEY"] = config["intel_api_key"]
    if config.get("trusted_agent_mrtds"):
        env["TRUSTED_AGENT_MRTDS"] = config["trusted_agent_mrtds"]
    if config.get("trusted_proxy_mrtds"):
        env["TRUSTED_PROXY_MRTDS"] = config["trusted_proxy_mrtds"]
    if config.get("admin_password"):
        env["ADMIN_PASSWORD"] = config["admin_password"]

    # Stop any existing containers
    subprocess.run(
        ["docker", "compose", "down"],
        cwd=CONTROL_PLANE_DIR,
        capture_output=True,
    )

    # Build fresh to pick up code changes (no cache)
    # Output flows to console for visibility during --wait
    logger.info("Building control plane image (no cache)...")
    build_result = subprocess.run(
        ["docker", "compose", "build", "--no-cache"],
        cwd=CONTROL_PLANE_DIR,
        env=env,
    )
    if build_result.returncode != 0:
        logger.warning("Docker build failed, check output above")

    # Start the control plane
    result = subprocess.run(
        ["docker", "compose", "up", "-d"],
        cwd=CONTROL_PLANE_DIR,
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
                ["docker", "compose", "ps", "-q"],
                cwd=CONTROL_PLANE_DIR,
                capture_output=True,
                text=True,
            )
            if not result.stdout.strip():
                logger.warning("Control plane container stopped, restarting...")
                subprocess.run(
                    ["docker", "compose", "up", "-d"],
                    cwd=CONTROL_PLANE_DIR,
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
    global CONTROL_PLANE_URL

    # Override control plane URL if specified in config
    if config.get("control_plane_url"):
        CONTROL_PLANE_URL = config["control_plane_url"]

    # Set INTEL_API_KEY env var for use by deployment attestation
    if config.get("intel_api_key") and not os.environ.get("INTEL_API_KEY"):
        os.environ["INTEL_API_KEY"] = config["intel_api_key"]

    _admin_state["status"] = "starting"

    logger.info("Starting in AGENT mode (push/pull)")
    logger.info(f"Control plane: {CONTROL_PLANE_URL}")

    vm_name = get_vm_name()
    logger.info(f"VM name: {vm_name}")
    _admin_state["vm_name"] = vm_name

    # 1. Generate initial attestation (requires Intel TA - will crash if fails)
    attestation = generate_initial_attestation(config)
    _admin_state["attestation"] = attestation

    # 2. Register with control plane (with retry)
    agent_id = None
    cloudflared_proc = None
    tunnel_hostname = None

    for attempt in range(10):
        try:
            reg_response = register_with_control_plane(attestation, vm_name)
            agent_id = reg_response["agent_id"]
            tunnel_hostname = reg_response.get("hostname")

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

    # 4. Monitor loop (just keep cloudflared running)
    while True:
        try:
            # Check if cloudflared is still running
            if cloudflared_proc is not None:
                poll_result = cloudflared_proc.poll()
                if poll_result is not None:
                    logger.warning(f"cloudflared exited with code {poll_result}, restarting...")
                    # Re-register to get fresh tunnel token
                    try:
                        reg_response = register_with_control_plane(attestation, vm_name)
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

    if mode == MODE_CONTROL_PLANE:
        run_control_plane_mode(config)
    else:
        run_agent_mode(config)


if __name__ == "__main__":
    exit(main() or 0)
