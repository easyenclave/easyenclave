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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# Configuration
CONTROL_PLANE_URL = os.environ.get("EASYENCLAVE_URL", "https://app.easyenclave.com")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "30"))
LOG_FLUSH_INTERVAL = int(os.environ.get("LOG_FLUSH_INTERVAL", "10"))  # Send logs every 10s
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


# Admin HTML page (embedded to avoid file dependencies)
ADMIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EasyEnclave Agent Admin</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #f3f4f6; color: #1f2937; }
        .container { max-width: 1000px; margin: 0 auto; padding: 20px; }
        header { background: #7c3aed; color: white; padding: 20px 0; margin-bottom: 20px; }
        header h1 { padding: 0 20px; }
        .card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .card h2 { margin-bottom: 15px; color: #374151; font-size: 1.1rem; }
        table { width: 100%; border-collapse: collapse; }
        td { padding: 8px 0; border-bottom: 1px solid #e5e7eb; }
        td:first-child { color: #6b7280; width: 150px; }
        code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 0.85rem; }
        .status { padding: 3px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 500; }
        .status.healthy, .status.deployed { background: #dcfce7; color: #166534; }
        .status.unhealthy, .status.error { background: #fee2e2; color: #991b1b; }
        .status.undeployed { background: #e5e7eb; color: #374151; }
        .log-viewer { background: #1f2937; color: #e5e7eb; padding: 15px; border-radius: 8px; font-family: monospace; font-size: 0.8rem; max-height: 400px; overflow-y: auto; white-space: pre-wrap; }
        .log-entry { margin-bottom: 2px; }
        .log-entry.error { color: #f87171; }
        .log-entry.warning { color: #fbbf24; }
        .log-entry.info { color: #60a5fa; }
        .btn { padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; font-size: 0.9rem; }
        .btn-primary { background: #7c3aed; color: white; }
        .btn-primary:hover { background: #6d28d9; }
        .hidden { display: none; }
        .login-box { max-width: 350px; margin: 100px auto; }
        .login-box input { width: 100%; padding: 10px; margin-bottom: 15px; border: 1px solid #d1d5db; border-radius: 6px; }
        .error-msg { background: #fee2e2; color: #991b1b; padding: 10px; border-radius: 6px; margin-bottom: 15px; display: none; }
        .flex { display: flex; justify-content: space-between; align-items: center; }
    </style>
</head>
<body>
    <div id="loginPage">
        <div class="container">
            <div class="login-box card">
                <h2>Agent Admin Login</h2>
                <div id="loginError" class="error-msg"></div>
                <form onsubmit="login(event)">
                    <input type="password" id="password" placeholder="Password" required autofocus>
                    <button type="submit" class="btn btn-primary" style="width:100%">Login</button>
                </form>
            </div>
        </div>
    </div>

    <div id="adminPage" class="hidden">
        <header><div class="container"><h1>Agent Admin</h1></div></header>
        <div class="container">
            <div class="card">
                <div class="flex">
                    <h2>Agent Status</h2>
                    <button class="btn btn-primary" onclick="refresh()">Refresh</button>
                </div>
                <table id="statusTable">
                    <tr><td>Loading...</td><td></td></tr>
                </table>
            </div>

            <div class="card">
                <h2>Containers</h2>
                <div id="containers">Loading...</div>
            </div>

            <div class="card">
                <div class="flex">
                    <h2>Logs</h2>
                    <select id="logLevel" onchange="loadLogs()">
                        <option value="debug">Debug+</option>
                        <option value="info" selected>Info+</option>
                        <option value="warning">Warning+</option>
                        <option value="error">Error only</option>
                    </select>
                </div>
                <div id="logViewer" class="log-viewer">Loading...</div>
            </div>
        </div>
    </div>

    <script>
        let token = sessionStorage.getItem("agentToken");
        if (token) showDashboard();

        async function login(e) {
            e.preventDefault();
            const pw = document.getElementById("password").value;
            const err = document.getElementById("loginError");
            try {
                const r = await fetch("/api/login", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({password: pw})
                });
                if (r.ok) {
                    const d = await r.json();
                    token = d.token;
                    sessionStorage.setItem("agentToken", token);
                    showDashboard();
                } else {
                    err.textContent = "Invalid password";
                    err.style.display = "block";
                }
            } catch(e) { err.textContent = "Error"; err.style.display = "block"; }
        }

        function showDashboard() {
            document.getElementById("loginPage").classList.add("hidden");
            document.getElementById("adminPage").classList.remove("hidden");
            refresh();
        }

        async function apiFetch(url) {
            const r = await fetch(url, {headers: {"Authorization": "Bearer " + token}});
            if (r.status === 401) { sessionStorage.removeItem("agentToken"); location.reload(); }
            return r.json();
        }

        async function refresh() {
            try {
                const s = await apiFetch("/api/status");
                document.getElementById("statusTable").innerHTML = `
                    <tr><td>Agent ID</td><td><code>${s.agent_id || "N/A"}</code></td></tr>
                    <tr><td>VM Name</td><td>${s.vm_name || "N/A"}</td></tr>
                    <tr><td>Status</td><td><span class="status ${s.status}">${s.status}</span></td></tr>
                    <tr><td>Deployment</td><td><code>${s.deployment_id || "None"}</code></td></tr>
                    <tr><td>Control Plane</td><td>${s.control_plane || "N/A"}</td></tr>
                `;

                const c = await apiFetch("/api/containers");
                if (c.containers && c.containers.length > 0) {
                    document.getElementById("containers").innerHTML = "<table>" +
                        c.containers.map(x => `<tr><td>${x.name}</td><td><span class="status ${x.status}">${x.status}</span></td></tr>`).join("") +
                        "</table>";
                } else {
                    document.getElementById("containers").innerHTML = "<em>No containers running</em>";
                }

                loadLogs();
            } catch(e) { console.error(e); }
        }

        async function loadLogs() {
            const level = document.getElementById("logLevel").value;
            const l = await apiFetch("/api/logs?level=" + level);
            const viewer = document.getElementById("logViewer");
            if (l.logs && l.logs.length > 0) {
                viewer.innerHTML = l.logs.map(x => {
                    const t = new Date(x.timestamp).toLocaleTimeString();
                    return `<div class="log-entry ${x.level}">${t} [${x.level.toUpperCase()}] ${x.message}</div>`;
                }).join("");
                viewer.scrollTop = viewer.scrollHeight;
            } else {
                viewer.innerHTML = "No logs";
            }
        }

        setInterval(refresh, 30000);
    </script>
</body>
</html>
"""


class AdminRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for agent admin interface."""

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def _send_response(self, code: int, content: str, content_type: str = "text/html"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content.encode())

    def _send_json(self, code: int, data: dict):
        content = json.dumps(data)
        self._send_response(code, content, "application/json")

    def _check_auth(self) -> bool:
        """Check authorization header."""
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
            return token in _admin_tokens
        return False

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/admin":
            self._send_response(200, ADMIN_HTML)
            return

        if path == "/api/login":
            self._send_json(405, {"error": "Use POST"})
            return

        # Protected endpoints
        if not self._check_auth():
            self._send_json(401, {"error": "Unauthorized"})
            return

        if path == "/api/status":
            self._send_json(
                200,
                {
                    "agent_id": _admin_state["agent_id"],
                    "vm_name": _admin_state["vm_name"],
                    "status": _admin_state["status"],
                    "deployment_id": _admin_state["deployment_id"],
                    "control_plane": CONTROL_PLANE_URL,
                },
            )
            return

        if path == "/api/containers":
            containers = []
            try:
                result = subprocess.run(
                    ["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                for line in result.stdout.strip().split("\n"):
                    if line:
                        parts = line.split("\t")
                        name = parts[0] if parts else "unknown"
                        status_str = parts[1] if len(parts) > 1 else "unknown"
                        status = "healthy" if "Up" in status_str else "unhealthy"
                        containers.append({"name": name, "status": status})
            except Exception:
                pass
            self._send_json(200, {"containers": containers})
            return

        if path.startswith("/api/logs"):
            query = urllib.parse.parse_qs(parsed.query)
            min_level = query.get("level", ["info"])[0]
            level_order = ["debug", "info", "warning", "error"]
            min_idx = level_order.index(min_level) if min_level in level_order else 1
            filtered = [
                log for log in _admin_state["logs"] if level_order.index(log["level"]) >= min_idx
            ]
            self._send_json(200, {"logs": filtered[-200:]})
            return

        self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        if self.path == "/api/login":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode()
            try:
                data = json.loads(body)
                if data.get("password") == ADMIN_PASSWORD:
                    token = secrets.token_urlsafe(32)
                    _admin_tokens.add(token)
                    # Limit tokens
                    if len(_admin_tokens) > 50:
                        _admin_tokens.pop()
                    self._send_json(200, {"token": token})
                else:
                    self._send_json(401, {"error": "Invalid password"})
            except Exception:
                self._send_json(400, {"error": "Invalid request"})
            return

        self._send_json(404, {"error": "Not found"})


def start_admin_server():
    """Start the admin HTTP server in a background thread."""

    class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    try:
        server = ThreadedHTTPServer(("0.0.0.0", ADMIN_PORT), AdminRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        logger.info(f"Admin server started on port {ADMIN_PORT}")
        return server
    except Exception as e:
        logger.warning(f"Failed to start admin server: {e}")
        return None


class ControlPlaneLogHandler(logging.Handler):
    """Custom log handler that buffers logs and sends them to the control plane."""

    def __init__(self):
        super().__init__()
        self._buffer: list[dict] = []
        self._lock = threading.Lock()
        self._agent_id: str | None = None
        self.setLevel(logging.DEBUG)  # Capture all logs

    def set_agent_id(self, agent_id: str):
        """Set the agent ID for log submission."""
        self._agent_id = agent_id

    def emit(self, record: logging.LogRecord):
        """Buffer a log record."""
        try:
            level_name = record.levelname.lower()
            if level_name == "warn":
                level_name = "warning"

            log_entry = {
                "source": "agent",
                "level": level_name,
                "message": self.format(record),
                "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
                "metadata": {
                    "module": record.module,
                    "funcName": record.funcName,
                    "lineno": record.lineno,
                },
            }

            with self._lock:
                self._buffer.append(log_entry)

            # Also add to admin state for local admin UI
            _add_admin_log(level_name, self.format(record))
        except Exception:
            self.handleError(record)

    def flush_to_control_plane(self) -> int:
        """Send buffered logs to control plane. Returns number of logs sent."""
        if not self._agent_id:
            return 0

        with self._lock:
            if not self._buffer:
                return 0
            logs_to_send = self._buffer.copy()
            self._buffer.clear()

        try:
            response = requests.post(
                f"{CONTROL_PLANE_URL}/api/v1/agents/{self._agent_id}/logs",
                json={"logs": logs_to_send},
                timeout=10,
            )
            response.raise_for_status()
            result = response.json()
            return result.get("stored", 0)
        except Exception as e:
            # Put logs back in buffer if send failed
            with self._lock:
                self._buffer = logs_to_send + self._buffer
            logger.debug(f"Failed to send logs: {e}")
            return 0


# Global control plane log handler
cp_log_handler: ControlPlaneLogHandler | None = None


def setup_control_plane_logging():
    """Setup logging to send agent logs to control plane."""
    global cp_log_handler
    cp_log_handler = ControlPlaneLogHandler()
    cp_log_handler.setFormatter(logging.Formatter("%(message)s"))
    logging.getLogger().addHandler(cp_log_handler)


def set_log_agent_id(agent_id: str):
    """Set the agent ID for log submission."""
    global cp_log_handler
    if cp_log_handler:
        cp_log_handler.set_agent_id(agent_id)


def flush_logs() -> int:
    """Flush buffered logs to control plane."""
    global cp_log_handler
    if cp_log_handler:
        return cp_log_handler.flush_to_control_plane()
    return 0


def collect_container_logs(agent_id: str, since_minutes: int = 1) -> list[dict]:
    """Collect docker container logs and return as list of log entries.

    Args:
        agent_id: Agent ID for log attribution
        since_minutes: Collect logs from the last N minutes

    Returns:
        List of log entry dicts
    """
    logs = []

    try:
        # Get list of running containers
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            logger.warning(f"docker ps failed with code {result.returncode}: {result.stderr}")
            return logs

        containers = result.stdout.strip().split("\n")
        containers = [c for c in containers if c]

        if containers:
            logger.debug(f"Found {len(containers)} containers: {containers}")
        else:
            logger.debug("No running containers found")

        for container in containers:
            try:
                # Get logs for this container
                log_result = subprocess.run(
                    ["docker", "logs", "--since", f"{since_minutes}m", "--timestamps", container],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                # Combine stdout and stderr
                output = log_result.stdout + log_result.stderr

                for line in output.strip().split("\n"):
                    if not line:
                        continue

                    # Parse timestamp and message
                    # Docker timestamps look like: 2024-01-15T10:30:00.123456789Z
                    parts = line.split(" ", 1)
                    if len(parts) == 2:
                        timestamp_str, message = parts
                        try:
                            # Parse docker timestamp
                            timestamp_str = timestamp_str.rstrip("Z")
                            if "." in timestamp_str:
                                timestamp_str = timestamp_str[:26]  # Truncate nanoseconds
                            timestamp = datetime.fromisoformat(timestamp_str)
                        except ValueError:
                            timestamp = datetime.now(timezone.utc)
                            message = line
                    else:
                        timestamp = datetime.now(timezone.utc)
                        message = line

                    # Detect log level from message
                    level = "info"
                    msg_lower = message.lower()
                    if "error" in msg_lower or "exception" in msg_lower or "traceback" in msg_lower:
                        level = "error"
                    elif "warn" in msg_lower:
                        level = "warning"
                    elif "debug" in msg_lower:
                        level = "debug"

                    logs.append(
                        {
                            "source": "container",
                            "container_name": container,
                            "level": level,
                            "message": message,
                            "timestamp": timestamp.isoformat()
                            if hasattr(timestamp, "isoformat")
                            else str(timestamp),
                        }
                    )

            except subprocess.TimeoutExpired:
                logger.warning(f"Timeout getting logs for container {container}")
            except Exception as e:
                logger.warning(f"Failed to get logs for container {container}: {e}")

    except subprocess.TimeoutExpired:
        logger.warning("Timeout listing containers")
    except Exception as e:
        logger.warning(f"Failed to list containers: {e}")

    return logs


def send_container_logs(agent_id: str, since_minutes: int = 1) -> int:
    """Collect and send container logs to control plane.

    Args:
        agent_id: Agent ID
        since_minutes: Collect logs from the last N minutes

    Returns:
        Number of logs sent
    """
    logs = collect_container_logs(agent_id, since_minutes)
    if not logs:
        return 0

    try:
        response = requests.post(
            f"{CONTROL_PLANE_URL}/api/v1/agents/{agent_id}/logs",
            json={"logs": logs},
            timeout=10,
        )
        response.raise_for_status()
        result = response.json()
        return result.get("stored", 0)
    except Exception as e:
        logger.warning(f"Failed to send {len(logs)} container logs: {e}")
        return 0


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

    report_id = f"quote_{os.getpid()}_{int(time.time())}"
    report_dir = TSM_REPORT_PATH / report_id

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
    logger.info(f"Generated TDX quote, MRTD: {measurements.get('mrtd', 'unknown')[:32]}...")

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


def poll_control_plane(agent_id: str, intel_ta_token: str | None = None) -> dict:
    """Poll control plane for deployment with optional attestation.

    Args:
        agent_id: Agent ID from registration
        intel_ta_token: Fresh Intel TA token for continuous attestation

    Returns:
        Response dict with deployment and tunnel info
    """
    payload = {}
    if intel_ta_token:
        payload["intel_ta_token"] = intel_ta_token

    response = requests.post(
        f"{CONTROL_PLANE_URL}/api/v1/agents/{agent_id}/poll",
        json=payload,
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def report_status(agent_id: str, status: str, deployment_id: str, error: str = None):
    """Report status to control plane.

    Args:
        agent_id: Agent ID
        status: New status
        deployment_id: Deployment ID being updated
        error: Error message if status is error
    """
    requests.post(
        f"{CONTROL_PLANE_URL}/api/v1/agents/{agent_id}/status",
        json={
            "status": status,
            "deployment_id": deployment_id,
            "error": error,
        },
        timeout=30,
    )


def report_deployed(agent_id: str, deployment_id: str, service_id: str, attestation: dict):
    """Report successful deployment to control plane.

    Args:
        agent_id: Agent ID
        deployment_id: Completed deployment ID
        service_id: Registered service ID
        attestation: Workload attestation
    """
    requests.post(
        f"{CONTROL_PLANE_URL}/api/v1/agents/{agent_id}/deployed",
        json={
            "deployment_id": deployment_id,
            "service_id": service_id,
            "attestation": attestation,
        },
        timeout=30,
    )


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


def handle_deployment(agent_id: str, deployment: dict, tunnel_hostname: str | None = None):
    """Execute a deployment from the control plane.

    Args:
        agent_id: Agent ID
        deployment: Deployment dict with deployment_id, compose, build_context, config
        tunnel_hostname: Optional Cloudflare tunnel hostname for this agent
    """
    deployment_id = deployment["deployment_id"]
    config = deployment.get("config") or {}

    # Update admin state
    _admin_state["deployment_id"] = deployment_id

    logger.info(f"Starting deployment: {deployment_id}")

    # Report status: deploying
    report_status(agent_id, "deploying", deployment_id)

    try:
        # Setup workload from deployment config
        setup_workload_from_deployment(deployment)

        # Run compose
        run_compose(config)

        # Wait for health
        health_status = wait_for_health(config)

        # Generate attestation
        attestation = get_tdx_attestation(config, health_status)

        # Register service with discovery (use tunnel hostname if available)
        service_id = register_service(config, attestation, tunnel_hostname)

        # Report success
        report_deployed(agent_id, deployment_id, service_id, attestation)
        write_status("deployed")
        logger.info(f"Deployment complete: {deployment_id}")

    except requests.exceptions.HTTPError as e:
        # Extract response body for better error messages
        error_detail = str(e)
        if e.response is not None:
            try:
                error_detail = f"{e}: {e.response.text}"
            except Exception:
                pass
        logger.error(f"Deployment failed: {error_detail}")
        report_status(agent_id, "error", deployment_id, error=error_detail)
        write_status("error")
        raise
    except Exception as e:
        logger.error(f"Deployment failed: {e}")
        report_status(agent_id, "error", deployment_id, error=str(e))
        write_status("error")
        raise


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
    """Run in agent mode - poll control plane for deployments.

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

    # Start admin server for local monitoring
    start_admin_server()
    _admin_state["status"] = "starting"

    # Setup logging to control plane
    setup_control_plane_logging()
    logger.info("Log relay enabled")

    logger.info("Starting in AGENT mode")
    logger.info(f"Control plane: {CONTROL_PLANE_URL}")
    logger.info(f"Poll interval: {POLL_INTERVAL}s")

    vm_name = get_vm_name()
    logger.info(f"VM name: {vm_name}")
    _admin_state["vm_name"] = vm_name

    # 1. Generate initial attestation (requires Intel TA - will crash if fails)
    attestation = generate_initial_attestation(config)

    # 2. Register with control plane
    agent_id = None
    cloudflared_proc = None
    tunnel_hostname = None  # Track the tunnel hostname for service registration
    last_log_flush = time.time()
    last_attestation = time.time()  # Track when we last sent attestation
    current_intel_ta_token = attestation["tdx"].get("intel_ta_token")  # Current token
    try:
        reg_response = register_with_control_plane(attestation, vm_name)
        agent_id = reg_response["agent_id"]
        tunnel_hostname = reg_response.get("hostname")

        # Update admin state
        _admin_state["agent_id"] = agent_id
        _admin_state["status"] = "undeployed"

        # Enable log relay now that we have an agent_id
        set_log_agent_id(agent_id)
        logger.info(f"Agent log relay active for {agent_id}")

        # Start cloudflared if we got a tunnel token
        if reg_response.get("tunnel_token"):
            cloudflared_proc = start_cloudflared(reg_response["tunnel_token"])
            if cloudflared_proc and tunnel_hostname:
                logger.info(f"Agent reachable at: https://{tunnel_hostname}")
    except Exception as e:
        logger.error(f"Failed to register with control plane: {e}")
        logger.info("Will retry registration in poll loop...")

    write_status("undeployed")

    # 3. Main loop - poll for work
    while True:
        try:
            # Try to register if not registered
            if agent_id is None:
                try:
                    reg_response = register_with_control_plane(attestation, vm_name)
                    agent_id = reg_response["agent_id"]
                    tunnel_hostname = reg_response.get("hostname")

                    # Update admin state
                    _admin_state["agent_id"] = agent_id
                    _admin_state["status"] = "undeployed"

                    # Enable log relay now that we have an agent_id
                    set_log_agent_id(agent_id)

                    # Start cloudflared if we got a tunnel token (and not already running)
                    if reg_response.get("tunnel_token") and cloudflared_proc is None:
                        cloudflared_proc = start_cloudflared(reg_response["tunnel_token"])
                        if cloudflared_proc and tunnel_hostname:
                            logger.info(f"Agent reachable at: https://{tunnel_hostname}")
                except Exception as e:
                    logger.warning(f"Registration failed, will retry: {e}")
                    time.sleep(POLL_INTERVAL)
                    continue

            # Check if cloudflared is still running
            if cloudflared_proc is not None:
                poll_result = cloudflared_proc.poll()
                if poll_result is not None:
                    logger.warning(
                        f"cloudflared exited with code {poll_result}, will restart on next registration"
                    )
                    cloudflared_proc = None

            # Generate fresh attestation if needed
            token_to_send = None
            if time.time() - last_attestation >= ATTESTATION_INTERVAL:
                try:
                    logger.info("Generating fresh attestation for poll...")
                    fresh_attestation = generate_initial_attestation(config)
                    current_intel_ta_token = fresh_attestation["tdx"].get("intel_ta_token")
                    token_to_send = current_intel_ta_token
                    last_attestation = time.time()
                    logger.info("Fresh attestation generated")
                except Exception as e:
                    logger.warning(f"Failed to generate fresh attestation: {e}")

            # Poll for deployment with attestation
            response = poll_control_plane(agent_id, intel_ta_token=token_to_send)

            # Start cloudflared if poll response includes tunnel info and we don't have it running
            # This handles the case where agent was verified after registration (MRTD trusted later)
            if response.get("tunnel_token") and cloudflared_proc is None:
                tunnel_hostname = response.get("hostname", tunnel_hostname)
                logger.info("Received tunnel token from poll, starting cloudflared...")
                cloudflared_proc = start_cloudflared(response["tunnel_token"])
                if cloudflared_proc and tunnel_hostname:
                    logger.info(f"Agent reachable at: https://{tunnel_hostname}")

            # Handle deployment if available
            if response.get("deployment"):
                try:
                    # Pass tunnel hostname so services can be registered with the public URL
                    handle_deployment(agent_id, response["deployment"], tunnel_hostname)
                except Exception as e:
                    logger.error(f"Deployment failed: {e}")
                    # Continue polling - agent may get another deployment

        except requests.exceptions.ConnectionError as e:
            logger.warning(f"Connection error: {e}")
        except requests.exceptions.Timeout as e:
            logger.warning(f"Request timeout: {e}")
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                # Agent was deleted from control plane - re-register
                logger.warning("Agent not found (404), will re-register...")
                agent_id = None
                if cloudflared_proc is not None:
                    cloudflared_proc.terminate()
                    cloudflared_proc.wait()
                    cloudflared_proc = None
            else:
                logger.exception(f"HTTP error: {e}")
        except Exception as e:
            logger.exception(f"Poll error: {e}")

        # Periodically flush logs to control plane
        if agent_id and time.time() - last_log_flush >= LOG_FLUSH_INTERVAL:
            try:
                # Flush agent logs
                agent_logs_sent = flush_logs()

                # Collect and send container logs
                container_logs_sent = send_container_logs(agent_id, since_minutes=1)

                if agent_logs_sent or container_logs_sent:
                    logger.info(
                        f"Sent {agent_logs_sent} agent logs, {container_logs_sent} container logs"
                    )
            except Exception as e:
                logger.warning(f"Log flush error: {e}")
            finally:
                last_log_flush = time.time()

        time.sleep(POLL_INTERVAL)


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
