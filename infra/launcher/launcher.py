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
import json
import logging
import os
import shutil
import struct
import subprocess
import sys
import threading
import time
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
LOG_MIN_LEVEL = os.environ.get("LOG_MIN_LEVEL", "info").lower()  # Default to INFO level
VERSION = "1.0.0"

# Modes
MODE_CONTROL_PLANE = "control-plane"
MODE_AGENT = "agent"

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


class ControlPlaneLogHandler(logging.Handler):
    """Custom log handler that buffers logs and sends them to the control plane."""

    def __init__(self, min_level: str = "info"):
        super().__init__()
        self._buffer: list[dict] = []
        self._lock = threading.Lock()
        self._agent_id: str | None = None
        self._min_level = min_level
        self.setLevel(LOG_LEVEL_MAP.get(min_level, logging.INFO))

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
                json={"logs": logs_to_send, "min_level": self._min_level},
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


def setup_control_plane_logging(min_level: str = "info"):
    """Setup logging to send agent logs to control plane."""
    global cp_log_handler
    cp_log_handler = ControlPlaneLogHandler(min_level)
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
            return logs

        containers = result.stdout.strip().split("\n")
        containers = [c for c in containers if c]

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
                logger.debug(f"Failed to get logs for container {container}: {e}")

    except subprocess.TimeoutExpired:
        logger.warning("Timeout listing containers")
    except Exception as e:
        logger.debug(f"Failed to list containers: {e}")

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
            json={"logs": logs, "min_level": LOG_MIN_LEVEL},
            timeout=10,
        )
        response.raise_for_status()
        result = response.json()
        return result.get("stored", 0)
    except Exception as e:
        logger.debug(f"Failed to send container logs: {e}")
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
        tdx = claims.get("tdx", {})
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
        raise RuntimeError(f"Intel Trust Authority request failed: {e}")

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


def poll_control_plane(agent_id: str) -> dict:
    """Poll control plane for deployment.

    Args:
        agent_id: Agent ID from registration

    Returns:
        Response dict with deployment, update instructions, and/or action
    """
    response = requests.get(
        f"{CONTROL_PLANE_URL}/api/v1/agents/{agent_id}/poll",
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def handle_re_attest(vm_name: str, config: dict) -> dict | None:
    """Handle re-attestation request from control plane.

    Generates fresh TDX attestation and re-registers with the control plane.

    Args:
        vm_name: VM name for re-registration
        config: Launcher config with Intel TA credentials

    Returns:
        New registration response or None if failed
    """
    write_status("re-attesting")
    logger.info("Control plane requested re-attestation...")

    try:
        # Generate fresh TDX attestation (requires Intel TA)
        attestation = generate_initial_attestation(config)
        logger.info("Generated fresh TDX attestation")

        # Re-register with control plane
        reg_response = register_with_control_plane(attestation, vm_name)
        logger.info(f"Re-registered as agent: {reg_response['agent_id']}")

        return reg_response

    except Exception as e:
        logger.error(f"Re-attestation failed: {e}")
        write_status("re-attest-failed")
        return None


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
    build_context = deployment.get("build_context", {})
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

    intel_api_key = config.get("intel_api_key", "")
    intel_api_url = config.get("intel_api_url", "https://api.trustauthority.intel.com")

    # Generate TDX quote
    logger.info("Generating TDX quote...")
    quote_b64 = generate_tdx_quote()

    # Parse local measurements from quote
    measurements = parse_tdx_quote(quote_b64)

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tdx": {
            "quote_b64": quote_b64,
            "measurements": measurements,
        },
        "workload": {
            "compose_hash": f"sha256:{compute_compose_hash()}",
            "health_status": health_status.get("status", "unknown"),
        },
    }

    # Call Intel Trust Authority if API key provided
    if intel_api_key:
        try:
            logger.info("Calling Intel Trust Authority...")
            ita_response = call_intel_trust_authority(quote_b64, intel_api_key, intel_api_url)
            token = ita_response.get("token")
            if token:
                result["tdx"]["intel_ta_token"] = token
                jwt_measurements = parse_jwt_claims(token)
                if jwt_measurements:
                    result["tdx"]["verified_measurements"] = jwt_measurements
                logger.info("Intel TA attestation successful")
        except Exception as e:
            logger.warning(f"Intel TA call failed: {e}")
            result["tdx"]["intel_ta_error"] = str(e)
    else:
        logger.info("No Intel API key - local measurements only")

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
        "tags": config.get("tags", []),
        "mrtd": attestation["tdx"]["measurements"].get("mrtd", ""),
        "intel_ta_token": attestation["tdx"].get("intel_ta_token"),
    }

    logger.info(f"Registering service: {service_name} at {service_url}")

    response = requests.post(
        f"{CONTROL_PLANE_URL}/api/v1/register",
        json=payload,
        timeout=30,
    )
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
    config = deployment.get("config", {})

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

    except Exception as e:
        logger.error(f"Deployment failed: {e}")
        report_status(agent_id, "error", deployment_id, error=str(e))
        write_status("error")
        raise


def handle_self_update():
    """Check GitHub for latest launcher version and update if newer."""
    # TODO: Implement self-update from GitHub releases
    # For now, just log that we would check for updates
    logger.debug("Self-update check: not implemented yet")


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
        tunnels = list_resp.json().get("result", [])

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
    except Exception:
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

    # Setup logging to control plane
    log_min_level = config.get("log_min_level", LOG_MIN_LEVEL)
    setup_control_plane_logging(log_min_level)
    logger.info(f"Log relay enabled (min_level={log_min_level})")

    logger.info("Starting in AGENT mode")
    logger.info(f"Control plane: {CONTROL_PLANE_URL}")
    logger.info(f"Poll interval: {POLL_INTERVAL}s")

    vm_name = get_vm_name()
    logger.info(f"VM name: {vm_name}")

    # 1. Generate initial attestation (requires Intel TA - will crash if fails)
    attestation = generate_initial_attestation(config)

    # 2. Register with control plane
    agent_id = None
    cloudflared_proc = None
    tunnel_hostname = None  # Track the tunnel hostname for service registration
    last_log_flush = time.time()
    try:
        reg_response = register_with_control_plane(attestation, vm_name)
        agent_id = reg_response["agent_id"]
        tunnel_hostname = reg_response.get("hostname")

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

            # Poll for deployment
            response = poll_control_plane(agent_id)

            # Handle re-attestation request (attestation failed on control plane)
            if response.get("action") == "re_attest":
                logger.warning(f"Received re_attest action: {response.get('message')}")
                reg_response = handle_re_attest(vm_name, config)
                if reg_response:
                    # Update agent_id and tunnel info from new registration
                    agent_id = reg_response["agent_id"]
                    tunnel_hostname = reg_response.get("hostname")

                    # Update log relay with new agent_id
                    set_log_agent_id(agent_id)

                    # Restart cloudflared with new tunnel token if provided
                    if reg_response.get("tunnel_token"):
                        if cloudflared_proc is not None:
                            cloudflared_proc.terminate()
                            cloudflared_proc.wait()
                        cloudflared_proc = start_cloudflared(reg_response["tunnel_token"])
                        if cloudflared_proc and tunnel_hostname:
                            logger.info(f"Agent reachable at: https://{tunnel_hostname}")

                    write_status("undeployed")
                else:
                    # Re-attestation failed, wait and retry
                    logger.error("Re-attestation failed, will retry...")
                    time.sleep(POLL_INTERVAL)
                continue

            # Handle deployment if available
            if response.get("deployment"):
                try:
                    # Pass tunnel hostname so services can be registered with the public URL
                    handle_deployment(agent_id, response["deployment"], tunnel_hostname)
                except Exception as e:
                    logger.error(f"Deployment failed: {e}")
                    # Continue polling - agent may get another deployment

            # Handle self-update if requested
            if response.get("update", {}).get("check_github"):
                handle_self_update()

        except requests.exceptions.ConnectionError as e:
            logger.warning(f"Connection error: {e}")
        except requests.exceptions.Timeout as e:
            logger.warning(f"Request timeout: {e}")
        except Exception as e:
            logger.error(f"Poll error: {e}")

        # Periodically flush logs to control plane
        if agent_id and time.time() - last_log_flush >= LOG_FLUSH_INTERVAL:
            try:
                # Flush agent logs
                agent_logs_sent = flush_logs()

                # Collect and send container logs
                container_logs_sent = send_container_logs(agent_id, since_minutes=1)

                if agent_logs_sent or container_logs_sent:
                    logger.debug(
                        f"Sent {agent_logs_sent} agent logs, {container_logs_sent} container logs"
                    )
            except Exception as e:
                logger.debug(f"Log flush error: {e}")
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
