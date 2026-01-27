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

The mode is determined by config.json in /mnt/share (set by tdx_cli.py).
"""

import base64
import hashlib
import json
import logging
import os
import struct
import subprocess
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
VERSION = "1.0.0"

# Modes
MODE_CONTROL_PLANE = "control-plane"
MODE_AGENT = "agent"

# Paths
WORKLOAD_DIR = Path("/home/tdx/workload")
TSM_REPORT_PATH = Path("/sys/kernel/config/tsm/report")
CONTROL_PLANE_DIR = Path("/home/tdx/easyenclave")

# For config from host via 9p filesystem
SHARE_DIR = Path("/mnt/share")
CONFIG_FILE = SHARE_DIR / "config.json"
STATUS_FILE = SHARE_DIR / "status"


def mount_share_dir():
    """Mount the 9p shared directory from host."""
    if SHARE_DIR.exists() and list(SHARE_DIR.iterdir()):
        logger.info("Share directory already mounted")
        return True

    SHARE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["mount", "-t", "9p", "-o", "trans=virtio", "share", str(SHARE_DIR)],
            check=True,
            capture_output=True,
            text=True,
        )
        logger.info("Mounted share directory")
        return True
    except subprocess.CalledProcessError as e:
        logger.warning(f"Could not mount share directory: {e}")
        return False


def get_launcher_config() -> dict:
    """Read launcher config from shared directory.

    Returns:
        Config dict with mode and other settings
    """
    mount_share_dir()

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
    """Write status for monitoring."""
    try:
        if SHARE_DIR.exists():
            STATUS_FILE.write_text(status)
    except Exception:
        pass
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


def generate_initial_attestation() -> dict:
    """Generate initial TDX attestation for registration."""
    write_status("attesting")
    logger.info("Generating initial TDX attestation...")

    try:
        quote_b64 = generate_tdx_quote()
        measurements = parse_tdx_quote(quote_b64)

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tdx": {
                "quote_b64": quote_b64,
                "measurements": measurements,
            },
        }
    except Exception as e:
        logger.warning(f"TDX attestation failed: {e}")
        # Return empty attestation for non-TDX environments
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tdx": {
                "measurements": {},
                "error": str(e),
            },
        }


def register_with_control_plane(attestation: dict, vm_name: str) -> str:
    """Register agent with the control plane.

    Args:
        attestation: Initial TDX attestation
        vm_name: VM name for identification

    Returns:
        Agent ID from control plane
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
    logger.info(f"Registered as agent: {agent_id}")
    return agent_id


def poll_control_plane(agent_id: str) -> dict:
    """Poll control plane for deployment.

    Args:
        agent_id: Agent ID from registration

    Returns:
        Response dict with deployment and/or update instructions
    """
    response = requests.get(
        f"{CONTROL_PLANE_URL}/api/v1/agents/{agent_id}/poll",
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


def register_service(config: dict, attestation: dict) -> str:
    """Register service with EasyEnclave discovery.

    Args:
        config: Configuration dict with service_name, service_url, etc.
        attestation: Attestation dict with TDX measurements

    Returns:
        Service ID from registration
    """
    service_name = config.get("service_name")
    service_url = config.get("service_url")

    if not service_name or not service_url:
        logger.info("No service_name or service_url - skipping registration")
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


def handle_deployment(agent_id: str, deployment: dict):
    """Execute a deployment from the control plane.

    Args:
        agent_id: Agent ID
        deployment: Deployment dict with deployment_id, compose, build_context, config
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

        # Register service with discovery
        service_id = register_service(config, attestation)

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


def run_control_plane_mode(config: dict):
    """Run the control plane directly in this VM.

    This mode is used to bootstrap a new EasyEnclave network.
    The control plane runs via docker-compose.

    Args:
        config: Launcher config with repo URL, port, etc.
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
    attestation = generate_initial_attestation()

    # Save attestation to a file for reference
    attestation_file = CONTROL_PLANE_DIR / "control-plane-attestation.json"
    attestation_file.write_text(json.dumps(attestation, indent=2))
    logger.info(f"Saved attestation to {attestation_file}")

    # Run docker-compose
    logger.info("Starting control plane via docker-compose...")
    env = os.environ.copy()
    env["PORT"] = str(port)

    # Stop any existing containers
    subprocess.run(
        ["docker", "compose", "down"],
        cwd=CONTROL_PLANE_DIR,
        capture_output=True,
    )

    # Start the control plane
    result = subprocess.run(
        ["docker", "compose", "up", "--build", "-d"],
        cwd=CONTROL_PLANE_DIR,
        env=env,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        logger.error(f"Docker compose failed: {result.stderr}")
        write_status("control-plane-error")
        raise RuntimeError(f"Failed to start control plane: {result.stderr}")

    logger.info("Control plane started")
    write_status("control-plane-running")

    # Wait for health check
    health_url = f"http://localhost:{port}/health"
    logger.info(f"Waiting for control plane health: {health_url}")

    for _attempt in range(60):
        try:
            response = requests.get(health_url, timeout=5)
            if response.ok:
                logger.info("Control plane is healthy!")

                # Get the VM's IP for logging
                try:
                    ip_result = subprocess.run(
                        ["hostname", "-I"],
                        capture_output=True,
                        text=True,
                    )
                    vm_ip = ip_result.stdout.strip().split()[0]
                    logger.info(f"Control plane available at: http://{vm_ip}:{port}")
                    logger.info(f"API docs at: http://{vm_ip}:{port}/docs")

                    # Write URL to status file
                    write_status(f"control-plane-ready:{vm_ip}:{port}")
                except Exception:
                    pass

                break
        except requests.RequestException:
            pass
        time.sleep(2)
    else:
        logger.warning("Control plane health check timeout - may still be starting")

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

    logger.info("Starting in AGENT mode")
    logger.info(f"Control plane: {CONTROL_PLANE_URL}")
    logger.info(f"Poll interval: {POLL_INTERVAL}s")

    vm_name = get_vm_name()
    logger.info(f"VM name: {vm_name}")

    # 1. Generate initial attestation
    attestation = generate_initial_attestation()

    # 2. Register with control plane
    try:
        agent_id = register_with_control_plane(attestation, vm_name)
    except Exception as e:
        logger.error(f"Failed to register with control plane: {e}")
        logger.info("Will retry registration in poll loop...")
        agent_id = None

    write_status("undeployed")

    # 3. Main loop - poll for work
    while True:
        try:
            # Try to register if not registered
            if agent_id is None:
                try:
                    agent_id = register_with_control_plane(attestation, vm_name)
                except Exception as e:
                    logger.warning(f"Registration failed, will retry: {e}")
                    time.sleep(POLL_INTERVAL)
                    continue

            # Poll for deployment
            response = poll_control_plane(agent_id)

            # Handle deployment if available
            if response.get("deployment"):
                try:
                    handle_deployment(agent_id, response["deployment"])
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
