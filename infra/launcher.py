#!/usr/bin/env python3
"""
File-based launcher - watches shared directory for config

Replaces HTTP-based launcher with virtio-fs filesystem sharing.
The host writes config.json to the shared directory before booting the VM.
This launcher reads the config, clones the repo, runs docker compose,
waits for workload health, generates TDX attestation, and writes results
back to the shared directory.

Supports three modes:
- "measure" (default): Run compose, wait for health check, generate attestation
- "persistent": Run compose, optionally wait for health, generate attestation, stay running
- "control-plane": Run the EasyEnclave control plane directly (bootstrap a new network)

Attestation is handled at the VM level (not in workloads), so workloads
only need to expose a /health endpoint.
"""

import base64
import hashlib
import json
import logging
import os
import shutil
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

SHARE_DIR = Path("/mnt/share")
CONFIG_FILE = SHARE_DIR / "config.json"
STATUS_FILE = SHARE_DIR / "status"
ERROR_FILE = SHARE_DIR / "error.log"
ATTESTATION_FILE = SHARE_DIR / "attestation.json"
REGISTRATION_FILE = SHARE_DIR / "registration.json"
WORKLOAD_DIR = Path("/home/tdx/workload")
TSM_REPORT_PATH = Path("/sys/kernel/config/tsm/report")


def write_status(status: str):
    """Write current status to status file"""
    STATUS_FILE.write_text(status)
    logger.info(f"Status: {status}")


def write_error(error: str):
    """Write error message and set status to error"""
    ERROR_FILE.write_text(error)
    write_status("error")
    logger.error(f"Error: {error}")


def wait_for_config() -> dict:
    """Wait for config.json to appear in shared directory"""
    logger.info(f"Waiting for {CONFIG_FILE}...")
    while not CONFIG_FILE.exists():
        time.sleep(1)

    logger.info("Config file found, reading...")
    config = json.loads(CONFIG_FILE.read_text())
    logger.info(f"Config loaded: repo={config.get('repo')}, ref={config.get('ref')}")
    return config


def setup_workload(config: dict):
    """Setup workload directory with compose file from shared directory"""
    write_status("setup")

    # Clean up any previous workload
    if WORKLOAD_DIR.exists():
        subprocess.run(["rm", "-rf", str(WORKLOAD_DIR)], check=True)

    WORKLOAD_DIR.mkdir(parents=True)

    # Copy all workload files from shared directory
    compose_src = SHARE_DIR / "docker-compose.yml"
    if not compose_src.exists():
        raise RuntimeError(f"Compose file not found in shared directory: {compose_src}")

    # Copy compose file and any other config files/directories
    skip_files = {"config.json", "status", "error.log", "attestation.json", "registration.json"}
    for src_path in SHARE_DIR.iterdir():
        if src_path.name in skip_files:
            continue

        dst_path = WORKLOAD_DIR / src_path.name
        if src_path.is_file():
            shutil.copy2(src_path, dst_path)
            logger.info(f"Copied file {src_path.name}")
        elif src_path.is_dir():
            shutil.copytree(src_path, dst_path)
            logger.info(f"Copied directory {src_path.name}/")

    logger.info(f"Workload directory setup complete: {list(WORKLOAD_DIR.iterdir())}")


def run_compose(config: dict):
    """Run docker compose"""
    write_status("building")

    # Compose file is always at WORKLOAD_DIR/docker-compose.yml
    compose_dir = WORKLOAD_DIR
    compose_file = "docker-compose.yml"

    # Run docker compose
    compose_args = config.get("compose_up_args", "--build -d").split()
    cmd = ["docker", "compose", "-f", compose_file, "up"] + compose_args
    logger.info(f"Running: {' '.join(cmd)}")

    result = subprocess.run(cmd, cwd=compose_dir, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"Docker compose failed: {result.stderr}")

    logger.info("Docker compose completed")


def wait_for_health(config: dict) -> dict:
    """Wait for workload health endpoint to be ready"""
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


def compute_compose_hash() -> str:
    """Compute SHA256 hash of the docker-compose.yml file."""
    compose_file = WORKLOAD_DIR / "docker-compose.yml"
    if compose_file.exists():
        return hashlib.sha256(compose_file.read_bytes()).hexdigest()
    return ""


def get_tdx_attestation(config: dict, health_status: dict) -> dict:
    """
    Generate TDX quote and get Intel TA attestation.

    This is called by the launcher after the workload health check passes.
    Attestation happens at the VM level, not in the workload.
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
                # Parse JWT to get verified measurements
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


def run_control_plane(config: dict):
    """Run the EasyEnclave control plane directly.

    This bootstraps a new EasyEnclave network by cloning the repo
    and running docker-compose for the control plane.

    Args:
        config: Launcher config with repo URL, port, etc.
    """
    write_status("control-plane-starting")
    logger.info("Starting in CONTROL PLANE mode")

    repo_url = config.get("easyenclave_repo", "https://github.com/easyenclave/easyenclave.git")
    port = config.get("port", 8080)
    control_plane_dir = Path("/home/tdx/easyenclave")

    # Clone or update the easyenclave repo
    if control_plane_dir.exists():
        logger.info("Updating easyenclave repo...")
        subprocess.run(
            ["git", "pull"],
            cwd=control_plane_dir,
            check=True,
            capture_output=True,
        )
    else:
        logger.info(f"Cloning easyenclave repo from {repo_url}...")
        subprocess.run(
            ["git", "clone", repo_url, str(control_plane_dir)],
            check=True,
            capture_output=True,
        )

    # Generate attestation for the control plane VM
    logger.info("Generating control plane attestation...")
    attestation = get_tdx_attestation(config, {"status": "starting"})

    # Save attestation
    attestation_file = control_plane_dir / "control-plane-attestation.json"
    attestation_file.write_text(json.dumps(attestation, indent=2))
    ATTESTATION_FILE.write_text(json.dumps(attestation, indent=2))
    logger.info("Saved attestation")

    # Run docker-compose
    logger.info("Starting control plane via docker-compose...")
    env = os.environ.copy()
    env["PORT"] = str(port)

    # Stop any existing containers
    subprocess.run(
        ["docker", "compose", "down"],
        cwd=control_plane_dir,
        capture_output=True,
    )

    # Start the control plane
    result = subprocess.run(
        ["docker", "compose", "up", "--build", "-d"],
        cwd=control_plane_dir,
        env=env,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(f"Failed to start control plane: {result.stderr}")

    logger.info("Control plane container started")

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
                    write_status(f"control-plane-ready:{vm_ip}:{port}")
                except Exception:
                    write_status("control-plane-ready")
                break
        except requests.RequestException:
            pass
        time.sleep(2)
    else:
        logger.warning("Control plane health check timeout - may still be starting")
        write_status("control-plane-starting")

    # Monitor and keep running
    logger.info("Monitoring control plane...")
    while True:
        try:
            # Check container status
            result = subprocess.run(
                ["docker", "compose", "ps", "-q"],
                cwd=control_plane_dir,
                capture_output=True,
                text=True,
            )
            if not result.stdout.strip():
                logger.warning("Control plane stopped, restarting...")
                subprocess.run(
                    ["docker", "compose", "up", "-d"],
                    cwd=control_plane_dir,
                    capture_output=True,
                )
        except Exception as e:
            logger.error(f"Monitor error: {e}")

        time.sleep(30)


def register_with_easyenclave(config: dict, attestation: dict) -> dict:
    """
    Register service with EasyEnclave discovery.

    Args:
        config: Configuration dict with service_name, service_url, etc.
        attestation: Attestation dict with TDX measurements and ITA token

    Returns:
        Response dict from EasyEnclave API containing service_id
    """
    easyenclave_url = config.get("easyenclave_url", "https://app.easyenclave.com")

    payload = {
        "name": config["service_name"],
        "description": config.get("service_description", ""),
        "endpoints": {"prod": config["service_url"]},
        "source_repo": config.get("source_repo"),
        "source_commit": config.get("source_commit"),
        "tags": config.get("tags", []),
        "mrtd": attestation["tdx"]["measurements"]["mrtd"],
        "intel_ta_token": attestation["tdx"].get("intel_ta_token"),
    }

    logger.info(f"Registering with EasyEnclave: {easyenclave_url}")
    logger.info(f"Service: {payload['name']} at {payload['endpoints']['prod']}")

    response = requests.post(
        f"{easyenclave_url}/api/v1/register",
        json=payload,
        timeout=30,
    )
    response.raise_for_status()
    result = response.json()

    logger.info(f"Registered with EasyEnclave: service_id={result.get('service_id')}")
    return result


def check_for_updated_launcher():
    """Check if there's an updated launcher in the share directory.

    If launcher.py exists in the share, execute it instead of this one.
    This allows hot-patching the launcher without rebuilding the VM image.
    """
    updated_launcher = SHARE_DIR / "launcher.py"
    if updated_launcher.exists():
        logger.info("Found updated launcher in share directory, executing it...")
        import sys

        # Execute the updated launcher
        exec(
            compile(updated_launcher.read_text(), str(updated_launcher), "exec"),
            {
                "__name__": "__main__",
                "__file__": str(updated_launcher),
            },
        )
        sys.exit(0)


def main():
    """Main entry point"""
    logger.info("TDX File-based Launcher starting...")
    logger.info(f"Share directory: {SHARE_DIR}")

    # Wait for share directory to be mounted
    # The 9P mount may not happen automatically at boot, so try to mount manually
    for attempt in range(60):
        if SHARE_DIR.exists() and SHARE_DIR.is_mount():
            logger.info("Share directory is mounted")
            break
        logger.info("Waiting for share directory to be mounted...")

        # Try to mount manually every few attempts
        if attempt > 0 and attempt % 3 == 0:
            logger.info("Attempting manual mount...")
            result = subprocess.run(
                [
                    "mount",
                    "-t",
                    "9p",
                    "-o",
                    "trans=virtio,version=9p2000.L",
                    "share",
                    str(SHARE_DIR),
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                logger.info("Manual mount succeeded")
            else:
                logger.debug(f"Manual mount failed (may not be ready): {result.stderr}")

        time.sleep(2)

    if not SHARE_DIR.exists() or not SHARE_DIR.is_mount():
        logger.error("Share directory not available after 120s")
        return 1

    # Check for updated launcher in share directory
    check_for_updated_launcher()

    try:
        config = wait_for_config()

        # Check mode: "measure" (default), "persistent", or "control-plane"
        mode = config.get("mode", "measure")
        logger.info(f"Running in '{mode}' mode")

        # Control plane mode - run the EasyEnclave control plane directly
        if mode == "control-plane":
            run_control_plane(config)
            return 0  # run_control_plane runs forever

        # Setup and run compose only if compose file exists
        compose_src = SHARE_DIR / "docker-compose.yml"
        if compose_src.exists():
            setup_workload(config)
            run_compose(config)
        else:
            logger.info("No docker-compose.yml in share directory, skipping workload setup")

        if mode == "persistent":
            # Persistent mode: run compose and generate attestation, then stay running
            # Wait for health check if health_endpoint is configured
            health_status = {"status": "unknown"}
            if config.get("health_endpoint") or config.get("health_url"):
                try:
                    health_status = wait_for_health(config)
                except Exception as e:
                    logger.warning(f"Health check failed in persistent mode: {e}")
                    health_status = {"status": "unhealthy", "error": str(e)}

            # Generate attestation even in persistent mode
            attestation = None
            if config.get("intel_api_key"):
                try:
                    attestation = get_tdx_attestation(config, health_status)
                    ATTESTATION_FILE.write_text(json.dumps(attestation, indent=2))
                    logger.info(f"Attestation written to {ATTESTATION_FILE}")
                except Exception as e:
                    logger.warning(f"Attestation generation failed: {e}")

            # Register with EasyEnclave if service_name and service_url provided
            if config.get("service_name") and config.get("service_url"):
                if attestation is None:
                    logger.warning("Cannot register with EasyEnclave: no attestation available")
                elif not attestation.get("tdx", {}).get("intel_ta_token"):
                    logger.warning("Cannot register with EasyEnclave: no Intel TA token")
                else:
                    try:
                        registration = register_with_easyenclave(config, attestation)
                        REGISTRATION_FILE.write_text(json.dumps(registration, indent=2))
                        logger.info(f"Registration written to {REGISTRATION_FILE}")
                    except Exception as e:
                        logger.error(f"EasyEnclave registration failed: {e}")
                        raise

            write_status("ready")
            logger.info("Persistent mode: VM is ready")
            # Keep running indefinitely for persistent VMs
            while True:
                time.sleep(60)
        else:
            # Measure mode: wait for health, generate attestation
            health_status = wait_for_health(config)

            # Generate attestation at VM level (not in workload)
            attestation = get_tdx_attestation(config, health_status)

            # Write attestation to shared directory
            ATTESTATION_FILE.write_text(json.dumps(attestation, indent=2))
            logger.info(f"Attestation written to {ATTESTATION_FILE}")

            write_status("ready")
            logger.info("Launcher completed successfully")

        return 0
    except Exception as e:
        write_error(str(e))
        logger.exception("Launcher failed")
        raise


if __name__ == "__main__":
    exit(main())
