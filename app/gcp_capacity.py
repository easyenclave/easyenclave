"""CP-native GCP capacity fulfillment.

This is intentionally self-contained (no gcloud dependency). It uses a GCP
service account JSON key to mint OAuth access tokens and calls the Compute API
to create confidential TDX instances with cloud-init that boots the launcher.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import random
import re
import string
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote as _urlquote

import httpx
import jwt

logger = logging.getLogger(__name__)

_COMPUTE_SCOPE = "https://www.googleapis.com/auth/compute"
_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
_TOKEN_AUD = "https://oauth2.googleapis.com/token"


class GCPProvisionError(RuntimeError):
    pass


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _rand_suffix(length: int = 6) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _sanitize_name(value: str, max_len: int = 63) -> str:
    cleaned = re.sub(r"[^a-z0-9-]", "-", (value or "").strip().lower())
    cleaned = re.sub(r"-+", "-", cleaned).strip("-")
    if not cleaned:
        cleaned = "easyenclave"
    return cleaned[:max_len].strip("-")


def _sanitize_label_value(value: str, max_len: int = 63) -> str:
    return _sanitize_name(value, max_len=max_len)


def _parse_service_account_info(raw: str) -> dict[str, Any]:
    value = (raw or "").strip()
    if not value:
        raise GCPProvisionError("GCP service account key is empty")
    try:
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    # Some deployments store the JSON key base64-encoded.
    try:
        decoded = base64.b64decode(value).decode("utf-8", errors="replace")
        parsed = json.loads(decoded)
        if isinstance(parsed, dict):
            return parsed
    except Exception as exc:
        raise GCPProvisionError(
            f"Invalid GCP service account key (not JSON or b64 JSON): {exc}"
        ) from exc
    raise GCPProvisionError("Invalid GCP service account key")


def _service_account_env() -> str:
    return (
        os.environ.get("GCP_SERVICE_ACCOUNT_KEY")
        or os.environ.get("GCP_SERVICE_ACCOUNT_JSON")
        or ""
    ).strip()


def _project_id_env() -> str:
    return (os.environ.get("GCP_PROJECT_ID") or "").strip()


def _machine_type_for_size(node_size: str) -> str:
    size = (node_size or "").strip().lower()
    if size == "tiny":
        # NOTE: Some GCP zones/TDX offerings do not support the smallest C3 shapes.
        # Default to a known-good baseline; callers can override via EE_GCP_MACHINE_TYPE_TINY.
        return (os.environ.get("EE_GCP_MACHINE_TYPE_TINY") or "c3-standard-4").strip()
    if size == "standard":
        return (os.environ.get("EE_GCP_MACHINE_TYPE_STANDARD") or "c3-standard-4").strip()
    if size == "llm":
        return (os.environ.get("EE_GCP_MACHINE_TYPE_LLM") or "c3-standard-8").strip()
    return (os.environ.get("EE_GCP_MACHINE_TYPE_DEFAULT") or "c3-standard-4").strip()


def _image_project() -> str:
    return (os.environ.get("EE_GCP_IMAGE_PROJECT") or "ubuntu-os-cloud").strip()


def _image_family() -> str:
    return (os.environ.get("EE_GCP_IMAGE_FAMILY") or "ubuntu-2404-lts-amd64").strip()


def _boot_disk_size_gb() -> int:
    raw = (os.environ.get("EE_GCP_BOOT_DISK_GB") or "80").strip()
    try:
        return max(20, int(raw))
    except ValueError:
        return 80


def _boot_disk_type() -> str:
    return (os.environ.get("EE_GCP_BOOT_DISK_TYPE") or "pd-balanced").strip()


def _network() -> str:
    return (os.environ.get("EE_GCP_NETWORK") or "default").strip()


def _launcher_url() -> str:
    # Prefer the pinned SHA URL if available; fall back to a stable path.
    repo = os.environ.get("GITHUB_REPOSITORY", "easyenclave/easyenclave")
    sha = os.environ.get("GITHUB_SHA", "main")
    return f"https://raw.githubusercontent.com/{repo}/{sha}/infra/launcher/launcher.py"


def _cp_url() -> str:
    return (os.environ.get("EASYENCLAVE_CP_URL") or "https://app.easyenclave.com").strip()


def _agent_ita_api_key_env() -> str:
    # Agents need an ITA API key to mint Intel Trust Authority tokens for registration.
    # Prefer a dedicated CP env var for CP-native provisioning; fall back to legacy names.
    return (
        os.environ.get("EE_AGENT_ITA_API_KEY")
        or os.environ.get("ITA_API_KEY")
        or os.environ.get("INTEL_API_KEY")
        or ""
    ).strip()


def _cloud_init_user_data(*, launcher_config: dict[str, Any]) -> str:
    config_json = json.dumps(launcher_config, indent=2)
    launcher_url = _launcher_url()
    return f"""#cloud-config
package_update: true
packages:
  - ca-certificates
  - curl
  - gnupg
  - lsb-release
  - python3
  - python3-requests
  - python3-psutil
  - docker.io
  - docker-compose-plugin
write_files:
  - path: /etc/easyenclave/config.json
    permissions: "0644"
    owner: root:root
    content: |
{_indent_block(config_json, 6)}
  - path: /etc/systemd/system/tdx-launcher.service
    permissions: "0644"
    owner: root:root
    content: |
      [Unit]
      Description=TDX VM Launcher Service
      After=network-online.target docker.service
      Wants=network-online.target docker.service

      [Service]
      Type=simple
      User=root
      WorkingDirectory=/opt/launcher
      ExecStart=/usr/bin/python3 /opt/launcher/launcher.py
      Restart=on-failure
      RestartSec=5
      StandardOutput=journal+console
      StandardError=journal+console

      [Install]
      WantedBy=multi-user.target
runcmd:
  - mkdir -p /opt/launcher /home/tdx /etc/easyenclave
  - [bash, -lc, "curl -fsSL '{launcher_url}' -o /opt/launcher/launcher.py"]
  - chmod +x /opt/launcher/launcher.py
  - systemctl enable --now docker
  - [bash, -lc, "apt-get install -y docker-compose || true"]
  - [bash, -lc, "curl -fsSL -o /tmp/cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb && (dpkg -i /tmp/cloudflared.deb || apt-get install -f -y) && rm -f /tmp/cloudflared.deb || true"]
  - systemctl daemon-reload
  - systemctl enable --now tdx-launcher.service
final_message: "EasyEnclave launcher bootstrap complete"
"""


def _indent_block(value: str, spaces: int) -> str:
    prefix = " " * spaces
    return "\n".join(f"{prefix}{line}" for line in value.splitlines())


async def _oauth_access_token(*, service_account: dict[str, Any]) -> str:
    email = str(service_account.get("client_email") or "").strip()
    key = str(service_account.get("private_key") or "").strip()
    if not email or not key:
        raise GCPProvisionError("Service account JSON missing client_email/private_key")

    now = int(time.time())
    claims = {
        "iss": email,
        "sub": email,
        "aud": _TOKEN_AUD,
        "iat": now,
        "exp": now + 3600,
        "scope": f"{_COMPUTE_SCOPE} {_CLOUD_PLATFORM_SCOPE}",
    }
    assertion = jwt.encode(claims, key, algorithm="RS256")
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": assertion,
    }
    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.post(_TOKEN_AUD, data=data, headers={"Accept": "application/json"})
    if resp.status_code >= 400:
        raise GCPProvisionError(
            f"OAuth token exchange failed (HTTP {resp.status_code}): {(resp.text or '')[:240]}"
        )
    payload = resp.json()
    token = str(payload.get("access_token") or "").strip()
    if not token:
        raise GCPProvisionError("OAuth token exchange returned no access_token")
    return token


async def create_tdx_instance_for_order(
    *,
    order_id: str,
    bootstrap_token: str,
    datacenter: str,
    node_size: str,
) -> str:
    """Create a TDX VM for a launch order. Returns the instance name."""
    project_id = _project_id_env()
    if not project_id:
        raise GCPProvisionError("GCP_PROJECT_ID is not set on the control plane")
    service_account_raw = _service_account_env()
    if not service_account_raw:
        raise GCPProvisionError("GCP_SERVICE_ACCOUNT_KEY is not set on the control plane")

    dc = (datacenter or "").strip().lower()
    zone = ""
    if dc.startswith("gcp:"):
        zone = dc.split(":", 1)[1].strip()
    if not zone:
        zone = (os.environ.get("EE_GCP_DEFAULT_ZONE") or "us-central1-a").strip().lower()
    if not zone:
        raise GCPProvisionError(f"Invalid datacenter '{datacenter}' (missing zone)")

    machine_type = _machine_type_for_size(node_size)
    instance_name = _sanitize_name(f"ee-{node_size}-" + order_id[:8] + "-" + _rand_suffix())

    launcher_config: dict[str, Any] = {
        "mode": "agent",
        "control_plane_url": _cp_url(),
        "node_size": (node_size or "").strip().lower(),
        "cloud_provider": "gcp",
        "availability_zone": zone,
        "region": "-".join(zone.split("-")[:-1]) if "-" in zone else "",
        "datacenter": dc or f"gcp:{zone}",
        "bootstrap_order_id": order_id,
        "bootstrap_token": bootstrap_token,
    }
    ita_key = _agent_ita_api_key_env()
    if ita_key:
        launcher_config["intel_api_key"] = ita_key
    else:
        logger.warning(
            "EE_AGENT_ITA_API_KEY is not set on the control plane; provisioned GCP agents will fail registration "
            "(they must mint Intel Trust Authority tokens)."
        )

    cloud_init = _cloud_init_user_data(launcher_config=launcher_config)

    labels = {
        "easyenclave": "managed",
        "ee-order": _sanitize_label_value(order_id[:24]),
        "ee-node": _sanitize_label_value((node_size or "tiny").lower()),
        "ee-dc": _sanitize_label_value(dc or f"gcp:{zone}"),
    }

    body: dict[str, Any] = {
        "name": instance_name,
        "machineType": f"zones/{zone}/machineTypes/{machine_type}",
        "confidentialInstanceConfig": {"confidentialInstanceType": "TDX"},
        "disks": [
            {
                "boot": True,
                "autoDelete": True,
                "initializeParams": {
                    "sourceImage": f"projects/{_image_project()}/global/images/family/{_image_family()}",
                    "diskSizeGb": str(_boot_disk_size_gb()),
                    "diskType": f"projects/{project_id}/zones/{zone}/diskTypes/{_boot_disk_type()}",
                },
            }
        ],
        "networkInterfaces": [
            {
                "network": f"global/networks/{_network()}",
                "accessConfigs": [{"name": "External NAT", "type": "ONE_TO_ONE_NAT"}],
            }
        ],
        "metadata": {"items": [{"key": "user-data", "value": cloud_init}]},
        "labels": labels,
        "scheduling": {"onHostMaintenance": "TERMINATE"},
    }

    service_account = _parse_service_account_info(service_account_raw)
    token = await _oauth_access_token(service_account=service_account)

    url = f"https://compute.googleapis.com/compute/v1/projects/{_urlquote(project_id)}/zones/{_urlquote(zone)}/instances"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(url, headers=headers, json=body)
    if resp.status_code >= 400:
        raise GCPProvisionError(
            f"GCP instance insert failed (HTTP {resp.status_code}): {(resp.text or '')[:500]}"
        )
    op = resp.json()
    op_name = str(op.get("name") or "").strip()
    if not op_name:
        # Insert succeeded but returned unexpected payload. Still return instance name.
        logger.warning("GCP insert returned no operation name; proceeding without operation poll")
        return instance_name

    # Poll operation briefly to surface immediate errors (quota/capacity/etc).
    op_url = f"https://compute.googleapis.com/compute/v1/projects/{_urlquote(project_id)}/zones/{_urlquote(zone)}/operations/{_urlquote(op_name)}"
    deadline = _utc_now() + timedelta(seconds=120)
    while _utc_now() < deadline:
        async with httpx.AsyncClient(timeout=20.0) as client:
            op_resp = await client.get(op_url, headers=headers)
        if op_resp.status_code >= 400:
            break
        payload = op_resp.json()
        if str(payload.get("status") or "").upper() == "DONE":
            err = payload.get("error")
            if err:
                raise GCPProvisionError(f"GCP operation failed: {json.dumps(err)[:500]}")
            return instance_name
        time.sleep(2)

    return instance_name
