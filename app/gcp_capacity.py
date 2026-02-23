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
import urllib.parse
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


def _sanitize_optional_label_value(value: str, max_len: int = 63) -> str:
    cleaned = re.sub(r"[^a-z0-9-_]", "-", (value or "").strip().lower())
    cleaned = re.sub(r"[-_]{2,}", "-", cleaned).strip("-_")
    return cleaned[:max_len].strip("-_")


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


def _zone_from_datacenter(datacenter: str) -> str:
    dc = (datacenter or "").strip().lower()
    zone = ""
    if dc.startswith("gcp:"):
        zone = dc.split(":", 1)[1].strip()
    if not zone:
        zone = (os.environ.get("EE_GCP_DEFAULT_ZONE") or "us-central1-a").strip().lower()
    return zone


def _machine_type_for_size(node_size: str) -> str:
    # Back-compat: keep the old single-value API.
    return _machine_types_for_size(node_size)[0]


def _machine_types_for_size(node_size: str) -> list[str]:
    """Return a list of machine types to try, in order.

    Some zones don't support all TDX-capable machine types (or have transient
    capacity). Allow a comma-separated fallback list via env, and keep sane
    defaults for CI.
    """

    def _csv(value: str) -> list[str]:
        return [x.strip() for x in (value or "").split(",") if x.strip()]

    size = (node_size or "").strip().lower()
    if size == "tiny":
        raw = os.environ.get("EE_GCP_MACHINE_TYPE_TINY") or "c3-standard-4,c3-standard-8"
        return _csv(raw) or ["c3-standard-4", "c3-standard-8"]
    if size == "standard":
        raw = os.environ.get("EE_GCP_MACHINE_TYPE_STANDARD") or "c3-standard-4,c3-standard-8"
        return _csv(raw) or ["c3-standard-4", "c3-standard-8"]
    if size == "llm":
        # Prefer smaller shapes first to reduce the chance of hitting project-wide CPU quotas.
        raw = os.environ.get("EE_GCP_MACHINE_TYPE_LLM") or "c3-standard-4,c3-standard-8"
        return _csv(raw) or ["c3-standard-4", "c3-standard-8"]
    raw = os.environ.get("EE_GCP_MACHINE_TYPE_DEFAULT") or "c3-standard-4,c3-standard-8"
    return _csv(raw) or ["c3-standard-4", "c3-standard-8"]


def _image_project() -> str:
    return (
        os.environ.get("EE_GCP_IMAGE_PROJECT") or os.environ.get("GCP_PROJECT_ID") or ""
    ).strip()


def _image_family() -> str:
    return (os.environ.get("EE_GCP_IMAGE_FAMILY") or "").strip()


def _image_name() -> str:
    return (os.environ.get("EE_GCP_IMAGE_NAME") or "").strip()


def _boot_disk_size_gb() -> int:
    raw = (os.environ.get("EE_GCP_BOOT_DISK_GB") or "200").strip()
    try:
        return max(20, int(raw))
    except ValueError:
        return 200


def _boot_disk_type() -> str:
    return (os.environ.get("EE_GCP_BOOT_DISK_TYPE") or "pd-balanced").strip()


def _network() -> str:
    return (os.environ.get("EE_GCP_NETWORK") or "default").strip()


def _boot_source_image_params() -> dict[str, str]:
    """Return source image selector for Compute API initializeParams.

    Production can pin an exact release image via EE_GCP_IMAGE_NAME.
    Otherwise an explicit family must be set via EE_GCP_IMAGE_FAMILY.
    """
    name = _image_name()
    family = _image_family()
    project = _image_project()
    if not project:
        raise GCPProvisionError(
            "EE_GCP_IMAGE_PROJECT (or GCP_PROJECT_ID) must be set for GCP capacity image source"
        )
    if name:
        return {"sourceImage": f"projects/{project}/global/images/{name}"}
    if family:
        return {"sourceImage": f"projects/{project}/global/images/family/{family}"}
    raise GCPProvisionError(
        "Missing GCP image selector: set EE_GCP_IMAGE_NAME or EE_GCP_IMAGE_FAMILY."
    )


def _is_stock_ubuntu_source(*, image_project: str, image_family: str, image_name: str) -> bool:
    project = (image_project or "").strip().lower()
    family = (image_family or "").strip().lower()
    name = (image_name or "").strip().lower()
    if project == "ubuntu-os-cloud":
        return True
    if family.startswith("ubuntu-"):
        return True
    if name.startswith("ubuntu-"):
        return True
    return False


def _launcher_url() -> str:
    # Prefer the pinned SHA URL if available; fall back to a stable path.
    repo = os.environ.get("GITHUB_REPOSITORY", "easyenclave/easyenclave")
    sha = os.environ.get("GITHUB_SHA", "main")
    return f"https://raw.githubusercontent.com/{repo}/{sha}/infra/launcher/launcher.py"


def _cp_url() -> str:
    return (os.environ.get("EASYENCLAVE_CP_URL") or "https://app.easyenclave.com").strip()


def _network_name_env() -> str:
    return _sanitize_optional_label_value(os.environ.get("EASYENCLAVE_NETWORK_NAME") or "")


def _environment_env() -> str:
    return _sanitize_optional_label_value(
        os.environ.get("EASYENCLAVE_ENV") or os.environ.get("ENVIRONMENT") or ""
    )


def _cp_boot_id_env() -> str:
    return _sanitize_optional_label_value(os.environ.get("EASYENCLAVE_BOOT_ID") or "")


def _cp_host_env() -> str:
    cp_url = _cp_url()
    if not cp_url:
        return ""
    try:
        host = urllib.parse.urlparse(cp_url).hostname or ""
    except Exception:
        host = ""
    return _sanitize_optional_label_value(host)


def _release_tag_env() -> str:
    return _sanitize_optional_label_value(
        os.environ.get("EASYENCLAVE_RELEASE_TAG") or os.environ.get("RELEASE_TAG") or ""
    )


def _git_sha_env() -> str:
    return _sanitize_optional_label_value(
        os.environ.get("EASYENCLAVE_GIT_SHA") or os.environ.get("GITHUB_SHA") or ""
    )


def _ownership_scope_labels() -> dict[str, str]:
    labels: dict[str, str] = {}
    network = _network_name_env()
    if network:
        labels["ee-network"] = network
    env_name = _environment_env()
    if env_name:
        labels["ee-env"] = env_name
    cp_boot_id = _cp_boot_id_env()
    if cp_boot_id:
        labels["ee-cp-boot"] = cp_boot_id
    cp_host = _cp_host_env()
    if cp_host:
        labels["ee-cp-host"] = cp_host
    release_tag = _release_tag_env()
    if release_tag:
        # Keep both key styles for backward/forward compatibility with filters.
        labels["ee-release"] = release_tag
        labels["ee_release"] = release_tag
    git_sha = _git_sha_env()
    if git_sha:
        labels["ee-git-sha"] = git_sha
        labels["ee_git_sha"] = git_sha
    return labels


def _instance_owned_by_current_scope(labels: dict[str, Any] | None) -> bool:
    expected_network = _network_name_env()
    if not expected_network:
        return False
    raw_labels = labels if isinstance(labels, dict) else {}
    network_label = _sanitize_optional_label_value(str(raw_labels.get("ee-network") or ""))
    if network_label != expected_network:
        return False
    expected_env = _environment_env()
    if expected_env:
        env_label = _sanitize_optional_label_value(str(raw_labels.get("ee-env") or ""))
        if env_label != expected_env:
            return False
    return True


def _agent_ita_api_key_env() -> str:
    # Agents need an ITA API key to mint Intel Trust Authority tokens for registration.
    # Prefer a dedicated CP env var for CP-native provisioning; fall back to legacy names.
    return (
        os.environ.get("EE_AGENT_ITA_API_KEY")
        or os.environ.get("ITA_API_KEY")
        or os.environ.get("INTEL_API_KEY")
        or ""
    ).strip()


def _agent_disconnect_self_terminate_seconds() -> int:
    raw = (
        os.environ.get("AGENT_CLOUD_DISCONNECT_SELF_TERMINATE_SECONDS")
        or os.environ.get("EE_AGENT_DISCONNECT_SELF_TERMINATE_SECONDS")
        or "300"
    ).strip()
    try:
        return max(0, int(raw))
    except ValueError:
        return 300


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
    zone = _zone_from_datacenter(dc)
    if not zone:
        raise GCPProvisionError(f"Invalid datacenter '{datacenter}' (missing zone)")

    machine_types = _machine_types_for_size(node_size)
    instance_name = _sanitize_name(f"ee-{node_size}-" + order_id[:8] + "-" + _rand_suffix())
    image_project = _image_project()
    image_family = _image_family()
    image_name = _image_name()
    env_name = (os.environ.get("EASYENCLAVE_ENV") or "").strip().lower()
    if env_name == "production" and _is_stock_ubuntu_source(
        image_project=image_project,
        image_family=image_family,
        image_name=image_name,
    ):
        raise GCPProvisionError(
            "Refusing to provision production GCP capacity from stock Ubuntu image source. "
            "Set EE_GCP_IMAGE_PROJECT and EE_GCP_IMAGE_NAME/EE_GCP_IMAGE_FAMILY to an EasyEnclave image."
        )

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
        "disconnect_self_terminate_seconds": _agent_disconnect_self_terminate_seconds(),
    }
    network_name = (os.environ.get("EASYENCLAVE_NETWORK_NAME") or "").strip()
    if network_name:
        launcher_config["easyenclave_network_name"] = network_name
    env_name = (os.environ.get("EASYENCLAVE_ENV") or "").strip()
    if env_name:
        launcher_config["easyenclave_env"] = env_name
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
    labels.update(_ownership_scope_labels())

    body: dict[str, Any] = {
        "name": instance_name,
        # machineType will be filled per-attempt below.
        "machineType": "",
        "confidentialInstanceConfig": {"confidentialInstanceType": "TDX"},
        "disks": [
            {
                "boot": True,
                "autoDelete": True,
                "initializeParams": {
                    **_boot_source_image_params(),
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
        "scheduling": {"onHostMaintenance": "TERMINATE", "automaticRestart": False},
    }

    service_account = _parse_service_account_info(service_account_raw)
    token = await _oauth_access_token(service_account=service_account)

    url = f"https://compute.googleapis.com/compute/v1/projects/{_urlquote(project_id)}/zones/{_urlquote(zone)}/instances"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    last_err: str | None = None
    for machine_type in machine_types:
        body["machineType"] = f"zones/{zone}/machineTypes/{machine_type}"
        logger.info(
            "Creating GCP TDX instance for order %s in %s with machineType=%s",
            order_id[:8],
            zone,
            machine_type,
        )
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(url, headers=headers, json=body)
        if resp.status_code >= 400:
            last_err = f"HTTP {resp.status_code}: {(resp.text or '')[:500]}"
            logger.warning("GCP insert failed for machineType=%s: %s", machine_type, last_err)
            continue

        op = resp.json()
        op_name = str(op.get("name") or "").strip()
        if not op_name:
            # Insert succeeded but returned unexpected payload. Still return instance name.
            logger.warning(
                "GCP insert returned no operation name for machineType=%s; proceeding without op poll",
                machine_type,
            )
            return instance_name

        # Poll operation briefly to surface immediate errors (quota/capacity/etc).
        op_url = f"https://compute.googleapis.com/compute/v1/projects/{_urlquote(project_id)}/zones/{_urlquote(zone)}/operations/{_urlquote(op_name)}"
        deadline = _utc_now() + timedelta(seconds=120)
        while _utc_now() < deadline:
            async with httpx.AsyncClient(timeout=20.0) as client:
                op_resp = await client.get(op_url, headers=headers)
            if op_resp.status_code >= 400:
                last_err = f"op poll HTTP {op_resp.status_code}: {(op_resp.text or '')[:240]}"
                break
            payload = op_resp.json()
            if str(payload.get("status") or "").upper() == "DONE":
                err = payload.get("error")
                if err:
                    last_err = f"op failed: {json.dumps(err)[:500]}"
                    break
                return instance_name
            time.sleep(2)

        logger.warning(
            "GCP operation did not complete cleanly for machineType=%s: %s", machine_type, last_err
        )

    raise GCPProvisionError(
        f"GCP instance insert failed for all machine types {machine_types!r}: {last_err or 'unknown error'}"
    )


async def delete_instance(
    *,
    datacenter: str,
    instance_name: str,
) -> bool:
    """Delete a GCP instance by name. Returns True if a delete was issued.

    Returns False when the instance is already absent.
    """
    project_id = _project_id_env()
    if not project_id:
        raise GCPProvisionError("GCP_PROJECT_ID is not set on the control plane")
    service_account_raw = _service_account_env()
    if not service_account_raw:
        raise GCPProvisionError("GCP_SERVICE_ACCOUNT_KEY is not set on the control plane")

    name = (instance_name or "").strip().lower()
    if not name:
        raise GCPProvisionError("instance_name is required")

    zone = _zone_from_datacenter(datacenter)
    if not zone:
        raise GCPProvisionError(f"Invalid datacenter '{datacenter}' (missing zone)")

    service_account = _parse_service_account_info(service_account_raw)
    token = await _oauth_access_token(service_account=service_account)
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    base_url = (
        f"https://compute.googleapis.com/compute/v1/projects/{_urlquote(project_id)}"
        f"/zones/{_urlquote(zone)}/instances/{_urlquote(name)}"
    )
    async with httpx.AsyncClient(timeout=30.0) as client:
        get_resp = await client.get(base_url, headers=headers)
        if get_resp.status_code == 404:
            return False
        if get_resp.status_code >= 400:
            raise GCPProvisionError(
                f"GCP instance lookup failed (HTTP {get_resp.status_code}): {(get_resp.text or '')[:240]}"
            )

        del_resp = await client.delete(base_url, headers=headers)

    if del_resp.status_code == 404:
        return False
    if del_resp.status_code >= 400:
        raise GCPProvisionError(
            f"GCP instance delete failed (HTTP {del_resp.status_code}): {(del_resp.text or '')[:500]}"
        )

    op_name = str((del_resp.json() or {}).get("name") or "").strip()
    if not op_name:
        return True

    op_url = (
        f"https://compute.googleapis.com/compute/v1/projects/{_urlquote(project_id)}"
        f"/zones/{_urlquote(zone)}/operations/{_urlquote(op_name)}"
    )
    deadline = _utc_now() + timedelta(seconds=120)
    while _utc_now() < deadline:
        async with httpx.AsyncClient(timeout=20.0) as client:
            op_resp = await client.get(op_url, headers=headers)
        if op_resp.status_code >= 400:
            raise GCPProvisionError(
                f"GCP delete op poll failed (HTTP {op_resp.status_code}): {(op_resp.text or '')[:240]}"
            )
        payload = op_resp.json() or {}
        if str(payload.get("status") or "").upper() == "DONE":
            err = payload.get("error")
            if err:
                raise GCPProvisionError(f"GCP delete op failed: {json.dumps(err)[:500]}")
            return True
        time.sleep(2)
    return True


async def list_managed_instances(*, owned_only: bool = True) -> list[dict[str, Any]]:
    """List CP-managed GCP instances across zones.

    Returns lightweight inventory rows:
      - name
      - zone
      - datacenter
      - status
      - creation_timestamp
      - labels
    """
    if owned_only and not _network_name_env():
        logger.warning(
            "Skipping managed GCP inventory because EASYENCLAVE_NETWORK_NAME is not set; "
            "ownership-safe filtering cannot be applied."
        )
        return []

    project_id = _project_id_env()
    if not project_id:
        raise GCPProvisionError("GCP_PROJECT_ID is not set on the control plane")
    service_account_raw = _service_account_env()
    if not service_account_raw:
        raise GCPProvisionError("GCP_SERVICE_ACCOUNT_KEY is not set on the control plane")

    service_account = _parse_service_account_info(service_account_raw)
    token = await _oauth_access_token(service_account=service_account)
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    results: list[dict[str, Any]] = []
    page_token = ""
    while True:
        url = (
            "https://compute.googleapis.com/compute/v1/projects/"
            f"{_urlquote(project_id)}/aggregated/instances"
        )
        params: dict[str, str] = {"maxResults": "500"}
        if page_token:
            params["pageToken"] = page_token

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=headers, params=params)
        if resp.status_code >= 400:
            raise GCPProvisionError(
                f"GCP instance aggregated list failed (HTTP {resp.status_code}): {(resp.text or '')[:240]}"
            )

        payload = resp.json() or {}
        items = payload.get("items") or {}
        if isinstance(items, dict):
            for zone_block in items.values():
                if not isinstance(zone_block, dict):
                    continue
                for inst in zone_block.get("instances") or []:
                    if not isinstance(inst, dict):
                        continue
                    labels = inst.get("labels") or {}
                    if str(labels.get("easyenclave") or "").strip().lower() != "managed":
                        continue
                    if owned_only and not _instance_owned_by_current_scope(labels):
                        continue

                    name = str(inst.get("name") or "").strip()
                    zone_path = str(inst.get("zone") or "")
                    zone = zone_path.rsplit("/", 1)[-1] if zone_path else ""
                    results.append(
                        {
                            "name": name,
                            "zone": zone,
                            "datacenter": f"gcp:{zone}" if zone else "gcp",
                            "status": str(inst.get("status") or "").strip().lower(),
                            "creation_timestamp": str(inst.get("creationTimestamp") or "").strip(),
                            "labels": labels,
                        }
                    )

        page_token = str(payload.get("nextPageToken") or "").strip()
        if not page_token:
            break

    return results
