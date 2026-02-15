#!/usr/bin/env python3
"""Provision and manage EasyEnclave cloud agent VMs on GCP/Azure.

This script is intended for CI workflows:
- provision confidential VMs with cloud-init launcher bootstrap
- inventory managed resources
- cleanup managed resources (including attached NIC/PIP/disks on Azure)
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import string
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _rand_suffix(length: int = 6) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))


def _sanitize_name(value: str, max_len: int = 63) -> str:
    cleaned = re.sub(r"[^a-z0-9-]", "-", value.strip().lower())
    cleaned = re.sub(r"-+", "-", cleaned).strip("-")
    if not cleaned:
        cleaned = "easyenclave"
    return cleaned[:max_len].strip("-")


def _sanitize_label_value(value: str, max_len: int = 63) -> str:
    return _sanitize_name(value, max_len=max_len)


def _run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(cmd, text=True, capture_output=True)
    if check and result.returncode != 0:
        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        detail = stderr or stdout or f"exit={result.returncode}"
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{detail}")
    return result


def _json_cmd(cmd: list[str]) -> Any:
    result = _run(cmd)
    raw = (result.stdout or "").strip()
    if not raw:
        return None
    return json.loads(raw)


def _cp_headers(cp_admin_token: str = "") -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "User-Agent": "easyenclave-cloud-provisioner/1.0",
    }
    token = cp_admin_token.strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _cp_get_json(*, cp_url: str, path: str, cp_admin_token: str = "", timeout_seconds: int = 30) -> Any:
    url = f"{cp_url.rstrip('/')}{path}"
    req = urllib.request.Request(url, headers=_cp_headers(cp_admin_token))
    with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
        raw = resp.read().decode()
    if not raw.strip():
        return {}
    return json.loads(raw)


def _cp_post_json(
    *,
    cp_url: str,
    path: str,
    body: dict[str, Any],
    cp_admin_token: str = "",
    timeout_seconds: int = 30,
) -> Any:
    url = f"{cp_url.rstrip('/')}{path}"
    data = json.dumps(body).encode("utf-8")
    headers = {
        **_cp_headers(cp_admin_token),
        "Content-Type": "application/json",
    }
    req = urllib.request.Request(url, headers=headers, data=data, method="POST")
    with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
        raw = resp.read().decode()
    if not raw.strip():
        return {}
    return json.loads(raw)


def _http_error_detail(exc: urllib.error.HTTPError) -> str:
    detail = f"HTTP {exc.code}"
    try:
        body = exc.read().decode("utf-8", errors="replace").strip()
    except Exception:
        body = ""
    if body:
        body_single = re.sub(r"\s+", " ", body)
        detail = f"{detail}: {body_single[:240]}"
    return detail


def _maybe_int(value: str) -> int | None:
    value = value.strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _extract_azure_zone_suffix(zone_label: str) -> str:
    # Examples: eastus2-1 -> 1, westus3-2 -> 2
    parts = zone_label.strip().split("-")
    if parts and parts[-1].isdigit():
        return parts[-1]
    return ""


def _build_datacenter(*, provider: str, zone: str, region: str, explicit: str) -> str:
    if explicit.strip():
        return explicit.strip().lower()
    provider_norm = provider.strip().lower()
    zone_norm = zone.strip().lower()
    region_norm = region.strip().lower()
    if zone_norm:
        return f"{provider_norm}:{zone_norm}"
    if region_norm:
        return f"{provider_norm}:{region_norm}"
    return provider_norm


def _build_launcher_config(
    *,
    cp_url: str,
    intel_api_key: str,
    node_size: str,
    provider: str,
    zone: str,
    region: str,
    datacenter: str,
) -> dict[str, str]:
    return {
        "mode": "agent",
        "control_plane_url": cp_url,
        "intel_api_key": intel_api_key,
        "node_size": node_size,
        "cloud_provider": provider,
        "availability_zone": zone,
        "region": region,
        "datacenter": datacenter,
    }


def _cloud_init_user_data(*, launcher_url: str, launcher_config: dict[str, str]) -> str:
    config_json_pretty = json.dumps(launcher_config, indent=2)

    # Keep this boot sequence explicit and linear for easier debugging in serial logs.
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
    permissions: \"0644\"
    owner: root:root
    content: |
{_indent_block(config_json_pretty, 6)}
  - path: /etc/systemd/system/tdx-launcher.service
    permissions: \"0644\"
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
  - [bash, -lc, \"curl -fsSL '{launcher_url}' -o /opt/launcher/launcher.py\"]
  - chmod +x /opt/launcher/launcher.py
  - systemctl enable --now docker
  # cloudflared is optional for agent registration; failures here should not block launcher startup.
  - [bash, -lc, \"curl -fsSL -o /tmp/cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb && (dpkg -i /tmp/cloudflared.deb || apt-get install -f -y) && rm -f /tmp/cloudflared.deb || true\"]
  - systemctl daemon-reload
  - systemctl enable --now tdx-launcher.service
final_message: \"EasyEnclave launcher bootstrap complete\"
"""


def _indent_block(value: str, spaces: int) -> str:
    prefix = " " * spaces
    return "\n".join(f"{prefix}{line}" for line in value.splitlines())


@dataclass
class ManagedResource:
    provider: str
    resource_id: str
    name: str
    resource_type: str
    status: str
    region: str
    zone: str
    datacenter: str
    labels: dict[str, str]

    def to_external_inventory_item(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "cloud": self.provider,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "name": self.name,
            "datacenter": self.datacenter,
            "availability_zone": self.zone,
            "region": self.region,
            "status": self.status,
            "labels": self.labels,
            "metadata": {},
        }


def _gcp_provision(args: argparse.Namespace, run_tag: str) -> list[ManagedResource]:
    if not args.gcp_project:
        raise RuntimeError("--gcp-project is required for GCP provisioning")
    if not args.gcp_zone:
        raise RuntimeError("--gcp-zone is required for GCP provisioning")

    resources: list[ManagedResource] = []
    for idx in range(args.gcp_count):
        name = _sanitize_name(
            f"{args.name_prefix}-gcp-{args.node_size}-{run_tag}-{idx + 1}-{_rand_suffix()}"
        )
        datacenter = _build_datacenter(
            provider="gcp",
            zone=args.gcp_zone,
            region=args.gcp_region,
            explicit=args.gcp_datacenter,
        )
        launcher_config = _build_launcher_config(
            cp_url=args.cp_url,
            intel_api_key=args.intel_api_key,
            node_size=args.node_size,
            provider="gcp",
            zone=args.gcp_zone,
            region=args.gcp_region,
            datacenter=datacenter,
        )
        cloud_init = _cloud_init_user_data(
            launcher_url=args.launcher_url,
            launcher_config=launcher_config,
        )

        labels = {
            "easyenclave": "managed",
            "ee-run": run_tag,
            "ee-cloud": "gcp",
            "ee-node": _sanitize_label_value(args.node_size),
            "ee-dc": _sanitize_label_value(datacenter),
        }
        labels_arg = ",".join(f"{k}={v}" for k, v in labels.items())

        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(cloud_init)
            user_data_path = f.name

        try:
            cmd = [
                "gcloud",
                "compute",
                "instances",
                "create",
                name,
                "--project",
                args.gcp_project,
                "--zone",
                args.gcp_zone,
                "--machine-type",
                args.gcp_machine_type,
                "--provisioning-model",
                "STANDARD",
                "--confidential-compute-type",
                "TDX",
                "--maintenance-policy",
                "TERMINATE",
                "--image-project",
                args.gcp_image_project,
                "--image-family",
                args.gcp_image_family,
                "--boot-disk-size",
                args.gcp_boot_disk_size,
                "--boot-disk-type",
                args.gcp_boot_disk_type,
                "--metadata-from-file",
                f"user-data={user_data_path}",
                "--labels",
                labels_arg,
                "--quiet",
            ]
            _run(cmd)
        finally:
            try:
                Path(user_data_path).unlink(missing_ok=True)
            except Exception:
                pass

        resource = ManagedResource(
            provider="gcp",
            resource_id=name,
            name=name,
            resource_type="vm",
            status="provisioning",
            region=args.gcp_region,
            zone=args.gcp_zone,
            datacenter=datacenter,
            labels=labels,
        )
        resources.append(resource)

    return resources


def _gcp_inventory(args: argparse.Namespace, run_tag: str = "") -> list[ManagedResource]:
    if not args.gcp_project:
        return []

    items = _json_cmd(
        [
            "gcloud",
            "compute",
            "instances",
            "list",
            "--project",
            args.gcp_project,
            "--format=json(name,id,status,zone,machineType,labels,creationTimestamp)",
        ]
    )
    if not isinstance(items, list):
        return []

    resources: list[ManagedResource] = []
    for item in items:
        labels = item.get("labels") or {}
        if labels.get("easyenclave") != "managed":
            continue
        if run_tag and labels.get("ee-run") != run_tag:
            continue

        zone_path = str(item.get("zone") or "")
        zone = zone_path.rsplit("/", 1)[-1] if zone_path else ""
        datacenter = f"gcp:{zone}" if zone else "gcp"
        resources.append(
            ManagedResource(
                provider="gcp",
                resource_id=str(item.get("id") or item.get("name") or ""),
                name=str(item.get("name") or ""),
                resource_type="vm",
                status=str(item.get("status") or "").lower(),
                region=args.gcp_region,
                zone=zone,
                datacenter=datacenter,
                labels={str(k): str(v) for k, v in labels.items()},
            )
        )

    return resources


def _gcp_cleanup(args: argparse.Namespace, run_tag: str = "") -> dict[str, Any]:
    resources = _gcp_inventory(args, run_tag=run_tag)
    deleted = 0
    errors: list[str] = []

    for resource in resources:
        zone = resource.zone or args.gcp_zone
        cmd = [
            "gcloud",
            "compute",
            "instances",
            "delete",
            resource.name,
            "--project",
            args.gcp_project,
            "--zone",
            zone,
            "--quiet",
        ]
        try:
            if args.dry_run:
                continue
            _run(cmd)
            deleted += 1
        except Exception as exc:
            errors.append(f"{resource.name}: {exc}")

    return {
        "provider": "gcp",
        "candidate_count": len(resources),
        "deleted_count": deleted,
        "errors": errors,
    }


def _gcp_describe_instance(args: argparse.Namespace, name: str) -> dict[str, Any]:
    if not args.gcp_project or not args.gcp_zone:
        return {}
    try:
        data = _json_cmd(
            [
                "gcloud",
                "compute",
                "instances",
                "describe",
                name,
                "--project",
                args.gcp_project,
                "--zone",
                args.gcp_zone,
                "--format=json(name,status,creationTimestamp,networkInterfaces,confidentialInstanceConfig,shieldedInstanceConfig)",
            ]
        )
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        return {"error": str(exc)}


def _gcp_serial_port_tail(args: argparse.Namespace, name: str, *, max_chars: int = 12000) -> str:
    if not args.gcp_project or not args.gcp_zone:
        return ""
    # Fetch serial output and truncate; gcloud does not provide a reliable "tail" flag.
    result = _run(
        [
            "gcloud",
            "compute",
            "instances",
            "get-serial-port-output",
            name,
            "--project",
            args.gcp_project,
            "--zone",
            args.gcp_zone,
            "--port",
            "1",
            "--format",
            "text",
            "--quiet",
        ],
        check=False,
    )
    raw = (result.stdout or "").strip()
    if not raw:
        raw = (result.stderr or "").strip()
    if len(raw) > max_chars:
        return raw[-max_chars:]
    return raw


def _azure_vm_related_resource_ids(args: argparse.Namespace, vm_name: str) -> list[str]:
    vm_data = _json_cmd(
        [
            "az",
            "vm",
            "show",
            "--resource-group",
            args.azure_resource_group,
            "--name",
            vm_name,
            "--output",
            "json",
        ]
    )
    if not isinstance(vm_data, dict):
        return []

    ids: set[str] = set()
    vm_id = vm_data.get("id")
    if isinstance(vm_id, str) and vm_id:
        ids.add(vm_id)

    os_disk = (((vm_data.get("storageProfile") or {}).get("osDisk") or {}).get("managedDisk") or {}).get(
        "id"
    )
    if isinstance(os_disk, str) and os_disk:
        ids.add(os_disk)

    nic_ids = ((vm_data.get("networkProfile") or {}).get("networkInterfaces") or [])
    for nic in nic_ids:
        nic_id = nic.get("id") if isinstance(nic, dict) else ""
        if isinstance(nic_id, str) and nic_id:
            ids.add(nic_id)
            nic_data = _json_cmd(["az", "network", "nic", "show", "--ids", nic_id, "--output", "json"])
            if isinstance(nic_data, dict):
                ip_configs = nic_data.get("ipConfigurations") or []
                for ip_conf in ip_configs:
                    pip = (ip_conf.get("publicIPAddress") or {}).get("id") if isinstance(ip_conf, dict) else ""
                    if isinstance(pip, str) and pip:
                        ids.add(pip)

    return sorted(ids)


def _azure_apply_tags(resource_ids: list[str], tags: dict[str, str]) -> None:
    if not resource_ids:
        return
    tags_arg = " ".join(f"{k}={v}" for k, v in tags.items())
    for resource_id in resource_ids:
        _run(["az", "tag", "update", "--resource-id", resource_id, "--operation", "merge", "--tags", *tags_arg.split()])


def _azure_power_state(args: argparse.Namespace, vm_name: str) -> str:
    result = _run(
        [
            "az",
            "vm",
            "show",
            "--resource-group",
            args.azure_resource_group,
            "--name",
            vm_name,
            "--show-details",
            "--query",
            "powerState",
            "--output",
            "tsv",
        ],
        check=False,
    )
    if result.returncode != 0:
        return ""
    return (result.stdout or "").strip()


def _azure_ensure_vm_running(args: argparse.Namespace, vm_name: str) -> None:
    deadline = time.time() + max(60, int(args.azure_boot_timeout_seconds))
    poll_seconds = max(5, int(args.azure_boot_poll_seconds))
    stable_seconds = max(0, int(args.azure_running_stable_seconds))
    max_start_attempts = max(0, int(args.azure_max_start_attempts))

    start_attempts = 0
    last_state = ""
    running_since: float | None = None

    while time.time() < deadline:
        state = _azure_power_state(args, vm_name)
        if state:
            last_state = state
        normalized = state.strip().lower()

        if normalized == "vm running":
            if running_since is None:
                running_since = time.time()
            if time.time() - running_since >= stable_seconds:
                return
        else:
            running_since = None
            if normalized in {"vm stopped", "vm deallocated", "vm stopping", "vm deallocating"}:
                if start_attempts < max_start_attempts:
                    start_attempts += 1
                    _run(
                        [
                            "az",
                            "vm",
                            "start",
                            "--resource-group",
                            args.azure_resource_group,
                            "--name",
                            vm_name,
                            "--no-wait",
                        ],
                        check=False,
                    )

        time.sleep(poll_seconds)

    raise RuntimeError(
        "Azure VM did not remain in running state after provisioning: "
        f"name={vm_name}, last_power_state='{last_state or 'unknown'}', "
        f"start_attempts={start_attempts}, timeout_seconds={int(args.azure_boot_timeout_seconds)}"
    )


def _azure_provision(args: argparse.Namespace, run_tag: str) -> list[ManagedResource]:
    if not args.azure_resource_group:
        raise RuntimeError("--azure-resource-group is required for Azure provisioning")
    if not args.azure_location:
        raise RuntimeError("--azure-location is required for Azure provisioning")

    # Resource groups are global containers; resources can live in a different location.
    # Create only when missing to avoid InvalidResourceGroupLocation on cross-region deploys.
    group_show = _run(
        [
            "az",
            "group",
            "show",
            "--name",
            args.azure_resource_group,
            "--output",
            "none",
        ],
        check=False,
    )
    if group_show.returncode != 0:
        _run(
            [
                "az",
                "group",
                "create",
                "--name",
                args.azure_resource_group,
                "--location",
                args.azure_location,
                "--output",
                "none",
            ]
        )

    resources: list[ManagedResource] = []
    zone_label = args.azure_zone_label
    zone_number = _extract_azure_zone_suffix(zone_label)
    datacenter = _build_datacenter(
        provider="azure",
        zone=zone_label,
        region=args.azure_location,
        explicit=args.azure_datacenter,
    )

    for idx in range(args.azure_count):
        name = _sanitize_name(
            f"{args.name_prefix}-az-{args.node_size}-{run_tag}-{idx + 1}-{_rand_suffix()}"
        )
        launcher_config = _build_launcher_config(
            cp_url=args.cp_url,
            intel_api_key=args.intel_api_key,
            node_size=args.node_size,
            provider="azure",
            zone=zone_label,
            region=args.azure_location,
            datacenter=datacenter,
        )
        cloud_init = _cloud_init_user_data(
            launcher_url=args.launcher_url,
            launcher_config=launcher_config,
        )
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(cloud_init)
            user_data_path = f.name

        tags = {
            "easyenclave": "managed",
            "ee-run": run_tag,
            "ee-cloud": "azure",
            "ee-node": _sanitize_label_value(args.node_size),
            "ee-dc": _sanitize_label_value(datacenter),
        }

        try:
            cmd = [
                "az",
                "vm",
                "create",
                "--resource-group",
                args.azure_resource_group,
                "--name",
                name,
                "--image",
                args.azure_image,
                "--size",
                args.azure_vm_size,
                "--location",
                args.azure_location,
                "--admin-username",
                args.azure_admin_username,
                "--generate-ssh-keys",
                "--custom-data",
                user_data_path,
                "--security-type",
                "ConfidentialVM",
                "--enable-vtpm",
                "true",
                "--enable-secure-boot",
                "true",
                "--os-disk-security-encryption-type",
                "VMGuestStateOnly",
                "--os-disk-delete-option",
                "Delete",
                "--nic-delete-option",
                "Delete",
                "--public-ip-sku",
                "Standard",
                "--nsg-rule",
                "None",
                "--output",
                "none",
                "--tags",
            ]
            cmd.extend([f"{k}={v}" for k, v in tags.items()])
            if zone_number:
                cmd.extend(["--zone", zone_number])
            _run(cmd)
        finally:
            try:
                Path(user_data_path).unlink(missing_ok=True)
            except Exception:
                pass

        # Apply tags to related resources (disk/NIC/PIP) for deterministic cleanup.
        try:
            related_ids = _azure_vm_related_resource_ids(args, name)
            _azure_apply_tags(related_ids, tags)
        except Exception:
            # Continue even if tagging related resources fails.
            pass

        _azure_ensure_vm_running(args, name)

        resources.append(
            ManagedResource(
                provider="azure",
                resource_id=name,
                name=name,
                resource_type="vm",
                status="provisioning",
                region=args.azure_location,
                zone=zone_label,
                datacenter=datacenter,
                labels=tags,
            )
        )

    return resources


def _azure_inventory(args: argparse.Namespace, run_tag: str = "") -> list[ManagedResource]:
    if not args.azure_resource_group:
        return []

    items = _json_cmd(
        [
            "az",
            "vm",
            "list",
            "--resource-group",
            args.azure_resource_group,
            "--show-details",
            "--output",
            "json",
        ]
    )
    if not isinstance(items, list):
        return []

    resources: list[ManagedResource] = []
    for item in items:
        tags = item.get("tags") or {}
        if tags.get("easyenclave") != "managed":
            continue
        if run_tag and tags.get("ee-run") != run_tag:
            continue

        zones = item.get("zones") or []
        zone_number = str(zones[0]) if zones else ""
        zone_label = args.azure_zone_label
        if not zone_label and zone_number:
            zone_label = f"{args.azure_location}-{zone_number}"

        datacenter = _build_datacenter(
            provider="azure",
            zone=zone_label,
            region=args.azure_location,
            explicit=args.azure_datacenter,
        )

        resources.append(
            ManagedResource(
                provider="azure",
                resource_id=str(item.get("id") or item.get("name") or ""),
                name=str(item.get("name") or ""),
                resource_type="vm",
                status=str(item.get("powerState") or "").lower(),
                region=str(item.get("location") or args.azure_location),
                zone=zone_label,
                datacenter=datacenter,
                labels={str(k): str(v) for k, v in tags.items()},
            )
        )

    return resources


def _azure_cleanup(args: argparse.Namespace, run_tag: str = "") -> dict[str, Any]:
    if not args.azure_resource_group:
        return {
            "provider": "azure",
            "candidate_count": 0,
            "deleted_count": 0,
            "errors": [],
        }

    resources = _azure_inventory(args, run_tag=run_tag)
    vm_names = [res.name for res in resources]

    deleted = 0
    errors: list[str] = []

    # Delete VMs first (this detaches NIC/disks).
    for vm_name in vm_names:
        cmd = [
            "az",
            "vm",
            "delete",
            "--resource-group",
            args.azure_resource_group,
            "--name",
            vm_name,
            "--yes",
            "--force-deletion",
            "true",
        ]
        try:
            if not args.dry_run:
                _run(cmd)
            deleted += 1
        except Exception as exc:
            errors.append(f"vm {vm_name}: {exc}")

    # Delete tagged non-VM resources to avoid orphaned disk/NIC/public IP costs.
    tagged_resources = _json_cmd(
        [
            "az",
            "resource",
            "list",
            "--resource-group",
            args.azure_resource_group,
            "--output",
            "json",
        ]
    )
    if not isinstance(tagged_resources, list):
        tagged_resources = []

    extra_resources: list[tuple[str, str]] = []
    for resource in tagged_resources:
        tags = resource.get("tags") or {}
        if tags.get("easyenclave") != "managed":
            continue
        if run_tag and tags.get("ee-run") != run_tag:
            continue
        resource_type = str(resource.get("type") or "")
        if resource_type == "Microsoft.Compute/virtualMachines":
            continue
        resource_id = str(resource.get("id") or "")
        if resource_id:
            extra_resources.append((resource_id, resource_type))

    delete_priority = {
        "Microsoft.Network/networkInterfaces": 10,
        "Microsoft.Compute/disks": 20,
        "Microsoft.Network/publicIPAddresses": 30,
        "Microsoft.Network/networkSecurityGroups": 40,
        "Microsoft.Network/virtualNetworks/subnets": 50,
        "Microsoft.Network/virtualNetworks": 60,
    }
    extra_resources.sort(key=lambda item: (delete_priority.get(item[1], 100), item[1], item[0]))

    for resource_id, _resource_type in extra_resources:
        cmd = ["az", "resource", "delete", "--ids", resource_id]
        if args.dry_run:
            continue
        last_exc: Exception | None = None
        for attempt in range(1, 4):
            try:
                _run(cmd)
                last_exc = None
                break
            except Exception as exc:
                last_exc = exc
                if attempt < 3:
                    time.sleep(5)
        if last_exc is not None:
            errors.append(f"resource {resource_id}: {last_exc}")

    return {
        "provider": "azure",
        "candidate_count": len(resources),
        "deleted_count": deleted,
        "errors": errors,
    }


def _wait_for_registration(
    *,
    cp_url: str,
    cp_admin_token: str,
    datacenter_targets: dict[str, int],
    timeout_seconds: int,
    poll_seconds: int = 20,
) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds
    attempts = 0
    last_counts: dict[str, int] = dict.fromkeys(datacenter_targets, 0)
    last_error = ""
    attempted_trust: set[str] = set()

    while time.time() < deadline:
        attempts += 1
        try:
            payload = _cp_get_json(
                cp_url=cp_url,
                path="/api/v1/agents",
                cp_admin_token=cp_admin_token,
                timeout_seconds=30,
            )
        except urllib.error.HTTPError as exc:
            err = _http_error_detail(exc)
            if exc.code in {401, 403} and not cp_admin_token.strip():
                return {
                    "ready": False,
                    "attempts": attempts,
                    "counts": last_counts,
                    "error": (
                        f"Control plane agent list denied ({err}). "
                        "Set --cp-admin-token (or CP_ADMIN_TOKEN) for registration checks."
                    ),
                }
            last_error = f"Control plane agent list failed ({err})"
            time.sleep(poll_seconds)
            continue
        except Exception as exc:
            last_error = f"Control plane agent list failed ({exc})"
            time.sleep(poll_seconds)
            continue

        agents = payload.get("agents") if isinstance(payload, dict) else []
        if not isinstance(agents, list):
            agents = []

        counts: dict[str, int] = dict.fromkeys(datacenter_targets, 0)
        # If the control plane recorded an untrusted baseline (verified=false) we can
        # auto-trust it (admin-token permitting) so the agent can re-register as verified.
        untrusted_candidates: list[tuple[str, str]] = []
        for agent in agents:
            if not isinstance(agent, dict):
                continue
            status = str(agent.get("status") or "").strip().lower()
            dc = str(agent.get("datacenter") or "").strip().lower()
            if dc not in counts:
                continue

            if bool(agent.get("verified")):
                if status not in {"undeployed", "deployed", "deploying"}:
                    continue
                if str(agent.get("health_status") or "").strip().lower() != "healthy":
                    continue
                if not str(agent.get("hostname") or "").strip():
                    continue
                counts[dc] += 1
                continue

            # Unverified: capture MRDT for admin trust step.
            mrtd = str(agent.get("mrtd") or "").strip().lower()
            attestation_valid = bool(agent.get("attestation_valid", True))
            if (
                status in {"unverified", "attestation_failed"}
                and attestation_valid
                and mrtd
                and mrtd not in attempted_trust
                and re.fullmatch(r"[0-9a-f]{96}", mrtd)
            ):
                untrusted_candidates.append((dc, mrtd))

        last_counts = counts
        if all(counts[dc] >= required for dc, required in datacenter_targets.items()):
            return {
                "ready": True,
                "attempts": attempts,
                "counts": counts,
            }

        if untrusted_candidates:
            if not cp_admin_token.strip():
                dc, mrtd = untrusted_candidates[0]
                return {
                    "ready": False,
                    "attempts": attempts,
                    "counts": last_counts,
                    "error": (
                        "Found untrusted agent baseline that needs approval in the control plane "
                        f"(datacenter={dc} mrtd={mrtd[:16]}...). "
                        "Set --cp-admin-token (or CP_ADMIN_TOKEN) so CI can add it."
                    ),
                }

            for dc, mrtd in untrusted_candidates:
                try:
                    _cp_post_json(
                        cp_url=cp_url,
                        path="/api/v1/admin/trusted-mrtds",
                        cp_admin_token=cp_admin_token,
                        body={
                            "mrtd": mrtd,
                            "type": "agent",
                            "note": f"auto-trusted by cloud_provisioner for {dc} at {_utc_now()}",
                        },
                        timeout_seconds=30,
                    )
                    attempted_trust.add(mrtd)
                    last_error = (
                        f"Added trusted MRTD baseline for datacenter={dc} mrtd={mrtd[:16]}..."
                    )
                except urllib.error.HTTPError as exc:
                    err = _http_error_detail(exc)
                    if exc.code == 404:
                        return {
                            "ready": False,
                            "attempts": attempts,
                            "counts": last_counts,
                            "error": (
                                "Control plane does not support DB-backed trusted MRTDs yet "
                                f"({err}). Deploy the updated control plane and retry."
                            ),
                        }
                    last_error = f"Failed to add trusted MRTD baseline ({err})"
                except Exception as exc:
                    last_error = f"Failed to add trusted MRTD baseline ({exc})"

        time.sleep(poll_seconds)

    return {
        "ready": False,
        "attempts": attempts,
        "counts": last_counts,
        "error": last_error,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Provision EasyEnclave cloud agents")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--provider", choices=["gcp", "azure", "all"], default="all")
        p.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", "manual"))
        p.add_argument("--name-prefix", default="easyenclave-agent")
        p.add_argument("--dry-run", action="store_true")
        p.add_argument("--all-managed", action="store_true")

        p.add_argument("--cp-url", default="https://app.easyenclave.com")
        p.add_argument("--cp-admin-token", default=os.environ.get("CP_ADMIN_TOKEN", ""))
        p.add_argument("--intel-api-key", default=os.environ.get("INTEL_API_KEY", ""))
        p.add_argument("--node-size", default="tiny")
        p.add_argument("--launcher-url", default="")

        p.add_argument("--gcp-project", default=os.environ.get("GCP_PROJECT_ID", ""))
        p.add_argument("--gcp-zone", default=os.environ.get("GCP_ZONE", "us-central1-a"))
        p.add_argument("--gcp-region", default=os.environ.get("GCP_REGION", "us-central1"))
        p.add_argument("--gcp-machine-type", default=os.environ.get("GCP_MACHINE_TYPE", "c3-standard-4"))
        p.add_argument("--gcp-image-project", default=os.environ.get("GCP_IMAGE_PROJECT", "ubuntu-os-cloud"))
        p.add_argument("--gcp-image-family", default=os.environ.get("GCP_IMAGE_FAMILY", "ubuntu-2404-lts-amd64"))
        p.add_argument("--gcp-boot-disk-size", default=os.environ.get("GCP_BOOT_DISK_SIZE", "80GB"))
        p.add_argument("--gcp-boot-disk-type", default=os.environ.get("GCP_BOOT_DISK_TYPE", "pd-balanced"))
        p.add_argument("--gcp-count", type=int, default=1)
        p.add_argument("--gcp-datacenter", default="")

        p.add_argument("--azure-resource-group", default=os.environ.get("AZURE_RESOURCE_GROUP", ""))
        p.add_argument("--azure-location", default=os.environ.get("AZURE_LOCATION", "eastus2"))
        p.add_argument("--azure-zone-label", default=os.environ.get("AZURE_ZONE_LABEL", "eastus2-3"))
        p.add_argument("--azure-vm-size", default=os.environ.get("AZURE_VM_SIZE", "Standard_DC2eds_v5"))
        p.add_argument("--azure-image", default=os.environ.get("AZURE_IMAGE", "Canonical:ubuntu-24_04-lts:cvm:latest"))
        p.add_argument("--azure-admin-username", default=os.environ.get("AZURE_ADMIN_USERNAME", "easyenclave"))
        p.add_argument("--azure-count", type=int, default=1)
        p.add_argument("--azure-datacenter", default="")
        p.add_argument("--azure-boot-timeout-seconds", type=int, default=420)
        p.add_argument("--azure-boot-poll-seconds", type=int, default=15)
        p.add_argument("--azure-running-stable-seconds", type=int, default=90)
        p.add_argument("--azure-max-start-attempts", type=int, default=2)

    provision = sub.add_parser("provision", help="Provision managed confidential VMs")
    add_common(provision)
    provision.add_argument("--wait-registration", action="store_true")
    provision.add_argument("--wait-seconds", type=int, default=1800)

    inventory = sub.add_parser("inventory", help="List managed cloud resources")
    add_common(inventory)

    cleanup = sub.add_parser("cleanup", help="Delete managed cloud resources")
    add_common(cleanup)

    return parser


def _resolve_launcher_url(args: argparse.Namespace) -> str:
    if args.launcher_url:
        return args.launcher_url

    repo = os.environ.get("GITHUB_REPOSITORY", "easyenclave/easyenclave")
    sha = os.environ.get("GITHUB_SHA", "main")
    return f"https://raw.githubusercontent.com/{repo}/{sha}/infra/launcher/launcher.py"


def _providers(args: argparse.Namespace) -> list[str]:
    if args.provider == "all":
        return ["gcp", "azure"]
    return [args.provider]


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    run_tag = _sanitize_label_value(str(args.run_id), max_len=30)
    run_filter = "" if args.all_managed else run_tag
    args.launcher_url = _resolve_launcher_url(args)

    if args.command == "provision" and not args.intel_api_key:
        raise RuntimeError("--intel-api-key is required for provision command")

    providers = _providers(args)
    inventory_items: list[ManagedResource] = []

    if args.command == "provision":
        for provider in providers:
            if provider == "gcp":
                inventory_items.extend(_gcp_provision(args, run_tag=run_tag))
            elif provider == "azure":
                inventory_items.extend(_azure_provision(args, run_tag=run_tag))

        result: dict[str, Any] = {
            "status": "provisioned",
            "generated_at": _utc_now(),
            "run_id": run_tag,
            "resources": [item.to_external_inventory_item() for item in inventory_items],
        }

        if args.wait_registration:
            targets: dict[str, int] = {}
            for item in inventory_items:
                targets[item.datacenter] = targets.get(item.datacenter, 0) + 1
            wait_result = _wait_for_registration(
                cp_url=args.cp_url,
                cp_admin_token=args.cp_admin_token,
                datacenter_targets=targets,
                timeout_seconds=args.wait_seconds,
            )
            result["registration"] = wait_result
            if not wait_result.get("ready"):
                # Best-effort diagnostics for provisioning failures. Keep output compact.
                diagnostics: dict[str, Any] = {"gcp": [], "azure": []}
                for item in inventory_items:
                    if item.provider == "gcp":
                        diagnostics["gcp"].append(
                            {
                                "name": item.name,
                                "datacenter": item.datacenter,
                                "describe": _gcp_describe_instance(args, item.name),
                                "serial_port_tail": _gcp_serial_port_tail(args, item.name),
                            }
                        )
                # Only include non-empty sections.
                diagnostics = {k: v for k, v in diagnostics.items() if v}
                if diagnostics:
                    result["diagnostics"] = diagnostics
                print(json.dumps(result, indent=2))
                return 2

        print(json.dumps(result, indent=2))
        return 0

    if args.command == "inventory":
        for provider in providers:
            if provider == "gcp":
                inventory_items.extend(_gcp_inventory(args, run_tag=run_filter))
            elif provider == "azure":
                inventory_items.extend(_azure_inventory(args, run_tag=run_filter))

        payload = {
            "detail": "cloud-provisioner inventory",
            "resources": [item.to_external_inventory_item() for item in inventory_items],
        }
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "cleanup":
        cleanup_results = []
        for provider in providers:
            if provider == "gcp":
                cleanup_results.append(_gcp_cleanup(args, run_tag=run_filter))
            elif provider == "azure":
                cleanup_results.append(_azure_cleanup(args, run_tag=run_filter))

        deleted = sum(int(item.get("deleted_count") or 0) for item in cleanup_results)
        candidates = sum(int(item.get("candidate_count") or 0) for item in cleanup_results)
        errors: list[str] = []
        for item in cleanup_results:
            errors.extend(item.get("errors") or [])

        payload = {
            "detail": "cloud-provisioner cleanup",
            "run_id": run_filter or "all-managed",
            "candidate_count": candidates,
            "deleted_count": deleted,
            "errors": errors,
        }
        print(json.dumps(payload, indent=2))
        return 0 if not errors else 3

    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"status": "error", "detail": str(exc)}), file=sys.stderr)
        raise SystemExit(1) from exc
