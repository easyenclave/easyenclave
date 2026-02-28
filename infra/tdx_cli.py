#!/usr/bin/env python3
"""EasyEnclave GCP CLI.

GCP-only orchestration for control-plane and agent lifecycle.
Legacy local/libvirt VM paths are intentionally removed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

NODE_SIZES: dict[str, tuple[int, int, int, str]] = {
    # memory_gib, vcpus, disk_gib, gcp machine type
    "tiny": (8, 4, 200, "c3-standard-4"),
    "standard": (16, 8, 200, "c3-standard-8"),
    "llm": (44, 22, 200, "c3-standard-22"),
}

CONTROL_PLANE_MODE = "control-plane"
AGENT_MODE = "agent"
MEASURE_MODE = "measure"


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def _fatal(msg: str, code: int = 1) -> None:
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(code)


def _normalize_name(value: str, *, max_len: int = 63) -> str:
    cleaned = re.sub(r"[^a-z0-9-]+", "-", value.strip().lower())
    cleaned = re.sub(r"-+", "-", cleaned).strip("-")
    if not cleaned:
        cleaned = "easyenclave"
    return cleaned[:max_len].rstrip("-") or "easyenclave"


def _network_slug(value: str) -> str:
    return _normalize_name(value, max_len=48)


def _json_dump(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


@dataclass
class GcpConfig:
    project_id: str
    zone: str
    image_project: str
    image_name: str | None
    image_family: str | None
    service_account_key_json: str | None


class GcpCli:
    def __init__(self, workspace: Path):
        self.workspace = workspace

    def _run(
        self, args: list[str], *, capture: bool = True, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        cmd = ["gcloud", *args]
        proc = subprocess.run(
            cmd,
            text=True,
            capture_output=capture,
            check=False,
        )
        if check and proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            stdout = (proc.stdout or "").strip()
            detail = stderr or stdout or f"exit_code={proc.returncode}"
            raise RuntimeError(f"gcloud command failed: {' '.join(cmd)}\n{detail}")
        return proc

    def _run_json(self, args: list[str]) -> Any:
        proc = self._run([*args, "--format=json"], capture=True, check=True)
        text = (proc.stdout or "").strip()
        if not text:
            return {}
        return json.loads(text)

    def _activate_service_account_if_needed(self, cfg: GcpConfig) -> None:
        if cfg.service_account_key_json:
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tf:
                tf.write(cfg.service_account_key_json)
                key_path = tf.name
            try:
                self._run(
                    ["auth", "activate-service-account", "--key-file", key_path],
                    capture=True,
                    check=True,
                )
            finally:
                try:
                    os.unlink(key_path)
                except OSError:
                    pass
        self._run(["config", "set", "project", cfg.project_id], capture=True, check=True)

    def _resolve_config(self, *, zone_override: str | None = None) -> GcpConfig:
        project_id = (
            os.environ.get("GCP_PROJECT_ID")
            or os.environ.get("STAGING_GCP_PROJECT_ID")
            or os.environ.get("PRODUCTION_GCP_PROJECT_ID")
            or ""
        ).strip()
        if not project_id:
            _fatal("Missing GCP_PROJECT_ID")

        zone = (
            zone_override
            or os.environ.get("GCP_ZONE")
            or os.environ.get("AGENT_DATACENTER_AZ")
            or "us-central1-f"
        ).strip()
        if not zone:
            zone = "us-central1-f"

        image_project = (os.environ.get("EE_GCP_IMAGE_PROJECT") or project_id).strip()
        image_name = (os.environ.get("EE_GCP_IMAGE_NAME") or "").strip() or None
        image_family = (
            os.environ.get("EE_GCP_IMAGE_FAMILY") or "easyenclave-agent-main"
        ).strip() or None
        if not image_name and not image_family:
            _fatal("Missing EE_GCP_IMAGE_NAME/EE_GCP_IMAGE_FAMILY")

        sa_key = (
            os.environ.get("GCP_SERVICE_ACCOUNT_KEY")
            or os.environ.get("STAGING_GCP_SERVICE_ACCOUNT_KEY")
            or os.environ.get("PRODUCTION_GCP_SERVICE_ACCOUNT_KEY")
            or ""
        ).strip() or None

        return GcpConfig(
            project_id=project_id,
            zone=zone,
            image_project=image_project,
            image_name=image_name,
            image_family=image_family,
            service_account_key_json=sa_key,
        )

    def _image_args(self, cfg: GcpConfig) -> list[str]:
        args = ["--image-project", cfg.image_project]
        if cfg.image_name:
            args.extend(["--image", cfg.image_name])
        elif cfg.image_family:
            args.extend(["--image-family", cfg.image_family])
        else:
            _fatal("Image source is not configured")
        return args

    def _machine_type_for_size(self, size: str) -> str:
        normalized = (size or "").strip().lower()
        if normalized not in NODE_SIZES:
            _fatal(f"Unsupported size '{size}'. Allowed: {', '.join(NODE_SIZES.keys())}")
        return NODE_SIZES[normalized][3]

    def _boot_disk_gib(self, default_gib: int) -> int:
        raw = (
            os.environ.get("EE_GCP_BOOT_DISK_GB") or os.environ.get("GCP_BOOT_DISK_GB") or ""
        ).strip()
        if not raw:
            return default_gib
        try:
            parsed = int(raw)
        except ValueError:
            _log(f"Ignoring invalid EE_GCP_BOOT_DISK_GB value: {raw!r}")
            return default_gib
        return max(default_gib, parsed)

    def _write_startup_script(self, config: dict[str, Any]) -> str:
        script = f"""#!/usr/bin/env bash
set -euo pipefail
mkdir -p /etc/easyenclave
cat > /etc/easyenclave/config.json <<'EOF_CONFIG'
{json.dumps(config, indent=2, sort_keys=True)}
EOF_CONFIG
chmod 0600 /etc/easyenclave/config.json
systemctl daemon-reload || true
systemctl restart tdx-launcher.service || true
"""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".sh") as tf:
            tf.write(script)
            return tf.name

    def _create_instance(
        self,
        *,
        cfg: GcpConfig,
        name: str,
        machine_type: str,
        startup_script_path: str,
        labels: dict[str, str],
        disk_gib: int,
    ) -> dict[str, Any]:
        labels_arg = ",".join(f"{k}={_normalize_name(v, max_len=63)}" for k, v in labels.items())
        cmd = [
            "compute",
            "instances",
            "create",
            name,
            "--project",
            cfg.project_id,
            "--zone",
            cfg.zone,
            "--machine-type",
            machine_type,
            "--boot-disk-size",
            f"{disk_gib}GB",
            "--maintenance-policy",
            "TERMINATE",
            "--provisioning-model",
            "STANDARD",
            "--confidential-compute-type",
            "TDX",
            "--scopes",
            "https://www.googleapis.com/auth/cloud-platform",
            "--labels",
            labels_arg,
            "--metadata-from-file",
            f"startup-script={startup_script_path}",
            *self._image_args(cfg),
        ]
        self._run(cmd, capture=True, check=True)
        return self.describe_instance(cfg=cfg, name=name)

    def describe_instance(self, *, cfg: GcpConfig, name: str) -> dict[str, Any]:
        return self._run_json(
            [
                "compute",
                "instances",
                "describe",
                name,
                "--project",
                cfg.project_id,
                "--zone",
                cfg.zone,
            ]
        )

    def _instance_ips(self, instance: dict[str, Any]) -> tuple[str | None, str | None]:
        internal_ip = None
        external_ip = None
        nics = instance.get("networkInterfaces") or []
        if nics:
            internal_ip = nics[0].get("networkIP")
            access_cfgs = nics[0].get("accessConfigs") or []
            if access_cfgs:
                external_ip = access_cfgs[0].get("natIP")
        return internal_ip, external_ip

    def _wait_http_health(self, url: str, timeout_seconds: int) -> bool:
        deadline = time.time() + max(1, timeout_seconds)
        while time.time() < deadline:
            proc = subprocess.run(
                ["curl", "-fsS", f"{url.rstrip('/')}/health"],
                text=True,
                capture_output=True,
            )
            if proc.returncode == 0:
                return True
            time.sleep(5)
        return False

    def _wait_instance_running(
        self, *, cfg: GcpConfig, name: str, timeout_seconds: int
    ) -> dict[str, Any]:
        deadline = time.time() + max(1, timeout_seconds)
        while time.time() < deadline:
            inst = self.describe_instance(cfg=cfg, name=name)
            status = str(inst.get("status") or "").upper()
            if status == "RUNNING":
                return inst
            time.sleep(3)
        _fatal(f"Timed out waiting for instance '{name}' to reach RUNNING")

    def _control_plane_hosts(
        self, domain: str, env_name: str, network_name: str
    ) -> tuple[str, str | None]:
        alias = f"app-staging.{domain}" if env_name == "staging" else f"app.{domain}"
        slug = _network_slug(network_name)
        if slug:
            return alias, f"{slug}.{domain}"
        return alias, None

    def _build_cp_config(self, *, port: int, cp_url_for_agents: str) -> dict[str, Any]:
        cfg: dict[str, Any] = {
            "mode": CONTROL_PLANE_MODE,
            "port": int(port),
            "control_plane_image": os.environ.get("CONTROL_PLANE_IMAGE")
            or f"ghcr.io/{os.environ.get('GITHUB_REPOSITORY', 'easyenclave/easyenclave')}/control-plane-rust:latest",
            "easyenclave_domain": os.environ.get("EASYENCLAVE_DOMAIN", "easyenclave.com"),
            "easyenclave_env": os.environ.get("EASYENCLAVE_ENV", "staging"),
            "easyenclave_network_name": os.environ.get("EASYENCLAVE_NETWORK_NAME", ""),
            "easyenclave_boot_id": os.environ.get("EASYENCLAVE_BOOT_ID", ""),
            "easyenclave_git_sha": os.environ.get("EASYENCLAVE_GIT_SHA", ""),
            "easyenclave_release_tag": os.environ.get("EASYENCLAVE_RELEASE_TAG", ""),
            "easyenclave_cp_url": cp_url_for_agents,
            "cloudflare_api_token": os.environ.get("CLOUDFLARE_API_TOKEN", ""),
            "cloudflare_account_id": os.environ.get("CLOUDFLARE_ACCOUNT_ID", ""),
            "cloudflare_zone_id": os.environ.get("CLOUDFLARE_ZONE_ID", ""),
            "admin_password": os.environ.get("ADMIN_PASSWORD", ""),
            "admin_github_logins": os.environ.get("ADMIN_GITHUB_LOGINS", ""),
            "admin_password_hash": os.environ.get("ADMIN_PASSWORD_HASH", ""),
            "ee_agent_ita_api_key": os.environ.get("EE_AGENT_ITA_API_KEY")
            or os.environ.get("ITA_API_KEY")
            or os.environ.get("INTEL_API_KEY")
            or "",
            "gcp_project_id": os.environ.get("GCP_PROJECT_ID", ""),
            "gcp_service_account_key": os.environ.get("GCP_SERVICE_ACCOUNT_KEY", ""),
            "ee_gcp_image_project": os.environ.get("EE_GCP_IMAGE_PROJECT", ""),
            "ee_gcp_image_family": os.environ.get("EE_GCP_IMAGE_FAMILY", ""),
            "ee_gcp_image_name": os.environ.get("EE_GCP_IMAGE_NAME", ""),
            "github_oauth_client_id": os.environ.get("GITHUB_OAUTH_CLIENT_ID", ""),
            "github_oauth_client_secret": os.environ.get("GITHUB_OAUTH_CLIENT_SECRET", ""),
            "github_oauth_redirect_uri": os.environ.get("GITHUB_OAUTH_REDIRECT_URI", ""),
            "stripe_secret_key": os.environ.get("STRIPE_SECRET_KEY", ""),
            "stripe_webhook_secret": os.environ.get("STRIPE_WEBHOOK_SECRET", ""),
            "trusted_agent_mrtds": os.environ.get("TRUSTED_AGENT_MRTDS", ""),
            "trusted_proxy_mrtds": os.environ.get("TRUSTED_PROXY_MRTDS", ""),
            "trusted_agent_rtmrs": os.environ.get("TRUSTED_AGENT_RTMRS", ""),
            "trusted_proxy_rtmrs": os.environ.get("TRUSTED_PROXY_RTMRS", ""),
            "trusted_agent_rtmrs_by_size": os.environ.get("TRUSTED_AGENT_RTMRS_BY_SIZE", ""),
            "trusted_proxy_rtmrs_by_size": os.environ.get("TRUSTED_PROXY_RTMRS_BY_SIZE", ""),
            "tcb_enforcement_mode": os.environ.get("TCB_ENFORCEMENT_MODE", ""),
            "allowed_tcb_statuses": os.environ.get("ALLOWED_TCB_STATUSES", ""),
            "nonce_enforcement_mode": os.environ.get("NONCE_ENFORCEMENT_MODE", ""),
            "nonce_ttl_seconds": os.environ.get("NONCE_TTL_SECONDS", ""),
            "rtmr_enforcement_mode": os.environ.get("RTMR_ENFORCEMENT_MODE", ""),
            "signature_verification_mode": os.environ.get("SIGNATURE_VERIFICATION_MODE", ""),
            "cp_to_agent_attestation_mode": os.environ.get("CP_TO_AGENT_ATTESTATION_MODE", ""),
            "auth_require_github_oauth_in_production": os.environ.get(
                "AUTH_REQUIRE_GITHUB_OAUTH_IN_PRODUCTION", ""
            ),
            "password_login_enabled": os.environ.get("PASSWORD_LOGIN_ENABLED", ""),
            "auth_allow_password_login_in_production": os.environ.get(
                "AUTH_ALLOW_PASSWORD_LOGIN_IN_PRODUCTION", ""
            ),
            "billing_enabled": os.environ.get("BILLING_ENABLED", ""),
            "billing_capacity_request_dev_simulation": os.environ.get(
                "BILLING_CAPACITY_REQUEST_DEV_SIMULATION", ""
            ),
            "billing_platform_account_id": os.environ.get("BILLING_PLATFORM_ACCOUNT_ID", ""),
            "billing_contributor_pool_bps": os.environ.get("BILLING_CONTRIBUTOR_POOL_BPS", ""),
            "default_gcp_tiny_capacity_enabled": os.environ.get(
                "DEFAULT_GCP_TINY_CAPACITY_ENABLED", ""
            ),
            "default_gcp_tiny_capacity_count": os.environ.get(
                "DEFAULT_GCP_TINY_CAPACITY_COUNT", ""
            ),
            "default_gcp_tiny_capacity_dispatch": os.environ.get(
                "DEFAULT_GCP_TINY_CAPACITY_DISPATCH", ""
            ),
            "cp_attestation_allow_insecure": os.environ.get("CP_ATTESTATION_ALLOW_INSECURE", ""),
            "cp_ita_jwks_url": os.environ.get("CP_ITA_JWKS_URL")
            or "https://portal.trustauthority.intel.com/certs",
            "cp_ita_issuer": os.environ.get("CP_ITA_ISSUER")
            or "https://portal.trustauthority.intel.com",
            "cp_ita_audience": os.environ.get("CP_ITA_AUDIENCE", ""),
            "cp_ita_jwks_ttl_seconds": os.environ.get("CP_ITA_JWKS_TTL_SECONDS", ""),
        }
        return {k: v for k, v in cfg.items() if v not in (None, "")}

    def control_plane_new(
        self,
        *,
        port: int,
        wait: bool,
        wait_timeout_seconds: int,
    ) -> dict[str, Any]:
        cfg = self._resolve_config()
        self._activate_service_account_if_needed(cfg)

        env_name = (os.environ.get("EASYENCLAVE_ENV") or "staging").strip().lower()
        network_name = (os.environ.get("EASYENCLAVE_NETWORK_NAME") or "").strip()
        domain = (os.environ.get("EASYENCLAVE_DOMAIN") or "easyenclave.com").strip()
        alias_hostname, network_hostname = self._control_plane_hosts(domain, env_name, network_name)
        cp_url_for_agents = f"https://{network_hostname or alias_hostname}"

        cp_name = _normalize_name(
            f"ee-cp-{env_name}-{network_name or uuid.uuid4().hex[:8]}-{int(time.time())}",
            max_len=63,
        )
        startup_script = self._write_startup_script(
            self._build_cp_config(port=port, cp_url_for_agents=cp_url_for_agents)
        )
        try:
            instance = self._create_instance(
                cfg=cfg,
                name=cp_name,
                machine_type=self._machine_type_for_size("standard"),
                startup_script_path=startup_script,
                labels={
                    "easyenclave": "managed",
                    "ee_role": "control-plane",
                    "ee_env": env_name,
                    "ee_network": network_name or "default",
                },
                disk_gib=200,
            )
        finally:
            try:
                os.unlink(startup_script)
            except OSError:
                pass

        instance = self._wait_instance_running(cfg=cfg, name=cp_name, timeout_seconds=300)
        internal_ip, external_ip = self._instance_ips(instance)

        preferred_url = (
            f"https://{network_hostname}" if network_hostname else f"https://{alias_hostname}"
        )
        fallback_url = f"https://{alias_hostname}"

        if wait:
            if not self._wait_http_health(preferred_url, wait_timeout_seconds):
                if preferred_url != fallback_url and self._wait_http_health(
                    fallback_url, wait_timeout_seconds
                ):
                    preferred_url = fallback_url
                else:
                    _fatal(
                        f"Control plane did not become healthy at {preferred_url} (fallback {fallback_url})"
                    )

        result = {
            "name": cp_name,
            "zone": cfg.zone,
            "ip": external_ip or internal_ip,
            "internal_ip": internal_ip,
            "external_ip": external_ip,
            "control_plane_url": preferred_url,
            "control_plane_hostname": alias_hostname,
            "control_plane_network_hostname": network_hostname,
        }
        return result

    def vm_new(
        self,
        *,
        node_size: str,
        control_plane_url: str,
        intel_api_key: str,
        cloud_provider: str,
        availability_zone: str,
        region: str,
        datacenter: str,
        wait: bool,
        wait_timeout_seconds: int,
    ) -> dict[str, Any]:
        provider = (cloud_provider or "gcp").strip().lower()
        if provider not in {"gcp", "google"}:
            _fatal(f"GCP-only mode: unsupported cloud provider '{provider}'")

        zone = (availability_zone or os.environ.get("GCP_ZONE") or "us-central1-f").strip()
        cfg = self._resolve_config(zone_override=zone)
        self._activate_service_account_if_needed(cfg)

        vm_name = _normalize_name(f"tdx-agent-{uuid.uuid4().hex[:10]}")
        datacenter_label = (datacenter or f"gcp:{zone}").strip().lower()

        config = {
            "mode": AGENT_MODE,
            "control_plane_url": control_plane_url,
            "cloud_provider": "gcp",
            "availability_zone": zone,
            "region": region,
            "datacenter": datacenter_label,
            "node_size": node_size,
            "intel_api_key": intel_api_key,
            "ita_api_key": intel_api_key,
            "easyenclave_env": os.environ.get("EASYENCLAVE_ENV", "staging"),
            "easyenclave_network_name": os.environ.get("EASYENCLAVE_NETWORK_NAME", ""),
        }

        startup_script = self._write_startup_script(config)
        try:
            instance = self._create_instance(
                cfg=cfg,
                name=vm_name,
                machine_type=self._machine_type_for_size(node_size),
                startup_script_path=startup_script,
                labels={
                    "easyenclave": "managed",
                    "ee_role": "agent",
                    "ee_env": os.environ.get("EASYENCLAVE_ENV", "staging"),
                    "ee_network": os.environ.get("EASYENCLAVE_NETWORK_NAME", "default"),
                    "ee_node_size": node_size,
                },
                disk_gib=self._boot_disk_gib(NODE_SIZES[node_size][2]),
            )
        finally:
            try:
                os.unlink(startup_script)
            except OSError:
                pass

        if wait:
            instance = self._wait_instance_running(
                cfg=cfg,
                name=vm_name,
                timeout_seconds=wait_timeout_seconds,
            )

        internal_ip, external_ip = self._instance_ips(instance)
        return {
            "name": vm_name,
            "zone": cfg.zone,
            "internal_ip": internal_ip,
            "external_ip": external_ip,
            "cloud_provider": "gcp",
            "datacenter": datacenter_label,
            "node_size": node_size,
        }

    def vm_list(self) -> list[str]:
        cfg = self._resolve_config()
        self._activate_service_account_if_needed(cfg)
        data = self._run_json(
            [
                "compute",
                "instances",
                "list",
                "--project",
                cfg.project_id,
                "--filter",
                "labels.easyenclave=managed",
            ]
        )
        names = []
        for item in data or []:
            name = str(item.get("name") or "").strip()
            if name:
                names.append(name)
        return sorted(names)

    def vm_delete(self, name: str) -> None:
        cfg = self._resolve_config()
        self._activate_service_account_if_needed(cfg)

        if name == "all":
            for vm_name in self.vm_list():
                self._run(
                    [
                        "compute",
                        "instances",
                        "delete",
                        vm_name,
                        "--project",
                        cfg.project_id,
                        "--zone",
                        cfg.zone,
                        "--quiet",
                    ],
                    capture=True,
                    check=False,
                )
            return

        self._run(
            [
                "compute",
                "instances",
                "delete",
                name,
                "--project",
                cfg.project_id,
                "--zone",
                cfg.zone,
                "--quiet",
            ],
            capture=True,
            check=True,
        )

    def vm_measure(self, *, size: str, timeout_seconds: int) -> dict[str, Any]:
        cfg = self._resolve_config()
        self._activate_service_account_if_needed(cfg)

        name = _normalize_name(f"ee-measure-{size}-{uuid.uuid4().hex[:8]}")
        startup_script = self._write_startup_script({"mode": MEASURE_MODE, "node_size": size})

        try:
            self._create_instance(
                cfg=cfg,
                name=name,
                machine_type=self._machine_type_for_size(size),
                startup_script_path=startup_script,
                labels={
                    "easyenclave": "managed",
                    "ee_role": "measure",
                    "ee_env": os.environ.get("EASYENCLAVE_ENV", "staging"),
                },
                disk_gib=self._boot_disk_gib(NODE_SIZES[size][2]),
            )

            deadline = time.time() + max(30, timeout_seconds)
            measurements: dict[str, Any] | None = None
            while time.time() < deadline:
                serial = self._run(
                    [
                        "compute",
                        "instances",
                        "get-serial-port-output",
                        name,
                        "--project",
                        cfg.project_id,
                        "--zone",
                        cfg.zone,
                        "--port",
                        "1",
                    ],
                    capture=True,
                    check=False,
                )
                text = serial.stdout or ""
                for line in text.splitlines():
                    line = line.strip()
                    if line.startswith("EASYENCLAVE_MEASUREMENTS="):
                        payload = line.split("=", 1)[1]
                        measurements = json.loads(payload)
                        break
                    if line.startswith("EASYENCLAVE_MEASURE_ERROR="):
                        _fatal(f"Measure VM error: {line.split('=', 1)[1]}")
                if measurements is not None:
                    break
                time.sleep(5)

            if measurements is None:
                _fatal("Timed out waiting for measure output from GCP VM")
            return measurements
        finally:
            try:
                os.unlink(startup_script)
            except OSError:
                pass
            self._run(
                [
                    "compute",
                    "instances",
                    "delete",
                    name,
                    "--project",
                    cfg.project_id,
                    "--zone",
                    cfg.zone,
                    "--quiet",
                ],
                capture=True,
                check=False,
            )


def _add_size_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--size", choices=sorted(NODE_SIZES.keys()), default="standard")
    parser.add_argument("--memory-gib", type=int, default=None)
    parser.add_argument("--vcpu-count", type=int, default=None)
    parser.add_argument("--disk-gib", type=int, default=None)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="EasyEnclave GCP CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    cp_parser = subparsers.add_parser("control-plane", help="Control-plane operations")
    cp_sub = cp_parser.add_subparsers(dest="cp_command", required=True)
    cp_new = cp_sub.add_parser("new", help="Create GCP control-plane VM")
    cp_new.add_argument("-i", "--image", default="", help="Ignored in GCP mode")
    cp_new.add_argument("--port", type=int, default=8080)
    cp_new.add_argument("--wait", action="store_true")
    cp_new.add_argument("--bootstrap-timeout", type=int, default=600)
    cp_new.add_argument("--debug", action="store_true")
    cp_new.add_argument("--bootstrap-measurers", action="store_true")
    cp_new.add_argument("--no-bootstrap-measurers", action="store_true")
    cp_new.add_argument("--bootstrap-sizes", default="tiny")
    _add_size_args(cp_new)

    vm_parser = subparsers.add_parser("vm", help="VM lifecycle")
    vm_sub = vm_parser.add_subparsers(dest="vm_command", required=True)

    vm_new = vm_sub.add_parser("new", help="Create GCP agent VM")
    vm_new.add_argument("-i", "--image", default="", help="Ignored in GCP mode")
    vm_new.add_argument("--easyenclave-url", default="https://app.easyenclave.com")
    vm_new.add_argument(
        "--intel-api-key",
        default=os.environ.get("ITA_API_KEY") or os.environ.get("INTEL_API_KEY", ""),
    )
    vm_new.add_argument("--wait", action="store_true")
    vm_new.add_argument("--debug", action="store_true")
    vm_new.add_argument("--cloud-provider", default="gcp")
    vm_new.add_argument("--availability-zone", default="")
    vm_new.add_argument("--region", default="")
    vm_new.add_argument("--datacenter", default="")
    _add_size_args(vm_new)

    vm_sub.add_parser("list", help="List managed GCP VMs")

    vm_delete = vm_sub.add_parser("delete", help="Delete managed GCP VM(s)")
    vm_delete.add_argument("name")
    vm_delete.add_argument("--easyenclave-url", default="", help="Ignored")
    vm_delete.add_argument("--admin-token", default="", help="Ignored")

    vm_measure = vm_sub.add_parser("measure", help="Measure a temporary GCP TDX VM")
    vm_measure.add_argument("-i", "--image", default="", help="Ignored in GCP mode")
    vm_measure.add_argument("--timeout", type=int, default=600)
    vm_measure.add_argument("--json", action="store_true")
    _add_size_args(vm_measure)

    return parser


def main() -> None:
    args = _build_parser().parse_args()
    mgr = GcpCli(Path(os.environ.get("GITHUB_WORKSPACE", ".")))

    if args.command == "control-plane" and args.cp_command == "new":
        result = mgr.control_plane_new(
            port=int(args.port),
            wait=bool(args.wait),
            wait_timeout_seconds=int(args.bootstrap_timeout),
        )
        print(json.dumps(result, indent=2))
        return

    if args.command == "vm" and args.vm_command == "new":
        result = mgr.vm_new(
            node_size=str(args.size),
            control_plane_url=str(args.easyenclave_url),
            intel_api_key=str(args.intel_api_key),
            cloud_provider=str(args.cloud_provider),
            availability_zone=str(args.availability_zone),
            region=str(args.region),
            datacenter=str(args.datacenter),
            wait=bool(args.wait),
            wait_timeout_seconds=600,
        )
        print(json.dumps(result, indent=2))
        return

    if args.command == "vm" and args.vm_command == "list":
        for name in mgr.vm_list():
            print(name)
        return

    if args.command == "vm" and args.vm_command == "delete":
        mgr.vm_delete(str(args.name))
        return

    if args.command == "vm" and args.vm_command == "measure":
        result = mgr.vm_measure(size=str(args.size), timeout_seconds=int(args.timeout))
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(result.get("mrtd") or "")
        return

    _fatal("Unsupported command")


if __name__ == "__main__":
    main()
