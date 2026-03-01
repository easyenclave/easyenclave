#!/usr/bin/env python3
"""EasyEnclave GCP infrastructure CLI.

This is a GCP-only orchestrator for:
- control-plane VM bootstrap
- agent VM lifecycle
- one-shot measurement VMs for trusted values
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
from typing import Any

NODE_SIZES: dict[str, dict[str, Any]] = {
    "tiny": {"machine_type": "c3-standard-4", "disk_gib": 200},
    "standard": {"machine_type": "c3-standard-8", "disk_gib": 200},
    "llm": {"machine_type": "c3-standard-22", "disk_gib": 200},
}


def _fatal(message: str, code: int = 1) -> None:
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(code)


def _warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)


def _normalize_name(value: str, *, max_len: int = 63) -> str:
    cleaned = re.sub(r"[^a-z0-9-]+", "-", value.strip().lower())
    cleaned = re.sub(r"-+", "-", cleaned).strip("-")
    if not cleaned:
        cleaned = "easyenclave"
    cleaned = cleaned[:max_len].rstrip("-")
    return cleaned or "easyenclave"


def _network_slug(value: str) -> str:
    return _normalize_name(value, max_len=48)


def _env_first(*keys: str) -> str:
    for key in keys:
        val = (os.environ.get(key) or "").strip()
        if val:
            return val
    return ""


def _coerce_disk_gib(default_gib: int) -> int:
    raw = _env_first("EE_GCP_BOOT_DISK_GB", "GCP_BOOT_DISK_GB")
    if not raw:
        return default_gib
    try:
        parsed = int(raw)
    except ValueError:
        _warn(f"Ignoring invalid disk size override: {raw!r}")
        return default_gib
    return max(default_gib, parsed)


@dataclass
class GcpConfig:
    project_id: str
    zone: str
    image_project: str
    image_name: str | None
    image_family: str | None
    service_account_key_json: str | None


class GcpApi:
    def __init__(self, cfg: GcpConfig):
        self.cfg = cfg

    def run(self, args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
        cmd = ["gcloud", *args]
        proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
        if check and proc.returncode != 0:
            detail = (proc.stderr or "").strip() or (proc.stdout or "").strip()
            if not detail:
                detail = f"exit_code={proc.returncode}"
            raise RuntimeError(f"gcloud failed: {' '.join(cmd)}\n{detail}")
        return proc

    def run_json(self, args: list[str]) -> Any:
        proc = self.run([*args, "--format=json"], check=True)
        raw = (proc.stdout or "").strip()
        if not raw:
            return {}
        return json.loads(raw)

    def activate_auth(self) -> None:
        if self.cfg.service_account_key_json:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
                tf.write(self.cfg.service_account_key_json)
                key_path = tf.name
            try:
                self.run(["auth", "activate-service-account", "--key-file", key_path])
            finally:
                try:
                    os.unlink(key_path)
                except OSError:
                    pass
        self.run(["config", "set", "project", self.cfg.project_id])

    def image_args(self) -> list[str]:
        args = ["--image-project", self.cfg.image_project]
        if self.cfg.image_name:
            args.extend(["--image", self.cfg.image_name])
            return args
        if self.cfg.image_family:
            args.extend(["--image-family", self.cfg.image_family])
            return args
        _fatal("Missing image source: set EE_GCP_IMAGE_NAME or EE_GCP_IMAGE_FAMILY")

    def zone_candidates(self, preferred_zone: str) -> list[str]:
        ordered: list[str] = []
        deprioritized: list[str] = []

        def add_csv(raw: str) -> None:
            for item in raw.split(","):
                zone = item.strip()
                if zone and zone not in ordered:
                    ordered.append(zone)

        def add_deprioritized_csv(raw: str) -> None:
            for item in raw.split(","):
                zone = item.strip()
                if zone and zone not in deprioritized:
                    deprioritized.append(zone)

        add_csv(preferred_zone)
        add_csv(_env_first("GCP_FALLBACK_ZONES", "EE_GCP_FALLBACK_ZONES"))
        add_deprioritized_csv(_env_first("GCP_DEPRIORITIZED_ZONES", "EE_GCP_DEPRIORITIZED_ZONES"))

        if preferred_zone.startswith("us-central1-"):
            add_csv("us-central1-a,us-central1-b,us-central1-c,us-central1-f")
            if "us-central1-f" not in deprioritized:
                deprioritized.append("us-central1-f")

        if not ordered:
            ordered = [preferred_zone]

        if deprioritized:
            leading = [z for z in ordered if z not in deprioritized]
            trailing = [z for z in ordered if z in deprioritized]
            ordered = leading + trailing
        return ordered

    def machine_type(self, size: str) -> str:
        key = size.strip().lower()
        if key not in NODE_SIZES:
            _fatal(f"Unsupported size '{size}'. Allowed: {', '.join(sorted(NODE_SIZES))}")
        return str(NODE_SIZES[key]["machine_type"])

    def list_instances(self) -> list[dict[str, Any]]:
        data = self.run_json(
            [
                "compute",
                "instances",
                "list",
                "--project",
                self.cfg.project_id,
                "--filter",
                "labels.easyenclave=managed",
            ]
        )
        return data if isinstance(data, list) else []

    def describe_instance(self, name: str, zone: str | None = None) -> dict[str, Any]:
        return self.run_json(
            [
                "compute",
                "instances",
                "describe",
                name,
                "--project",
                self.cfg.project_id,
                "--zone",
                zone or self.cfg.zone,
            ]
        )

    def create_instance(
        self,
        *,
        name: str,
        machine_type: str,
        startup_script_path: str,
        labels: dict[str, str],
        disk_gib: int,
        preferred_zone: str,
    ) -> tuple[dict[str, Any], str]:
        label_parts: list[str] = []
        for key, value in labels.items():
            norm_key = _normalize_name(key, max_len=63)
            norm_value = _normalize_name(str(value), max_len=63)
            label_parts.append(f"{norm_key}={norm_value}")
        labels_arg = ",".join(label_parts)

        last_error: Exception | None = None
        for zone in self.zone_candidates(preferred_zone):
            cmd = [
                "compute",
                "instances",
                "create",
                name,
                "--project",
                self.cfg.project_id,
                "--zone",
                zone,
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
                "--labels",
                labels_arg,
                "--metadata",
                "serial-port-enable=1",
                "--metadata-from-file",
                f"startup-script={startup_script_path}",
                "--scopes",
                "https://www.googleapis.com/auth/cloud-platform",
                *self.image_args(),
            ]
            try:
                self.run(cmd, check=True)
                self.cfg.zone = zone
                return self.describe_instance(name=name, zone=zone), zone
            except Exception as exc:
                last_error = exc
                msg = str(exc).lower()
                retryable = (
                    "configuration_availability" in msg
                    or "does not have enough resources" in msg
                    or "not supported in the" in msg
                )
                if retryable:
                    _warn(f"Zone '{zone}' unavailable for machine_type={machine_type}; retrying")
                    continue
                raise

        if last_error:
            raise last_error
        _fatal("create_instance failed")

    def wait_instance_running(
        self, *, name: str, zone: str, timeout_seconds: int
    ) -> dict[str, Any]:
        deadline = time.time() + max(5, timeout_seconds)
        while time.time() < deadline:
            inst = self.describe_instance(name=name, zone=zone)
            if str(inst.get("status") or "").upper() == "RUNNING":
                return inst
            time.sleep(3)
        _fatal(f"Timed out waiting for VM '{name}' to reach RUNNING")

    def delete_instance(self, name: str, zone: str, *, check: bool = False) -> None:
        self.run(
            [
                "compute",
                "instances",
                "delete",
                name,
                "--project",
                self.cfg.project_id,
                "--zone",
                zone,
                "--quiet",
            ],
            check=check,
        )


def _resolve_config(zone_override: str | None = None) -> GcpConfig:
    project_id = _env_first("GCP_PROJECT_ID", "STAGING_GCP_PROJECT_ID", "PRODUCTION_GCP_PROJECT_ID")
    if not project_id:
        _fatal("Missing GCP_PROJECT_ID")

    zone = (
        (zone_override or "").strip()
        or _env_first("GCP_ZONE", "AGENT_DATACENTER_AZ")
        or "us-central1-a"
    )

    image_project = _env_first("EE_GCP_IMAGE_PROJECT") or project_id
    image_name = _env_first("EE_GCP_IMAGE_NAME") or None
    image_family = _env_first("EE_GCP_IMAGE_FAMILY") or "easyenclave-agent-main"

    service_key = _env_first(
        "GCP_SERVICE_ACCOUNT_KEY",
        "STAGING_GCP_SERVICE_ACCOUNT_KEY",
        "PRODUCTION_GCP_SERVICE_ACCOUNT_KEY",
    )

    return GcpConfig(
        project_id=project_id,
        zone=zone,
        image_project=image_project,
        image_name=image_name,
        image_family=image_family,
        service_account_key_json=service_key or None,
    )


def _instance_ips(instance: dict[str, Any]) -> tuple[str | None, str | None]:
    internal_ip: str | None = None
    external_ip: str | None = None
    nics = instance.get("networkInterfaces") or []
    if nics:
        nic0 = nics[0] or {}
        internal_ip = nic0.get("networkIP")
        access_cfgs = nic0.get("accessConfigs") or []
        if access_cfgs:
            external_ip = access_cfgs[0].get("natIP")
    return internal_ip, external_ip


def _probe_http_health(url: str) -> bool:
    health_url = f"{url.rstrip('/')}/health"
    proc = subprocess.run(
        ["curl", "-fsS", "--max-time", "3", health_url],
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def _wait_http_health_any(candidates: list[str], timeout_seconds: int) -> str | None:
    urls = [u for u in candidates if str(u).strip()]
    if not urls:
        return None
    deadline = time.time() + max(5, timeout_seconds)
    while time.time() < deadline:
        for candidate in urls:
            if _probe_http_health(candidate):
                return candidate
        time.sleep(3)
    return None


def _instance_serial_port_tail(gcp: GcpApi, *, name: str, zone: str, lines: int = 120) -> str:
    proc = gcp.run(
        [
            "compute",
            "instances",
            "get-serial-port-output",
            name,
            "--project",
            gcp.cfg.project_id,
            "--zone",
            zone,
            "--port",
            "1",
        ],
        check=False,
    )
    text = (proc.stdout or "").strip()
    if not text:
        return ""
    tail = text.splitlines()[-max(1, int(lines)) :]
    return "\n".join(tail)


def _write_agent_startup_script(config: dict[str, Any]) -> str:
    script = f"""#!/usr/bin/env bash
set -euo pipefail
mkdir -p /etc/easyenclave
cat > /etc/easyenclave/agent.json <<'EOF_CONFIG'
{json.dumps(config, indent=2, sort_keys=True)}
EOF_CONFIG
chmod 0600 /etc/easyenclave/agent.json
systemctl daemon-reload || true
systemctl disable --now easyenclave-control-plane.service || true
systemctl enable easyenclave-agent.service || true
systemctl restart easyenclave-agent.service || true
"""
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as tf:
        tf.write(script)
        return tf.name


def _write_control_plane_startup_script(config: dict[str, Any]) -> str:
    local_port = int(config.get("port") or 8080)
    script = f"""#!/usr/bin/env bash
set -euo pipefail
exec > >(tee -a /var/log/easyenclave-control-plane-bootstrap.log /dev/ttyS0) 2>&1
mkdir -p /etc/easyenclave
cat > /etc/easyenclave/control-plane.json <<'EOF_CONFIG'
{json.dumps(config, indent=2, sort_keys=True)}
EOF_CONFIG
chmod 0600 /etc/easyenclave/control-plane.json
systemctl daemon-reload || true
systemctl disable --now easyenclave-agent.service || true
systemctl enable easyenclave-control-plane.service || true
systemctl restart easyenclave-control-plane.service || true
echo "__EE_CP_LOCAL_HEALTH_WAIT__ port={local_port}"
for _ in $(seq 1 150); do
  if curl -fsS "http://127.0.0.1:{local_port}/health" >/dev/null 2>&1; then
    echo "__EE_CP_LOCAL_HEALTH_OK__"
    break
  fi
  sleep 2
done
if ! curl -fsS "http://127.0.0.1:{local_port}/health" >/dev/null 2>&1; then
  echo "__EE_CP_LOCAL_HEALTH_TIMEOUT__"
fi
"""
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as tf:
        tf.write(script)
        return tf.name


def _write_measure_startup_script(node_size: str) -> str:
    cfg = {"node_size": node_size}
    script = f"""#!/usr/bin/env bash
set -euo pipefail
exec > >(tee -a /var/log/easyenclave-measure.log /dev/ttyS0) 2>&1
mkdir -p /etc/easyenclave
cat > /etc/easyenclave/measure.json <<'EOF_CONFIG'
{json.dumps(cfg, indent=2, sort_keys=True)}
EOF_CONFIG
chmod 0600 /etc/easyenclave/measure.json
if [ ! -x /usr/local/bin/ee-agent ]; then
  echo "EASYENCLAVE_MEASURE_ERROR=missing_agent_binary"
  systemctl poweroff || true
  exit 0
fi
EE_AGENT_MODE=measure EASYENCLAVE_CONFIG=/etc/easyenclave/measure.json timeout 300 /usr/local/bin/ee-agent || true
sleep 2
systemctl poweroff || true
"""
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as tf:
        tf.write(script)
        return tf.name


def _control_plane_hostnames(
    domain: str, env_name: str, network_name: str
) -> tuple[str, str | None]:
    alias = f"app-staging.{domain}" if env_name == "staging" else f"app.{domain}"
    slug = _network_slug(network_name)
    if slug:
        return alias, f"{slug}.{domain}"
    return alias, None


def _build_control_plane_config(port: int, cp_url_for_agents: str) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "port": int(port),
        "control_plane_image": _env_first("CONTROL_PLANE_IMAGE")
        or f"ghcr.io/{_env_first('GITHUB_REPOSITORY') or 'easyenclave/easyenclave'}/control-plane-rust:latest",
        "easyenclave_domain": _env_first("EASYENCLAVE_DOMAIN") or "easyenclave.com",
        "easyenclave_env": _env_first("EASYENCLAVE_ENV") or "staging",
        "easyenclave_network_name": _env_first("EASYENCLAVE_NETWORK_NAME"),
        "easyenclave_boot_id": _env_first("EASYENCLAVE_BOOT_ID"),
        "easyenclave_git_sha": _env_first("EASYENCLAVE_GIT_SHA"),
        "easyenclave_release_tag": _env_first("EASYENCLAVE_RELEASE_TAG"),
        "easyenclave_cp_url": cp_url_for_agents,
        "cloudflare_api_token": _env_first("CLOUDFLARE_API_TOKEN"),
        "cloudflare_account_id": _env_first("CLOUDFLARE_ACCOUNT_ID"),
        "cloudflare_zone_id": _env_first("CLOUDFLARE_ZONE_ID"),
        "admin_password": _env_first("CP_ADMIN_PASSWORD", "ADMIN_PASSWORD"),
        "admin_github_logins": _env_first("ADMIN_GITHUB_LOGINS"),
        "admin_password_hash": _env_first("ADMIN_PASSWORD_HASH"),
        "ee_agent_ita_api_key": _env_first("EE_AGENT_ITA_API_KEY", "ITA_API_KEY", "INTEL_API_KEY"),
        "gcp_project_id": _env_first("GCP_PROJECT_ID"),
        "gcp_service_account_key": _env_first("GCP_SERVICE_ACCOUNT_KEY"),
        "ee_gcp_image_project": _env_first("EE_GCP_IMAGE_PROJECT"),
        "ee_gcp_image_family": _env_first("EE_GCP_IMAGE_FAMILY"),
        "ee_gcp_image_name": _env_first("EE_GCP_IMAGE_NAME"),
        "github_oauth_client_id": _env_first("GITHUB_OAUTH_CLIENT_ID"),
        "github_oauth_client_secret": _env_first("GITHUB_OAUTH_CLIENT_SECRET"),
        "github_oauth_redirect_uri": _env_first("GITHUB_OAUTH_REDIRECT_URI"),
        "stripe_secret_key": _env_first("STRIPE_SECRET_KEY"),
        "stripe_webhook_secret": _env_first("STRIPE_WEBHOOK_SECRET"),
        "trusted_agent_mrtds": _env_first("TRUSTED_AGENT_MRTDS"),
        "trusted_proxy_mrtds": _env_first("TRUSTED_PROXY_MRTDS"),
        "trusted_agent_rtmrs": _env_first("TRUSTED_AGENT_RTMRS"),
        "trusted_proxy_rtmrs": _env_first("TRUSTED_PROXY_RTMRS"),
        "trusted_agent_rtmrs_by_size": _env_first("TRUSTED_AGENT_RTMRS_BY_SIZE"),
        "trusted_proxy_rtmrs_by_size": _env_first("TRUSTED_PROXY_RTMRS_BY_SIZE"),
        "tcb_enforcement_mode": _env_first("TCB_ENFORCEMENT_MODE"),
        "allowed_tcb_statuses": _env_first("ALLOWED_TCB_STATUSES"),
        "nonce_enforcement_mode": _env_first("NONCE_ENFORCEMENT_MODE"),
        "nonce_ttl_seconds": _env_first("NONCE_TTL_SECONDS"),
        "rtmr_enforcement_mode": _env_first("RTMR_ENFORCEMENT_MODE"),
        "signature_verification_mode": _env_first("SIGNATURE_VERIFICATION_MODE"),
        "cp_to_agent_attestation_mode": _env_first("CP_TO_AGENT_ATTESTATION_MODE"),
        "auth_require_github_oauth_in_production": _env_first(
            "AUTH_REQUIRE_GITHUB_OAUTH_IN_PRODUCTION"
        ),
        "password_login_enabled": _env_first("PASSWORD_LOGIN_ENABLED"),
        "auth_allow_password_login_in_production": _env_first(
            "AUTH_ALLOW_PASSWORD_LOGIN_IN_PRODUCTION"
        ),
        "billing_enabled": _env_first("BILLING_ENABLED"),
        "billing_capacity_request_dev_simulation": _env_first(
            "BILLING_CAPACITY_REQUEST_DEV_SIMULATION"
        ),
        "billing_platform_account_id": _env_first("BILLING_PLATFORM_ACCOUNT_ID"),
        "billing_contributor_pool_bps": _env_first("BILLING_CONTRIBUTOR_POOL_BPS"),
        "default_gcp_tiny_capacity_enabled": _env_first("DEFAULT_GCP_TINY_CAPACITY_ENABLED"),
        "default_gcp_tiny_capacity_count": _env_first("DEFAULT_GCP_TINY_CAPACITY_COUNT"),
        "default_gcp_tiny_capacity_dispatch": _env_first("DEFAULT_GCP_TINY_CAPACITY_DISPATCH"),
        "cp_attestation_allow_insecure": _env_first("CP_ATTESTATION_ALLOW_INSECURE"),
        "cp_ita_jwks_url": _env_first("CP_ITA_JWKS_URL")
        or "https://portal.trustauthority.intel.com/certs",
        "cp_ita_issuer": _env_first("CP_ITA_ISSUER") or "https://portal.trustauthority.intel.com",
        "cp_ita_audience": _env_first("CP_ITA_AUDIENCE"),
        "cp_ita_jwks_ttl_seconds": _env_first("CP_ITA_JWKS_TTL_SECONDS"),
    }
    return {k: v for k, v in cfg.items() if v not in ("", None)}


def control_plane_new(*, port: int, wait: bool, timeout_seconds: int) -> dict[str, Any]:
    cfg = _resolve_config()
    gcp = GcpApi(cfg)
    gcp.activate_auth()

    env_name = (_env_first("EASYENCLAVE_ENV") or "staging").lower()
    cp_size = (_env_first("CONTROL_PLANE_NODE_SIZE") or "").strip().lower()
    if not cp_size:
        cp_size = "tiny" if env_name == "staging" else "standard"
    if cp_size not in NODE_SIZES:
        _warn(f"Unsupported CONTROL_PLANE_NODE_SIZE='{cp_size}', falling back to 'standard'.")
        cp_size = "standard"
    network_name = _env_first("EASYENCLAVE_NETWORK_NAME")
    domain = _env_first("EASYENCLAVE_DOMAIN") or "easyenclave.com"

    alias_host, network_host = _control_plane_hostnames(domain, env_name, network_name)
    cp_url_for_agents = f"https://{network_host or alias_host}"

    name = _normalize_name(
        f"ee-cp-{env_name}-{network_name or uuid.uuid4().hex[:8]}-{int(time.time())}",
        max_len=63,
    )

    startup_script = _write_control_plane_startup_script(
        _build_control_plane_config(port, cp_url_for_agents)
    )
    try:
        _, zone = gcp.create_instance(
            name=name,
            machine_type=gcp.machine_type(cp_size),
            startup_script_path=startup_script,
            labels={
                "easyenclave": "managed",
                "ee_role": "control-plane",
                "ee_env": env_name,
                "ee_network": network_name or "default",
            },
            disk_gib=_coerce_disk_gib(200),
            preferred_zone=cfg.zone,
        )
    finally:
        try:
            os.unlink(startup_script)
        except OSError:
            pass

    inst = gcp.wait_instance_running(name=name, zone=zone, timeout_seconds=300)
    internal_ip, external_ip = _instance_ips(inst)

    public_alias_url = f"https://{alias_host}"
    network_url = f"https://{network_host}" if network_host else ""
    ip_fallback_url = (
        f"http://{external_ip or internal_ip}:8080" if (external_ip or internal_ip) else ""
    )

    selected_url = public_alias_url or network_url
    if wait:
        candidates = [u for u in [ip_fallback_url, public_alias_url, network_url] if u]
        healthy_url = _wait_http_health_any(candidates, timeout_seconds)
        if healthy_url:
            selected_url = healthy_url
        else:
            serial_tail = _instance_serial_port_tail(gcp, name=name, zone=zone, lines=120)
            if serial_tail:
                _warn("Control-plane serial-port tail follows:")
                print(serial_tail, file=sys.stderr)
                if "__EE_CP_LOCAL_HEALTH_OK__" in serial_tail:
                    _warn(
                        "Control plane reported local /health OK but remained externally "
                        "unreachable during bootstrap timeout; proceeding with hostname URL."
                    )
                    selected_url = public_alias_url or network_url or ip_fallback_url
                    return {
                        "name": name,
                        "zone": zone,
                        "ip": external_ip or internal_ip,
                        "internal_ip": internal_ip,
                        "external_ip": external_ip,
                        "control_plane_url": selected_url,
                        "control_plane_hostname": alias_host,
                        "control_plane_network_hostname": network_host,
                        "bootstrap_agents": [],
                    }
            _fatal(
                "Control plane did not become healthy. "
                f"Tried: {', '.join(candidates) if candidates else 'no candidates'}"
            )

    return {
        "name": name,
        "zone": zone,
        "ip": external_ip or internal_ip,
        "internal_ip": internal_ip,
        "external_ip": external_ip,
        "control_plane_url": selected_url,
        "control_plane_hostname": alias_host,
        "control_plane_network_hostname": network_host,
        "bootstrap_agents": [],
    }


def vm_new(
    *,
    size: str,
    cp_url: str,
    ita_api_key: str,
    zone: str,
    region: str,
    datacenter: str,
    wait: bool,
    timeout_seconds: int,
) -> dict[str, Any]:
    cfg = _resolve_config(zone_override=zone)
    gcp = GcpApi(cfg)
    gcp.activate_auth()

    node_size = size.strip().lower()
    if node_size not in NODE_SIZES:
        _fatal(f"Unsupported size '{size}'. Allowed: {', '.join(sorted(NODE_SIZES))}")

    vm_name = _normalize_name(f"tdx-agent-{uuid.uuid4().hex[:10]}")
    datacenter_label = (datacenter or f"gcp:{cfg.zone}").strip().lower()

    config = {
        "control_plane_url": cp_url,
        "cloud_provider": "gcp",
        "availability_zone": cfg.zone,
        "region": region.strip(),
        "datacenter": datacenter_label,
        "node_size": node_size,
        "intel_api_key": ita_api_key,
        "ita_api_key": ita_api_key,
        "easyenclave_env": _env_first("EASYENCLAVE_ENV") or "staging",
        "easyenclave_network_name": _env_first("EASYENCLAVE_NETWORK_NAME"),
    }

    startup_script = _write_agent_startup_script(config)
    try:
        inst, resolved_zone = gcp.create_instance(
            name=vm_name,
            machine_type=gcp.machine_type(node_size),
            startup_script_path=startup_script,
            labels={
                "easyenclave": "managed",
                "ee_role": "agent",
                "ee_env": _env_first("EASYENCLAVE_ENV") or "staging",
                "ee_network": _env_first("EASYENCLAVE_NETWORK_NAME") or "default",
                "ee_node_size": node_size,
            },
            disk_gib=_coerce_disk_gib(int(NODE_SIZES[node_size]["disk_gib"])),
            preferred_zone=cfg.zone,
        )
    finally:
        try:
            os.unlink(startup_script)
        except OSError:
            pass

    if wait:
        inst = gcp.wait_instance_running(
            name=vm_name, zone=resolved_zone, timeout_seconds=timeout_seconds
        )

    internal_ip, external_ip = _instance_ips(inst)
    return {
        "name": vm_name,
        "zone": resolved_zone,
        "internal_ip": internal_ip,
        "external_ip": external_ip,
        "cloud_provider": "gcp",
        "datacenter": datacenter_label or f"gcp:{resolved_zone}",
        "node_size": node_size,
    }


def vm_list(*, as_json: bool) -> None:
    cfg = _resolve_config()
    gcp = GcpApi(cfg)
    gcp.activate_auth()
    items = gcp.list_instances()
    if as_json:
        payload = []
        for item in items:
            zone = str(item.get("zone") or "").rsplit("/", 1)[-1]
            payload.append(
                {
                    "name": item.get("name"),
                    "zone": zone,
                    "status": item.get("status"),
                    "labels": item.get("labels") or {},
                }
            )
        print(json.dumps(payload, indent=2))
        return

    names = sorted([str(i.get("name") or "").strip() for i in items if i.get("name")])
    for name in names:
        print(name)


def vm_delete(name: str) -> None:
    cfg = _resolve_config()
    gcp = GcpApi(cfg)
    gcp.activate_auth()

    instances = gcp.list_instances()
    by_name: dict[str, str] = {}
    for item in instances:
        vm_name = str(item.get("name") or "").strip()
        zone = str(item.get("zone") or "").strip().rsplit("/", 1)[-1]
        if vm_name and zone:
            by_name[vm_name] = zone

    if name == "all":
        for vm_name, zone in sorted(by_name.items()):
            gcp.delete_instance(vm_name, zone, check=False)
        return

    zone = by_name.get(name) or cfg.zone
    gcp.delete_instance(name, zone, check=True)


def vm_measure(*, size: str, timeout_seconds: int) -> dict[str, Any]:
    node_size = size.strip().lower()
    if node_size not in NODE_SIZES:
        _fatal(f"Unsupported size '{size}'. Allowed: {', '.join(sorted(NODE_SIZES))}")

    cfg = _resolve_config()
    gcp = GcpApi(cfg)
    gcp.activate_auth()

    vm_name = _normalize_name(f"ee-measure-{node_size}-{uuid.uuid4().hex[:8]}")
    startup_script = _write_measure_startup_script(node_size)

    resolved_zone = cfg.zone
    try:
        _, resolved_zone = gcp.create_instance(
            name=vm_name,
            machine_type=gcp.machine_type(node_size),
            startup_script_path=startup_script,
            labels={
                "easyenclave": "managed",
                "ee_role": "measure",
                "ee_env": _env_first("EASYENCLAVE_ENV") or "staging",
            },
            disk_gib=_coerce_disk_gib(int(NODE_SIZES[node_size]["disk_gib"])),
            preferred_zone=cfg.zone,
        )

        deadline = time.time() + max(30, timeout_seconds)
        measurements: dict[str, Any] | None = None

        while time.time() < deadline:
            serial = gcp.run(
                [
                    "compute",
                    "instances",
                    "get-serial-port-output",
                    vm_name,
                    "--project",
                    cfg.project_id,
                    "--zone",
                    resolved_zone,
                    "--port",
                    "1",
                ],
                check=False,
            )
            text = serial.stdout or ""
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("EASYENCLAVE_MEASUREMENTS="):
                    measurements = json.loads(line.split("=", 1)[1])
                    break
                if line.startswith("EASYENCLAVE_MEASURE_ERROR="):
                    _fatal(f"Measure VM error: {line.split('=', 1)[1]}")
            if measurements is not None:
                break
            time.sleep(5)

        if measurements is None:
            _fatal("Timed out waiting for measurement output")
        return measurements
    finally:
        try:
            os.unlink(startup_script)
        except OSError:
            pass
        gcp.delete_instance(vm_name, resolved_zone, check=False)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="EasyEnclave GCP infrastructure CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    cp = sub.add_parser("control-plane", help="Control-plane operations")
    cp_sub = cp.add_subparsers(dest="cp_command", required=True)

    cp_new = cp_sub.add_parser("new", help="Create control-plane VM")
    cp_new.add_argument("--port", type=int, default=8080)
    cp_new.add_argument("--wait", action="store_true")
    cp_new.add_argument("--timeout", type=int, default=600)

    vm = sub.add_parser("vm", help="Agent/measure VM operations")
    vm_sub = vm.add_subparsers(dest="vm_command", required=True)

    vm_new_cmd = vm_sub.add_parser("new", help="Create agent VM")
    vm_new_cmd.add_argument("--size", choices=sorted(NODE_SIZES), default="standard")
    vm_new_cmd.add_argument(
        "--cp-url",
        default=_env_first("CP_URL") or "https://app.easyenclave.com",
        help="Control plane URL for agent registration",
    )
    vm_new_cmd.add_argument(
        "--ita-api-key",
        default=_env_first("ITA_API_KEY", "INTEL_API_KEY"),
        help="Intel Trust Authority API key",
    )
    vm_new_cmd.add_argument("--zone", default=_env_first("GCP_ZONE", "AGENT_DATACENTER_AZ") or "")
    vm_new_cmd.add_argument("--region", default=_env_first("AGENT_DATACENTER_REGION") or "")
    vm_new_cmd.add_argument("--datacenter", default=_env_first("AGENT_DATACENTER") or "")
    vm_new_cmd.add_argument("--wait", action="store_true")
    vm_new_cmd.add_argument("--timeout", type=int, default=600)

    vm_list_cmd = vm_sub.add_parser("list", help="List managed EasyEnclave instances")
    vm_list_cmd.add_argument("--json", action="store_true")

    vm_delete_cmd = vm_sub.add_parser("delete", help="Delete one managed instance or 'all'")
    vm_delete_cmd.add_argument("name")

    vm_measure_cmd = vm_sub.add_parser("measure", help="Run one-shot measurement VM")
    vm_measure_cmd.add_argument("--size", choices=sorted(NODE_SIZES), default="standard")
    vm_measure_cmd.add_argument("--timeout", type=int, default=600)
    vm_measure_cmd.add_argument("--json", action="store_true")

    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.command == "control-plane" and args.cp_command == "new":
        result = control_plane_new(
            port=int(args.port),
            wait=bool(args.wait),
            timeout_seconds=int(args.timeout),
        )
        print(json.dumps(result, indent=2))
        return

    if args.command == "vm" and args.vm_command == "new":
        if not str(args.cp_url).strip():
            _fatal("--cp-url is required")
        if not str(args.ita_api_key).strip():
            _fatal("--ita-api-key is required")
        result = vm_new(
            size=str(args.size),
            cp_url=str(args.cp_url),
            ita_api_key=str(args.ita_api_key),
            zone=str(args.zone),
            region=str(args.region),
            datacenter=str(args.datacenter),
            wait=bool(args.wait),
            timeout_seconds=int(args.timeout),
        )
        print(json.dumps(result, indent=2))
        return

    if args.command == "vm" and args.vm_command == "list":
        vm_list(as_json=bool(args.json))
        return

    if args.command == "vm" and args.vm_command == "delete":
        vm_delete(str(args.name))
        return

    if args.command == "vm" and args.vm_command == "measure":
        result = vm_measure(size=str(args.size), timeout_seconds=int(args.timeout))
        if bool(args.json):
            print(json.dumps(result, indent=2))
        else:
            print(str(result.get("mrtd") or ""))
        return

    _fatal("Unsupported command")


if __name__ == "__main__":
    main()
