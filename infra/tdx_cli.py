#!/usr/bin/env python3
"""TDX CLI - Manage TDX VM lifecycle.

Simple CLI for launching and managing TDX VMs with the launcher agent pre-installed.
VMs boot in "undeployed" state and register with the control plane.

Special command: `tdx control-plane new` launches a control plane in a TDX VM
and bootstraps measuring-capable agent VMs.
This bootstraps a new EasyEnclave network.

All deployments go through the control plane API - this CLI only handles VM lifecycle.
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib
from pathlib import Path

# Control plane mode config
CONTROL_PLANE_MODE = "control-plane"
AGENT_MODE = "agent"


# Node size presets: (memory_gib, vcpu_count, disk_gib)
# disk_gib=0 means no data disk (tmpfs-only fallback).
#
# NOTE: Keep defaults conservative for CI to avoid runaway storage usage on the
# self-hosted runner. Production can override via env vars.
def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as err:
        raise ValueError(f"Invalid int for {name}={raw!r}") from err


NODE_SIZES = {
    "tiny": (4, 4, 0),
    "standard": (16, 16, 0),
    "llm": (
        # Keep the default LLM preset small enough to boot on the self-hosted CI runner.
        # Production deployments can (and should) override via env vars.
        _env_int("EASYENCLAVE_LLM_MEM_GIB", 16),
        _env_int("EASYENCLAVE_LLM_VCPUS", 8),
        _env_int("EASYENCLAVE_LLM_DISK_GIB", 80),
    ),
}
# Network-level default; override with EASYENCLAVE_DEFAULT_SIZE env var.
# Early-stage networks run tiny; prod can set "standard" for more headroom.
DEFAULT_SIZE = os.environ.get("EASYENCLAVE_DEFAULT_SIZE", "tiny")


def tail_log(path: str, stop_event: threading.Event) -> None:
    """Tail a log file until stop_event is set.

    Args:
        path: Path to the log file to tail
        stop_event: Event to signal when to stop tailing
    """
    try:
        # Wait for file to exist
        while not stop_event.is_set() and not Path(path).exists():
            time.sleep(0.1)
        if stop_event.is_set():
            return
        with open(path, errors="replace") as f:
            # Read from beginning to catch boot messages
            while not stop_event.is_set():
                line = f.readline()
                if line:
                    print(line, end="", file=sys.stderr)
                else:
                    time.sleep(0.1)
    except PermissionError:
        print(f"Warning: Cannot read {path} (permission denied, try sudo)", file=sys.stderr)
    except Exception as e:
        print(f"Warning: Error reading {path}: {e}", file=sys.stderr)


class TDXManager:
    """Manages TDX VM lifecycle."""

    DOMAIN_PREFIX = "tdvirsh"
    WORKDIR = Path("/var/tmp/tdvirsh")
    VIRSH_CONNECT = "qemu:///system"

    def __init__(self, workspace: Path | None = None):
        self.workspace = workspace or Path.cwd()
        self.infra_dir = self._find_infra_dir()

    def _find_infra_dir(self) -> Path:
        """Find the infra directory."""
        for path in [
            self.workspace / "infra",
            Path(__file__).parent,
        ]:
            if path.exists():
                return path
        return Path(__file__).parent

    def _get_template(self) -> Path:
        """Get XML template path."""
        return self.infra_dir / "vm_templates" / "trust_domain_verity.xml.template"

    def _find_verity_image(self, image_path: str | None = None) -> dict:
        """Find verity image artifacts (kernel, initrd, rootfs, cmdline)."""
        artifacts_dir = (
            Path(image_path).resolve() if image_path else (self.infra_dir / "image" / "output")
        )
        if not artifacts_dir.is_dir():
            raise FileNotFoundError(
                f"Verity artifacts directory not found: {artifacts_dir}\n"
                "Build with: cd infra/image && nix develop --command make build"
            )

        files = {
            "kernel": artifacts_dir / "easyenclave.vmlinuz",
            "initrd": artifacts_dir / "easyenclave.initrd",
            "root": artifacts_dir / "easyenclave.root.raw",
            "cmdline_file": artifacts_dir / "easyenclave.cmdline",
        }
        missing = [str(path) for path in files.values() if not path.exists()]
        if missing:
            raise FileNotFoundError(
                "Missing verity image artifacts:\n"
                + "\n".join(f"  - {path}" for path in missing)
                + "\nBuild with: cd infra/image && nix develop --command make build"
            )

        return {
            "kernel": files["kernel"].resolve(),
            "initrd": files["initrd"].resolve(),
            "root": files["root"].resolve(),
            "cmdline": files["cmdline_file"].read_text().strip(),
        }

    def _encode_launcher_config_for_cmdline(self, launcher_config: dict) -> tuple[str, str]:
        """Encode launcher config for kernel cmdline.

        Returns:
            Tuple of (param_name, encoded_value), where param_name is either:
            - easyenclave.config  (plain base64 JSON)
            - easyenclave.configz (zlib-compressed base64 JSON)
        """
        import base64 as _b64

        # Compact JSON to keep cmdline payload as small as possible.
        config_json = json.dumps(launcher_config, separators=(",", ":")).encode()
        config_b64 = _b64.b64encode(config_json).decode()
        configz_b64 = _b64.b64encode(zlib.compress(config_json, level=9)).decode()

        # Prefer compressed payload when it is smaller.
        if len(configz_b64) < len(config_b64):
            return "easyenclave.configz", configz_b64
        return "easyenclave.config", config_b64

    def _virsh(self, *args, **kwargs) -> subprocess.CompletedProcess:
        """Run virsh command with system connection.

        Args:
            *args: virsh subcommand and arguments
            **kwargs: Passed to subprocess.run

        Returns:
            CompletedProcess result
        """
        cmd = ["virsh", "--connect", self.VIRSH_CONNECT, *args]
        kwargs.setdefault("capture_output", True)
        return subprocess.run(cmd, **kwargs)

    @staticmethod
    def _slug_name_component(value: str, default: str, max_len: int = 24) -> str:
        """Normalize a value for use in VM/domain names."""
        raw = (value or "").strip().lower()
        slug = re.sub(r"[^a-z0-9-]+", "-", raw).strip("-")
        slug = re.sub(r"-{2,}", "-", slug)
        if not slug:
            slug = default
        return slug[:max_len]

    def _resolve_vm_role_label(self, mode: str, launcher_config: dict) -> str:
        if mode == CONTROL_PLANE_MODE:
            return "cp"
        if mode == "measure":
            return "measure"
        return "agent"

    @staticmethod
    def _is_ip_host(host: str) -> bool:
        value = (host or "").strip()
        if not value:
            return False
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _resolve_network_label_from_cp_health(self, cp_url: str) -> str:
        """Resolve a stable network label from control-plane /health."""
        if not cp_url:
            return ""
        try:
            parsed = urllib.parse.urlparse(cp_url)
            health_url = urllib.parse.urlunparse(
                (parsed.scheme or "http", parsed.netloc, "/health", "", "", "")
            )
            req = urllib.request.Request(health_url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception:
            return ""

        boot_id = str(payload.get("boot_id") or "")
        if boot_id:
            # Example: bootstrap-22241734738-1 -> b22241734738
            match = re.search(r"bootstrap-(\d+)", boot_id)
            if match:
                return self._slug_name_component(f"b{match.group(1)}", "net", max_len=20)
            return self._slug_name_component(boot_id, "net", max_len=20)

        proxy_url = str(payload.get("proxy_url") or "")
        if proxy_url:
            try:
                host = urllib.parse.urlparse(proxy_url).hostname or ""
            except Exception:
                host = ""
            if host:
                parts = [p for p in host.split(".") if p]
                if parts and parts[0] == "app" and len(parts) > 1:
                    return self._slug_name_component(parts[1], "net", max_len=20)
                if parts:
                    return self._slug_name_component(parts[0], "net", max_len=20)
        return ""

    def _resolve_vm_network_label(self, launcher_config: dict) -> str:
        """Best-effort network label for VM naming."""
        direct = str(
            launcher_config.get("easyenclave_network_name")
            or launcher_config.get("network_name")
            or launcher_config.get("easyenclave_env")
            or ""
        )
        if direct:
            return self._slug_name_component(direct, "net", max_len=20)

        cp_url = str(launcher_config.get("control_plane_url") or "")
        if cp_url:
            try:
                host = urllib.parse.urlparse(cp_url).hostname or ""
            except Exception:
                host = ""
            if host:
                if host not in {"localhost", "127.0.0.1"} and not self._is_ip_host(host):
                    parts = [p for p in host.split(".") if p]
                    if parts and parts[0] == "app" and len(parts) > 1:
                        return self._slug_name_component(parts[1], "net", max_len=20)
                    if parts:
                        return self._slug_name_component(parts[0], "net", max_len=20)

                inferred = self._resolve_network_label_from_cp_health(cp_url)
                if inferred:
                    return inferred

        return "net"

    def vm_new(
        self,
        image: str | None = None,
        mode: str = AGENT_MODE,
        config: dict | None = None,
        debug: bool = False,
        memory_gib: int = 16,
        vcpu_count: int = 32,
        size_name: str = "",
        disk_gib: int = 0,
    ) -> dict:
        """Create and boot a new TDX VM.

        The VM boots with the launcher agent pre-installed, which will
        either run the control plane (if mode=control-plane) or register
        with the control plane and poll for deployments (if mode=agent).

        Args:
            image: Path to verity artifacts directory (auto-detected if not provided)
            mode: Launcher mode (control-plane or agent)
            config: Additional config to pass to launcher
            debug: If True, enable SSH and set password for debugging
            memory_gib: VM memory in GiB
            vcpu_count: Number of vCPUs
            disk_gib: Data disk size in GiB (0 = no disk, tmpfs-only fallback)

        Returns:
            Dict with vm_name, uuid, and info
        """
        template = self._get_template()

        if not template.exists():
            raise FileNotFoundError(f"XML template not found: {template}")

        # Create work directory with permissive access (multiple users may run VMs)
        self.WORKDIR.mkdir(parents=True, exist_ok=True)
        try:
            self.WORKDIR.chmod(0o1777)  # sticky bit + world writable (like /tmp)
        except PermissionError:
            pass  # Directory owned by another user, proceed anyway
        rand_str = uuid.uuid4().hex[:15]

        # Build launcher config.
        # Keep measure-mode cmdline deterministic so runtime RTMRs are stable
        # across repeated measurement boots.
        launcher_config = {
            "mode": mode,
            "node_size": size_name,
            **(config or {}),
        }
        if "vm_id" not in launcher_config:
            if mode == "measure":
                launcher_config["vm_id"] = f"measure-{size_name or 'default'}"
            else:
                launcher_config["vm_id"] = rand_str

        # Create serial console log file with world-readable permissions
        # (libvirt will append to it, preserving permissions)
        serial_log = self.WORKDIR / f"console.{rand_str}.log"
        serial_log.touch(mode=0o644)

        # Generate domain XML with unique name (supports concurrent VM creation)
        temp_domain = f"{self.DOMAIN_PREFIX}-{rand_str}"
        xml_content = template.read_text()
        xml_content = xml_content.replace("SERIAL_LOG_PATH", str(serial_log))
        xml_content = xml_content.replace("DOMAIN", temp_domain)
        xml_content = xml_content.replace("HOSTDEV_DEVICES", "")
        xml_content = xml_content.replace("MEMORY_GIB", str(memory_gib))
        xml_content = xml_content.replace("VCPU_COUNT", str(vcpu_count))

        # dm-verity boot: direct kernel boot, config passed via cmdline
        artifacts = self._find_verity_image(image)
        cidata_iso: Path | None = None

        config_param, config_value = self._encode_launcher_config_for_cmdline(launcher_config)
        cmdline = f"{artifacts['cmdline']} {config_param}={config_value}"

        # Large TDX VMs fail to allocate the default proportional swiotlb
        # bounce buffer (e.g. 1GB for 128G RAM).  Force a fixed 512MB buffer
        # which is small enough to allocate but sufficient for I/O.
        if memory_gib >= 64:
            cmdline += " swiotlb=131072"

        # TDX firmware/kernel cmdline has a hard size limit.
        # In practice, some environments truncate well below 3072 bytes; keep a conservative
        # default and fall back to a config-drive ISO for large configs (e.g. cloud creds).
        max_cmdline_bytes = int(
            os.environ.get("EASYENCLAVE_MAX_CMDLINE_BYTES", "2048").strip() or "2048"
        )
        # Exceeding it will truncate easyenclave.config and can cause the VM to boot
        # with no config (launcher defaults to agent mode), leading to confusing retry loops.
        if len(cmdline) > max_cmdline_bytes:
            sizes: list[tuple[str, int]] = []
            for k, v in launcher_config.items():
                if v is None:
                    continue
                try:
                    if isinstance(v, str):
                        sizes.append((k, len(v)))
                    else:
                        sizes.append((k, len(json.dumps(v, separators=(",", ":")))))
                except Exception:
                    sizes.append((k, -1))
            sizes.sort(key=lambda kv: kv[1], reverse=True)
            biggest = ", ".join(f"{k}={n}" for k, n in sizes[:6] if n >= 0) or "n/a"

            # Measurement VMs must remain deterministic; fail fast rather than introducing
            # a new disk/input that could affect RTMR baselines.
            if mode == "measure":
                raise RuntimeError(
                    f"Kernel cmdline too large ({len(cmdline)} bytes > {max_cmdline_bytes}). "
                    "This will truncate easyenclave.config and break boot. "
                    f"Largest config entries: {biggest}. "
                    "Avoid passing large JSON blobs (e.g., service account keys) via cmdline."
                )

            # For non-measure VMs, fall back to a config drive ISO.
            # The launcher will mount it and read config.json.
            print(
                f"Warning: kernel cmdline too large ({len(cmdline)} bytes > {max_cmdline_bytes}); "
                f"falling back to cidata ISO config drive. Largest config entries: {biggest}.",
                file=sys.stderr,
            )

            cidata_dir = self.WORKDIR / f"cidata.{rand_str}"
            cidata_dir.mkdir(parents=True, exist_ok=True)
            (cidata_dir / "config.json").write_text(
                json.dumps(launcher_config, indent=2),
                encoding="utf-8",
            )

            cidata_iso = self.WORKDIR / f"cidata.{rand_str}.iso"
            # NOTE: keep this ISO world-readable so cleanup scripts/users can inspect it.
            subprocess.run(
                [
                    "genisoimage",
                    "-output",
                    str(cidata_iso),
                    "-volid",
                    "EE_CONFIG",
                    "-joliet",
                    "-rock",
                    "config.json",
                ],
                cwd=str(cidata_dir),
                check=True,
                capture_output=True,
                text=True,
            )
            try:
                cidata_iso.chmod(0o644)
            except PermissionError:
                pass

            # Drop the cmdline-embedded config; the launcher will load from the ISO.
            cmdline = artifacts["cmdline"]
            if memory_gib >= 64:
                cmdline += " swiotlb=131072"

        xml_content = xml_content.replace("KERNEL_PATH", str(artifacts["kernel"]))
        xml_content = xml_content.replace("INITRD_PATH", str(artifacts["initrd"]))
        xml_content = xml_content.replace("KERNEL_CMDLINE", cmdline)
        xml_content = xml_content.replace("ROOT_IMG_PATH", str(artifacts["root"]))

        if disk_gib > 0:
            # Create writable data disk for Docker storage + workloads.
            # The guest encrypts it with an ephemeral key (dm-crypt).
            data_disk_path = self.WORKDIR / f"data.{rand_str}.qcow2"
            subprocess.run(
                [
                    "qemu-img",
                    "create",
                    "-f",
                    "qcow2",
                    str(data_disk_path),
                    f"{disk_gib}G",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            data_disk_path.chmod(0o666)
            xml_content = xml_content.replace("DATA_IMG_PATH", str(data_disk_path))
        else:
            # No data disk — strip the optional block from XML
            import re as _re

            xml_content = _re.sub(
                r"\s*<!-- DATA_DISK_START -->.*?<!-- DATA_DISK_END -->",
                "",
                xml_content,
                flags=_re.DOTALL,
            )

        if cidata_iso is not None:
            xml_content = xml_content.replace("CIDATA_ISO_PATH", str(cidata_iso))
        else:
            import re as _re

            xml_content = _re.sub(
                r"\s*<!-- CIDATA_START -->.*?<!-- CIDATA_END -->",
                "",
                xml_content,
                flags=_re.DOTALL,
            )

        xml_path = self.WORKDIR / f"{self.DOMAIN_PREFIX}.{rand_str}.xml"
        xml_path.write_text(xml_content)

        # Define and start VM
        self._virsh("define", str(xml_path), check=True)

        # Get UUID and rename to final name
        result = self._virsh("domuuid", temp_domain, text=True, check=True)
        vm_uuid = result.stdout.strip()

        # Keep measurement VM naming stable for existing cleanup scripts that target
        # trust_domain_verity-* domains explicitly.
        if mode == "measure":
            template_name = template.stem.replace(".xml", "")
            vm_name = f"{self.DOMAIN_PREFIX}-{template_name}-{vm_uuid}"
        else:
            role = self._slug_name_component(
                self._resolve_vm_role_label(mode, launcher_config), "vm", max_len=16
            )
            network = self._resolve_vm_network_label(launcher_config)
            uuid_short = re.sub(r"[^a-f0-9]", "", vm_uuid.lower())[:8] or rand_str[:8]
            size = self._slug_name_component(
                str(launcher_config.get("node_size") or size_name or "na"), "na", max_len=12
            )
            if role == "cp":
                vm_name = f"{self.DOMAIN_PREFIX}-cp-{network}-{uuid_short}"
            elif role == "agent":
                vm_name = f"{self.DOMAIN_PREFIX}-agent-{size}-{network}-{uuid_short}"
            else:
                vm_name = f"{self.DOMAIN_PREFIX}-{role}-{size}-{network}-{uuid_short}"
            vm_name = vm_name[:220]

        self._virsh("domrename", temp_domain, vm_name, check=True)
        self._virsh("start", vm_name, check=True)

        # Get VM info
        result = self._virsh("dominfo", vm_name, text=True)

        return {
            "name": vm_name,
            "uuid": vm_uuid,
            "mode": mode,
            "verity": True,
            "serial_log": str(serial_log),
            "info": result.stdout,
        }

    def control_plane_new(
        self,
        image: str | None = None,
        port: int = 8080,
        debug: bool = False,
        memory_gib: int = 16,
        vcpu_count: int = 32,
        disk_gib: int = 0,
    ) -> dict:
        """Launch a control plane in a TDX VM.

        This bootstraps a new EasyEnclave network. The control plane runs
        directly in the VM without needing to poll an external control plane.

        If Cloudflare environment variables are set, the control plane will
        create a tunnel with a canonical network hostname and keep
        a stable public alias (`https://app.{domain}` for production,
        `https://app-staging.{domain}` for staging).

        Environment variables for Cloudflare tunnel:
        - CLOUDFLARE_API_TOKEN: API token with Tunnel and DNS edit permissions
        - CLOUDFLARE_ACCOUNT_ID: Cloudflare account ID
        - CLOUDFLARE_ZONE_ID: Zone ID for the domain
        - EASYENCLAVE_DOMAIN: Domain for hostnames (default: easyenclave.com)
        - EASYENCLAVE_NETWORK_NAME: Optional network name used to isolate tunnel identity

        Args:
            image: Path to verity artifacts directory (auto-detected if not provided)
            port: Port for the control plane API (default 8080)

        Returns:
            Dict with vm_name, uuid, control_plane_url, and info
        """
        config = {
            "port": port,
            "control_plane_image": os.environ.get("CONTROL_PLANE_IMAGE"),
            # Debug/coordination: published on GET /health so CI can wait for the right CP instance.
            "easyenclave_boot_id": os.environ.get("EASYENCLAVE_BOOT_ID"),
            "easyenclave_git_sha": os.environ.get("EASYENCLAVE_GIT_SHA"),
            "easyenclave_release_tag": os.environ.get("EASYENCLAVE_RELEASE_TAG"),
            # Cloudflare config for self-tunneling (if env vars are set)
            "cloudflare_api_token": os.environ.get("CLOUDFLARE_API_TOKEN"),
            "cloudflare_account_id": os.environ.get("CLOUDFLARE_ACCOUNT_ID"),
            "cloudflare_zone_id": os.environ.get("CLOUDFLARE_ZONE_ID"),
            "easyenclave_domain": os.environ.get("EASYENCLAVE_DOMAIN", "easyenclave.com"),
            "easyenclave_network_name": os.environ.get("EASYENCLAVE_NETWORK_NAME", ""),
            "easyenclave_env": os.environ.get("EASYENCLAVE_ENV"),
            # Optional: passed through to the control plane to enable CP-native provisioning to inject
            # an ITA API key into provisioned agent VMs (EE_AGENT_ITA_API_KEY).
            "ee_agent_ita_api_key": os.environ.get("EE_AGENT_ITA_API_KEY") or "",
            # GCP credentials for CP-native provisioning (optional).
            "gcp_project_id": os.environ.get("GCP_PROJECT_ID"),
            "gcp_service_account_key": os.environ.get("GCP_SERVICE_ACCOUNT_KEY"),
            "ee_gcp_image_project": os.environ.get("EE_GCP_IMAGE_PROJECT"),
            "ee_gcp_image_family": os.environ.get("EE_GCP_IMAGE_FAMILY"),
            "ee_gcp_image_name": os.environ.get("EE_GCP_IMAGE_NAME"),
            # Auth / billing settings passed through to the control-plane container
            "github_oauth_client_id": os.environ.get("GITHUB_OAUTH_CLIENT_ID"),
            "github_oauth_client_secret": os.environ.get("GITHUB_OAUTH_CLIENT_SECRET"),
            "github_oauth_redirect_uri": os.environ.get("GITHUB_OAUTH_REDIRECT_URI"),
            # GitHub OAuth admin allowlist (comma-separated logins)
            "admin_github_logins": os.environ.get("ADMIN_GITHUB_LOGINS"),
            "stripe_secret_key": os.environ.get("STRIPE_SECRET_KEY"),
            "stripe_webhook_secret": os.environ.get("STRIPE_WEBHOOK_SECRET"),
            # Trusted MRTDs (comma-separated)
            "trusted_agent_mrtds": os.environ.get("TRUSTED_AGENT_MRTDS"),
            "trusted_proxy_mrtds": os.environ.get("TRUSTED_PROXY_MRTDS"),
            # Trusted RTMRs (JSON)
            "trusted_agent_rtmrs": os.environ.get("TRUSTED_AGENT_RTMRS"),
            "trusted_proxy_rtmrs": os.environ.get("TRUSTED_PROXY_RTMRS"),
            "trusted_agent_rtmrs_by_size": os.environ.get("TRUSTED_AGENT_RTMRS_BY_SIZE"),
            "trusted_proxy_rtmrs_by_size": os.environ.get("TRUSTED_PROXY_RTMRS_BY_SIZE"),
            "tcb_enforcement_mode": os.environ.get("TCB_ENFORCEMENT_MODE"),
            "allowed_tcb_statuses": os.environ.get("ALLOWED_TCB_STATUSES"),
            "nonce_enforcement_mode": os.environ.get("NONCE_ENFORCEMENT_MODE"),
            "nonce_ttl_seconds": os.environ.get("NONCE_TTL_SECONDS"),
            "rtmr_enforcement_mode": os.environ.get("RTMR_ENFORCEMENT_MODE"),
            "signature_verification_mode": os.environ.get("SIGNATURE_VERIFICATION_MODE"),
            "cp_to_agent_attestation_mode": os.environ.get("CP_TO_AGENT_ATTESTATION_MODE"),
            "auth_require_github_oauth_in_production": os.environ.get(
                "AUTH_REQUIRE_GITHUB_OAUTH_IN_PRODUCTION"
            ),
            "password_login_enabled": os.environ.get("PASSWORD_LOGIN_ENABLED"),
            "auth_allow_password_login_in_production": os.environ.get(
                "AUTH_ALLOW_PASSWORD_LOGIN_IN_PRODUCTION"
            ),
            "billing_enabled": os.environ.get("BILLING_ENABLED"),
            "billing_capacity_request_dev_simulation": os.environ.get(
                "BILLING_CAPACITY_REQUEST_DEV_SIMULATION"
            ),
            "billing_platform_account_id": os.environ.get("BILLING_PLATFORM_ACCOUNT_ID"),
            "billing_contributor_pool_bps": os.environ.get("BILLING_CONTRIBUTOR_POOL_BPS"),
            "default_gcp_tiny_capacity_enabled": os.environ.get(
                "DEFAULT_GCP_TINY_CAPACITY_ENABLED"
            ),
            "default_gcp_tiny_capacity_count": os.environ.get("DEFAULT_GCP_TINY_CAPACITY_COUNT"),
            "default_gcp_tiny_capacity_dispatch": os.environ.get(
                "DEFAULT_GCP_TINY_CAPACITY_DISPATCH"
            ),
            # Admin password hash for control plane dashboard
            "admin_password_hash": os.environ.get("ADMIN_PASSWORD_HASH"),
        }
        # Drop empty keys to minimize kernel cmdline payload size.
        config = {k: v for k, v in config.items() if v not in (None, "")}
        result = self.vm_new(
            image=image,
            mode=CONTROL_PLANE_MODE,
            config=config,
            debug=debug,
            memory_gib=memory_gib,
            vcpu_count=vcpu_count,
            disk_gib=disk_gib,
        )
        result["control_plane_port"] = port

        # Add expected hostname if Cloudflare is configured
        if config.get("cloudflare_api_token"):
            domain = config["easyenclave_domain"]
            env_name = (config.get("easyenclave_env") or "").strip().lower()
            alias_label = "app-staging" if env_name == "staging" else "app"
            result["control_plane_hostname"] = f"{alias_label}.{domain}"
            network_name = (config.get("easyenclave_network_name") or "").strip().lower()
            network_slug = re.sub(r"[^a-z0-9-]+", "-", network_name).strip("-")
            if network_slug:
                result["control_plane_network_hostname"] = f"{network_slug}.{domain}"

        return result

    def get_vm_ip(self, name: str, timeout: int = 120) -> str | None:
        """Wait for and return VM IP address.

        Args:
            name: VM name
            timeout: Max seconds to wait for IP

        Returns:
            IP address or None if timeout
        """
        start = time.time()
        while time.time() - start < timeout:
            result = self._virsh("domifaddr", name, text=True)
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if "ipv4" in line:
                        # Parse: " vnet0  52:54:00:xx:xx:xx  ipv4  192.168.122.x/24"
                        parts = line.split()
                        for part in parts:
                            if "/" in part and "." in part:
                                return part.split("/")[0]
            time.sleep(2)
        return None

    def vm_delete(self, name: str):
        """Delete a TDX VM.

        Args:
            name: VM name to delete
        """
        # First try graceful shutdown
        self._virsh("shutdown", name, check=False)
        time.sleep(2)

        # Then force destroy
        self._virsh("destroy", name, check=False)
        # Some libvirt versions require explicit --nvram removal.
        self._virsh("undefine", name, "--nvram", check=False)
        self._virsh("undefine", name, check=False)
        self.cleanup_orphaned_workdir_artifacts()

    def _workdir_scoped_path(self, raw_path: str) -> Path | None:
        """Return resolved path if it is within WORKDIR, else None."""
        if not raw_path:
            return None
        try:
            candidate = Path(raw_path).resolve()
            workdir = self.WORKDIR.resolve()
        except Exception:
            return None
        if candidate == workdir or workdir in candidate.parents:
            return candidate
        return None

    def _collect_domain_workdir_artifacts(self, name: str) -> set[Path]:
        """Collect WORKDIR paths referenced by a domain XML."""
        result = self._virsh("dumpxml", name, text=True, check=False)
        if result.returncode != 0 or not result.stdout:
            return set()

        refs: set[Path] = set()
        for raw in re.findall(r"""(?:file|path)=['"]([^'"]+)['"]""", result.stdout):
            scoped = self._workdir_scoped_path(raw)
            if scoped is not None:
                refs.add(scoped)
        return refs

    def _remove_path(self, path: Path) -> bool:
        """Best-effort path removal."""
        try:
            if not path.exists():
                return False
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            return True
        except FileNotFoundError:
            return False
        except Exception as e:
            print(f"Warning: failed to remove {path}: {e}", file=sys.stderr)
            return False

    def cleanup_orphaned_workdir_artifacts(self) -> int:
        """Delete tdvirsh artifacts in WORKDIR not referenced by active domains."""
        if not self.WORKDIR.exists():
            return 0

        referenced: set[Path] = set()
        for vm_name in self.vm_list():
            referenced.update(self._collect_domain_workdir_artifacts(vm_name))

        # If a cidata ISO is referenced, keep its matching cidata.<id> directory too.
        referenced_cidata_dirs = {
            self.WORKDIR / p.name[:-4]
            for p in referenced
            if p.name.startswith("cidata.") and p.name.endswith(".iso")
        }

        managed_prefixes = (
            "overlay.",
            "data.",
            "cidata.",
            "console.",
            "ip.",
            f"{self.DOMAIN_PREFIX}.",
        )

        removed = 0
        for entry in self.WORKDIR.iterdir():
            if not entry.name.startswith(managed_prefixes):
                continue
            scoped = self._workdir_scoped_path(str(entry))
            if scoped is None:
                continue
            if scoped in referenced or scoped in referenced_cidata_dirs:
                continue
            if self._remove_path(scoped):
                removed += 1

        return removed

    def vm_list(self) -> list:
        """List all TDX VMs.

        Returns:
            List of VM names managed by tdvirsh
        """
        result = self._virsh("list", "--all", "--name", text=True)
        return [n for n in result.stdout.strip().split("\n") if n.startswith(self.DOMAIN_PREFIX)]

    def vm_status(self, name: str) -> dict:
        """Get VM status.

        Args:
            name: VM name

        Returns:
            Dict with status info
        """
        result = self._virsh("dominfo", name, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"VM not found: {name}")

        # Parse dominfo output
        info = {}
        for line in result.stdout.strip().split("\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                info[key.strip().lower().replace(" ", "_")] = value.strip()

        return info

    def _dump_network_info(self, name: str):
        """Dump VM network interface info for diagnostics."""
        print("\n=== VM network interfaces ===", file=sys.stderr)
        for cmd in ("domiflist", "domifaddr"):
            result = self._virsh(cmd, name, text=True)
            print(f"  virsh {cmd}:", file=sys.stderr)
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split("\n"):
                    print(f"    {line}", file=sys.stderr)
            else:
                print("    (no output)", file=sys.stderr)
        print("=== End network info ===\n", file=sys.stderr)

    def _dump_serial_log(self, serial_log: str | None):
        """Dump last 500 lines of serial log for diagnostics."""
        print("\n=== Serial log (last 500 lines) ===", file=sys.stderr)
        if serial_log and Path(serial_log).exists():
            lines = Path(serial_log).read_text(errors="replace").splitlines()
            for line in lines[-500:]:
                print(f"  {line}", file=sys.stderr)
        else:
            print("  (no serial log found)", file=sys.stderr)
        print("=== End serial log ===\n", file=sys.stderr)

    def _parse_measurements_from_serial(self, serial_log: str) -> dict | None:
        """Parse EASYENCLAVE_MEASUREMENTS=<json> from serial log as fallback."""
        if not Path(serial_log).exists():
            return None
        for line in Path(serial_log).read_text(errors="replace").splitlines():
            if "EASYENCLAVE_MEASUREMENTS=" in line:
                try:
                    raw = line.split("EASYENCLAVE_MEASUREMENTS=", 1)[1].strip()
                    data = json.loads(raw)
                    if data.get("mrtd"):
                        return data
                except (json.JSONDecodeError, IndexError):
                    pass
            if "EASYENCLAVE_MEASURE_ERROR=" in line:
                err = line.split("EASYENCLAVE_MEASURE_ERROR=", 1)[1].strip()
                print(f"Measurement error (from serial): {err}", file=sys.stderr)
        return None

    def _tail_for_measurements(self, serial_log: str, timeout: int) -> dict | None:
        """Tail serial log in real-time, streaming output and scanning for measurements.

        Every line is printed to stderr so it appears in CI logs (GitHub Actions).
        Returns as soon as EASYENCLAVE_MEASUREMENTS=<json> is found, or None on
        timeout/error.

        Args:
            serial_log: Path to the serial log file
            timeout: Max seconds to wait

        Returns:
            Parsed measurements dict, or None
        """
        deadline = time.time() + timeout
        path = Path(serial_log)

        # Wait for file to exist
        while not path.exists():
            if time.time() > deadline:
                print("Timeout waiting for serial log file", file=sys.stderr)
                return None
            time.sleep(0.1)

        last_full_scan = 0.0
        with open(path, errors="replace") as f:
            while time.time() < deadline:
                line = f.readline()
                if not line:
                    # Fallback scan while tailing: some serial writes may not be
                    # observed immediately via readline() under heavy console output.
                    now = time.time()
                    if now - last_full_scan >= 1.0:
                        scanned = self._parse_measurements_from_serial(serial_log)
                        if scanned and scanned.get("mrtd"):
                            return scanned
                        last_full_scan = now
                    time.sleep(0.1)
                    continue

                # Stream to stderr (visible in GitHub Actions logs)
                print(line, end="", file=sys.stderr)

                if "EASYENCLAVE_MEASUREMENTS=" in line:
                    try:
                        raw = line.split("EASYENCLAVE_MEASUREMENTS=", 1)[1].strip()
                        data = json.loads(raw)
                        if data.get("mrtd"):
                            return data
                    except (json.JSONDecodeError, IndexError):
                        pass

                if "EASYENCLAVE_MEASURE_ERROR=" in line:
                    err = line.split("EASYENCLAVE_MEASURE_ERROR=", 1)[1].strip()
                    print(f"Measurement error: {err}", file=sys.stderr)
                    return None

        print(f"Timeout: no measurements within {timeout}s", file=sys.stderr)
        return None

    def vm_measure(
        self,
        image: str | None = None,
        timeout: int = 180,
        memory_gib: int = 16,
        vcpu_count: int = 32,
        disk_gib: int = 0,
    ) -> dict:
        """Boot a temporary VM to capture MRTD and RTMRs, then destroy it.

        Streams the serial console to stderr in real-time (visible in CI logs)
        and returns as soon as measurements are printed. No shutdown wait needed.

        Args:
            image: Path to verity artifacts directory (auto-detected if not provided)
            timeout: Max seconds to wait for measurements (default 180)

        Returns:
            Dict with mrtd, rtmr0-3, and vm_name
        """
        config = {
            "control_plane_url": "",  # Not needed for measure mode
            "intel_api_key": "",  # Not needed for measure mode
        }

        print("Booting temporary VM to capture measurements...", file=sys.stderr)
        # Measurements do not depend on a writable data disk; avoid allocating one,
        # especially for large presets (e.g. llm).
        result = self.vm_new(
            image=image,
            mode="measure",
            config=config,
            debug=False,
            memory_gib=memory_gib,
            vcpu_count=vcpu_count,
            disk_gib=0,
        )
        vm_name = result["name"]
        serial_log = result.get("serial_log")

        print(f"VM started: {vm_name}", file=sys.stderr)
        print(f"=== Streaming VM console ({serial_log}) ===", file=sys.stderr)

        measurements = None
        try:
            # Stream serial log and scan for measurements in real-time
            if serial_log:
                measurements = self._tail_for_measurements(serial_log, timeout)

            # Last-resort fallback: re-scan the full serial log file
            if not measurements and serial_log:
                measurements = self._parse_measurements_from_serial(serial_log)
                if measurements:
                    print("Recovered measurements from serial log", file=sys.stderr)

            if not measurements:
                print(
                    "Error: Could not capture measurements from serial log",
                    file=sys.stderr,
                )

        finally:
            # Best-effort cleanup with timeouts so CI never hangs on virsh.
            print(f"Destroying temporary VM: {vm_name}", file=sys.stderr)
            try:
                state = self._virsh("domstate", vm_name, text=True, check=False, timeout=10)
                is_running = state.returncode == 0 and "running" in state.stdout.lower()
            except Exception:
                is_running = True

            if is_running:
                try:
                    self._virsh("destroy", vm_name, check=False, timeout=20)
                except subprocess.TimeoutExpired:
                    print(f"Warning: timed out destroying {vm_name}", file=sys.stderr)

            try:
                self._virsh("undefine", vm_name, check=False, timeout=20)
            except subprocess.TimeoutExpired:
                print(f"Warning: timed out undefining {vm_name}", file=sys.stderr)
            removed = self.cleanup_orphaned_workdir_artifacts()
            if removed:
                print(f"Cleaned up {removed} orphaned tdvirsh artifacts", file=sys.stderr)

        if measurements:
            return {
                "mrtd": measurements.get("mrtd"),
                "rtmr0": measurements.get("rtmr0"),
                "rtmr1": measurements.get("rtmr1"),
                "rtmr2": measurements.get("rtmr2"),
                "rtmr3": measurements.get("rtmr3"),
                "vm_name": vm_name,
            }
        return {"mrtd": None, "vm_name": vm_name}


def _resolve_size(args) -> tuple[int, int, int, str]:
    """Resolve --size preset with optional --memory/--vcpus/--disk overrides.

    Priority: --memory/--vcpus/--disk > --size > EASYENCLAVE_DEFAULT_SIZE > tiny.
    Returns (memory_gib, vcpu_count, disk_gib, size_name).
    """
    size_name = getattr(args, "size", None) or DEFAULT_SIZE
    base_mem, base_vcpus, base_disk = NODE_SIZES[size_name]
    memory = getattr(args, "memory", None)
    vcpus = getattr(args, "vcpus", None)
    disk = getattr(args, "disk", None)
    return (
        memory if memory is not None else base_mem,
        vcpus if vcpus is not None else base_vcpus,
        disk if disk is not None else base_disk,
        size_name,
    )


def _add_size_args(parser):
    """Add --size, --memory, --vcpus, --disk arguments to a subparser."""
    parser.add_argument(
        "--size",
        choices=list(NODE_SIZES.keys()),
        default=None,
        help=f"Node size preset (env EASYENCLAVE_DEFAULT_SIZE, default: {DEFAULT_SIZE})",
    )
    parser.add_argument(
        "--memory", type=int, default=None, help="VM memory in GiB (overrides --size)"
    )
    parser.add_argument(
        "--vcpus", type=int, default=None, help="Number of vCPUs (overrides --size)"
    )
    parser.add_argument(
        "--disk", type=int, default=None, help="Data disk size in GiB, 0=none (overrides --size)"
    )


def _wait_for_agent_ready(
    cp_url: str,
    timeout: int = 300,
    poll_interval: int = 5,
    known_agent_ids: set[str] | None = None,
    expected_node_size: str = "",
) -> dict | None:
    """Wait until a new agent appears on CP and is verified + registered."""
    deadline = time.time() + timeout
    last_status = ""
    known_ids = known_agent_ids or set()
    expected_size = expected_node_size.strip().lower()

    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{cp_url}/api/v1/agents", timeout=10) as resp:
                payload = json.loads(resp.read())
        except Exception:
            time.sleep(poll_interval)
            continue

        for agent in payload.get("agents", []):
            agent_id = str(agent.get("agent_id") or "")
            if agent_id in known_ids:
                continue
            node_size = str(agent.get("node_size") or "").strip().lower()
            if expected_size and node_size != expected_size:
                continue

            verified = bool(agent.get("verified"))
            health = str(agent.get("health_status") or "").lower()
            status = str(agent.get("status") or "").lower()
            vm_name = str(agent.get("vm_name") or "unknown")
            summary = f"vm_name={vm_name} verified={verified} health={health or 'unknown'} status={status or 'unknown'}"
            if summary != last_status:
                print(f"Bootstrap agent state: {summary}", file=sys.stderr)
                last_status = summary

            if verified and status not in {"", "unverified", "attestation_failed", "error"}:
                return agent

        time.sleep(poll_interval)

    return None


def _list_agent_ids(cp_url: str) -> set[str]:
    """Fetch currently known agent IDs from control plane."""
    try:
        with urllib.request.urlopen(f"{cp_url}/api/v1/agents", timeout=10) as resp:
            payload = json.loads(resp.read())
    except Exception:
        return set()

    agent_ids: set[str] = set()
    for agent in payload.get("agents", []):
        agent_id = str(agent.get("agent_id") or "").strip()
        if agent_id:
            agent_ids.add(agent_id)
    return agent_ids


def main():
    parser = argparse.ArgumentParser(
        description="TDX CLI - Manage TDX VM lifecycle",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tdx control-plane new --wait        Launch control plane + bootstrap measurer agents
  tdx vm new                          Create new TDX VM (registers with control plane)
  tdx vm measure                      Boot temp VM to get MRTD, then destroy
  tdx vm list                         List all TDX VMs
  tdx vm status <name>                Get VM status
  tdx vm delete <name>                Delete a TDX VM
  tdx vm delete all                   Delete all TDX VMs

To start a new EasyEnclave network:
  1. tdx control-plane new --wait     Launch CP + default tiny bootstrap measurer
  2. tdx vm new                       Launch additional capacity agents
  3. POST /api/v1/deployments         Deploy workloads via API
        """,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Control plane commands
    cp_parser = subparsers.add_parser("control-plane", help="Control plane management")
    cp_sub = cp_parser.add_subparsers(dest="cp_command", required=True)

    cp_new_parser = cp_sub.add_parser("new", help="Launch control plane in TDX VM")
    cp_new_parser.add_argument(
        "-i", "--image", help="Path to verity artifacts directory (default: infra/image/output)"
    )
    cp_new_parser.add_argument(
        "-p", "--port", type=int, default=8080, help="API port (default 8080)"
    )
    cp_new_parser.add_argument(
        "--wait", action="store_true", help="Wait for control plane to be ready"
    )
    cp_new_parser.add_argument(
        "--bootstrap-measurers",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Launch bootstrap measuring agents after control plane health is ready (default: true)",
    )
    cp_new_parser.add_argument(
        "--bootstrap-sizes",
        default="tiny",
        help=f"Comma-separated bootstrap agent sizes (default: tiny, allowed: {','.join(NODE_SIZES.keys())})",
    )
    cp_new_parser.add_argument(
        "--bootstrap-timeout",
        type=int,
        default=300,
        help="Seconds to wait for each bootstrap agent to register and verify (default: 300)",
    )
    cp_new_parser.add_argument(
        "--debug", action="store_true", help="Enable SSH and set password (tdx) for debugging"
    )
    _add_size_args(cp_new_parser)

    # VM commands
    vm_parser = subparsers.add_parser("vm", help="VM lifecycle management")
    vm_sub = vm_parser.add_subparsers(dest="vm_command", required=True)

    new_parser = vm_sub.add_parser("new", help="Create new TDX VM")
    new_parser.add_argument(
        "-i", "--image", help="Path to verity artifacts directory (default: infra/image/output)"
    )
    new_parser.add_argument(
        "--easyenclave-url",
        default="https://app.easyenclave.com",
        help="Control plane URL for agent registration (default: https://app.easyenclave.com)",
    )
    new_parser.add_argument(
        "--intel-api-key",
        # Prefer ITA_API_KEY (new name) with INTEL_API_KEY as a legacy alias.
        default=os.environ.get("ITA_API_KEY") or os.environ.get("INTEL_API_KEY", ""),
        help="Intel Trust Authority API key (or set ITA_API_KEY / INTEL_API_KEY env var)",
    )
    new_parser.add_argument("--wait", action="store_true", help="Wait for agent to get IP")
    new_parser.add_argument(
        "--debug", action="store_true", help="Enable SSH and set password (tdx) for debugging"
    )
    new_parser.add_argument(
        "--cloud-provider",
        default="",
        help="Cloud provider label for placement metadata (e.g., gcp, azure, baremetal)",
    )
    new_parser.add_argument(
        "--availability-zone",
        default="",
        help="Availability zone for placement metadata (treated as datacenter)",
    )
    new_parser.add_argument(
        "--region",
        default="",
        help="Region for placement metadata fallback when zone is not set",
    )
    new_parser.add_argument(
        "--datacenter",
        default="",
        help="Explicit datacenter label override for placement metadata",
    )
    _add_size_args(new_parser)

    vm_sub.add_parser("list", help="List TDX VMs")

    status_parser = vm_sub.add_parser("status", help="Get VM status")
    status_parser.add_argument("name", help="VM name")

    del_parser = vm_sub.add_parser("delete", help="Delete TDX VM")
    del_parser.add_argument("name", help="VM name or 'all'")
    del_parser.add_argument(
        "--easyenclave-url",
        default=os.environ.get("EASYENCLAVE_CP_URL", ""),
        help="Control plane URL — if set, also deletes the agent registration",
    )
    del_parser.add_argument(
        "--admin-token",
        default=os.environ.get("ADMIN_TOKEN", ""),
        help="Admin bearer token for agent deletion (or set ADMIN_TOKEN env var)",
    )

    measure_parser = vm_sub.add_parser("measure", help="Boot temp VM to capture measurements")
    measure_parser.add_argument(
        "-i", "--image", help="Path to verity artifacts directory (default: infra/image/output)"
    )
    measure_parser.add_argument(
        "--timeout", type=int, default=180, help="Timeout in seconds (default 180)"
    )
    measure_parser.add_argument(
        "--json", action="store_true", help="Output all measurements as JSON (MRTD + RTMRs)"
    )
    _add_size_args(measure_parser)

    args = parser.parse_args()
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", "."))
    mgr = TDXManager(workspace)

    try:
        if args.command == "control-plane":
            if args.cp_command == "new":
                bootstrap_sizes: list[str] = []
                if args.bootstrap_measurers:
                    if not args.wait:
                        print(
                            "Error: --bootstrap-measurers requires --wait so control plane URL is known.",
                            file=sys.stderr,
                        )
                        sys.exit(1)
                    bootstrap_sizes_raw = [s.strip() for s in args.bootstrap_sizes.split(",")]
                    bootstrap_sizes = [s for s in bootstrap_sizes_raw if s]
                    if not bootstrap_sizes:
                        print(
                            "Error: --bootstrap-sizes is empty; provide at least one size (e.g. tiny).",
                            file=sys.stderr,
                        )
                        sys.exit(1)
                    invalid = [s for s in bootstrap_sizes if s not in NODE_SIZES]
                    if invalid:
                        print(
                            f"Error: invalid bootstrap size(s): {', '.join(invalid)}. "
                            f"Allowed: {', '.join(NODE_SIZES.keys())}",
                            file=sys.stderr,
                        )
                        sys.exit(1)

                print("Launching control plane in TDX VM...", file=sys.stderr)
                mem, vcpus, disk, size_name = _resolve_size(args)
                result = mgr.control_plane_new(
                    args.image,
                    args.port,
                    debug=args.debug,
                    memory_gib=mem,
                    vcpu_count=vcpus,
                    disk_gib=disk,
                )

                if args.wait:
                    # Start tailing serial log immediately so boot output is visible
                    serial_log = result.get("serial_log")
                    stop_tail = threading.Event()
                    tail_thread = None
                    if serial_log:
                        print(f"\n=== Streaming VM console ({serial_log}) ===", file=sys.stderr)
                        tail_thread = threading.Thread(
                            target=tail_log, args=(serial_log, stop_tail)
                        )
                        tail_thread.daemon = True
                        tail_thread.start()

                    print("\nWaiting for VM to get IP...", file=sys.stderr)
                    ip = mgr.get_vm_ip(result["name"])
                    if not ip:
                        stop_tail.set()
                        print("Error: Could not get VM IP", file=sys.stderr)
                        mgr._dump_network_info(result["name"])
                        mgr._dump_serial_log(result.get("serial_log"))
                        print(json.dumps(result, indent=2))
                        sys.exit(1)

                    url = f"http://{ip}:{args.port}"
                    print(f"Control plane VM IP: {ip}", file=sys.stderr)
                    print(f"Control plane URL: {url}", file=sys.stderr)

                    # Wait for control plane to be ready
                    print("Waiting for control plane to start...", file=sys.stderr)

                    # Always include IP in result so workflow can proceed
                    result["ip"] = ip
                    result["control_plane_url"] = url

                    for _ in range(120):  # 4 minutes for image pull + boot
                        try:
                            with urllib.request.urlopen(f"{url}/health", timeout=5) as resp:
                                if resp.status == 200:
                                    stop_tail.set()
                                    print(
                                        f"\n=== Control plane ready at {url} ===", file=sys.stderr
                                    )
                                    break
                        except (urllib.error.URLError, TimeoutError):
                            pass
                        time.sleep(2)
                    else:
                        stop_tail.set()
                        print(
                            "Error: Control plane did not become ready (health check timeout).",
                            file=sys.stderr,
                        )
                        mgr._dump_network_info(result["name"])
                        mgr._dump_serial_log(result.get("serial_log"))
                        print(json.dumps(result, indent=2))
                        sys.exit(1)

                    if args.bootstrap_measurers:
                        datacenter = os.environ.get("AGENT_DATACENTER", "")
                        cloud_provider = os.environ.get("AGENT_CLOUD_PROVIDER", "baremetal")
                        availability_zone = os.environ.get("AGENT_DATACENTER_AZ", "github-runner")
                        region = os.environ.get("AGENT_DATACENTER_REGION", "")
                        result["bootstrap_agents"] = []

                        for bootstrap_size in bootstrap_sizes:
                            size_mem, size_vcpus, size_disk = NODE_SIZES[bootstrap_size]
                            bootstrap_vm_id = f"bootstrap-{bootstrap_size}-{uuid.uuid4().hex[:8]}"
                            bootstrap_config = {
                                "control_plane_url": url,
                                "vm_id": bootstrap_vm_id,
                            }
                            env_network_name = (
                                os.environ.get("EASYENCLAVE_NETWORK_NAME") or ""
                            ).strip()
                            env_network_env = (os.environ.get("EASYENCLAVE_ENV") or "").strip()
                            if env_network_name:
                                bootstrap_config["easyenclave_network_name"] = env_network_name
                            elif env_network_env:
                                bootstrap_config["easyenclave_env"] = env_network_env
                            env_agent_mode = (
                                (os.environ.get("AGENT_ADMIN_AUTH_MODE") or "").strip().lower()
                            )
                            if env_agent_mode in {"password", "cp", "hybrid"}:
                                bootstrap_config["agent_admin_auth_mode"] = env_agent_mode
                            env_cp_mode = (
                                (os.environ.get("CP_TO_AGENT_ATTESTATION_MODE") or "")
                                .strip()
                                .lower()
                            )
                            if env_cp_mode in {"required", "optional", "disabled"}:
                                bootstrap_config["cp_to_agent_attestation_mode"] = env_cp_mode
                            trusted_proxy_mrtds = (
                                os.environ.get("TRUSTED_PROXY_MRTDS") or ""
                            ).strip()
                            if trusted_proxy_mrtds:
                                bootstrap_config["trusted_proxy_mrtds"] = trusted_proxy_mrtds
                            if datacenter:
                                bootstrap_config["datacenter"] = datacenter
                            else:
                                if cloud_provider:
                                    bootstrap_config["cloud_provider"] = cloud_provider
                                if availability_zone:
                                    bootstrap_config["availability_zone"] = availability_zone
                                if region:
                                    bootstrap_config["region"] = region

                            print(
                                f"Launching bootstrap measuring agent VM (size={bootstrap_size})...",
                                file=sys.stderr,
                            )
                            known_agent_ids = _list_agent_ids(url)
                            bootstrap_agent = mgr.vm_new(
                                image=args.image,
                                mode=AGENT_MODE,
                                config=bootstrap_config,
                                debug=args.debug,
                                memory_gib=size_mem,
                                vcpu_count=size_vcpus,
                                size_name=bootstrap_size,
                                disk_gib=size_disk,
                            )
                            bootstrap_agent["node_size"] = bootstrap_size

                            bootstrap_ip = mgr.get_vm_ip(bootstrap_agent["name"], timeout=180)
                            if not bootstrap_ip:
                                print(
                                    f"Error: Bootstrap agent (size={bootstrap_size}) did not get an IP.",
                                    file=sys.stderr,
                                )
                                mgr._dump_network_info(bootstrap_agent["name"])
                                mgr._dump_serial_log(bootstrap_agent.get("serial_log"))
                                sys.exit(1)
                            bootstrap_agent["ip"] = bootstrap_ip

                            ready_agent = _wait_for_agent_ready(
                                url,
                                timeout=args.bootstrap_timeout,
                                known_agent_ids=known_agent_ids,
                                expected_node_size=bootstrap_size,
                            )
                            if not ready_agent:
                                print(
                                    f"Error: Bootstrap agent (size={bootstrap_size}) did not become verified+registered in time.",
                                    file=sys.stderr,
                                )
                                mgr._dump_serial_log(bootstrap_agent.get("serial_log"))
                                sys.exit(1)

                            bootstrap_agent["agent_id"] = ready_agent.get("agent_id")
                            bootstrap_agent["verified"] = ready_agent.get("verified")
                            bootstrap_agent["health_status"] = ready_agent.get("health_status")
                            bootstrap_agent["status"] = ready_agent.get("status")
                            result["bootstrap_agents"].append(bootstrap_agent)
                            print(
                                f"Bootstrap agent ready (size={bootstrap_size}, id={ready_agent.get('agent_id')})",
                                file=sys.stderr,
                            )

                    # Always print final result with IP
                    print(json.dumps(result, indent=2))
                else:
                    # No --wait, just print immediately
                    print(json.dumps(result, indent=2))

        elif args.command == "vm":
            if args.vm_command == "new":
                config = {
                    "control_plane_url": args.easyenclave_url,
                }
                # Agents mint Intel Trust Authority tokens directly (requires ITA_API_KEY).
                if args.intel_api_key:
                    config["intel_api_key"] = args.intel_api_key
                env_network_name = (os.environ.get("EASYENCLAVE_NETWORK_NAME") or "").strip()
                env_network_env = (os.environ.get("EASYENCLAVE_ENV") or "").strip()
                if env_network_name:
                    config["easyenclave_network_name"] = env_network_name
                elif env_network_env:
                    config["easyenclave_env"] = env_network_env
                env_agent_mode = (os.environ.get("AGENT_ADMIN_AUTH_MODE") or "").strip().lower()
                if env_agent_mode in {"password", "cp", "hybrid"}:
                    config["agent_admin_auth_mode"] = env_agent_mode
                env_cp_mode = (os.environ.get("CP_TO_AGENT_ATTESTATION_MODE") or "").strip().lower()
                if env_cp_mode in {"required", "optional", "disabled"}:
                    config["cp_to_agent_attestation_mode"] = env_cp_mode
                trusted_proxy_mrtds = (os.environ.get("TRUSTED_PROXY_MRTDS") or "").strip()
                if trusted_proxy_mrtds:
                    config["trusted_proxy_mrtds"] = trusted_proxy_mrtds
                if args.cloud_provider:
                    config["cloud_provider"] = args.cloud_provider
                if args.availability_zone:
                    config["availability_zone"] = args.availability_zone
                if args.region:
                    config["region"] = args.region
                if args.datacenter:
                    config["datacenter"] = args.datacenter
                mem, vcpus, disk, size_name = _resolve_size(args)
                result = mgr.vm_new(
                    args.image,
                    config=config,
                    debug=args.debug,
                    memory_gib=mem,
                    vcpu_count=vcpus,
                    size_name=size_name,
                    disk_gib=disk,
                )
                print(json.dumps(result, indent=2))

                if args.wait:
                    print("\nWaiting for VM to get IP...", file=sys.stderr)
                    ip = mgr.get_vm_ip(result["name"])
                    if ip:
                        print(f"VM IP: {ip}", file=sys.stderr)
                        print(f"Agent will register with: {args.easyenclave_url}", file=sys.stderr)
                        result["ip"] = ip
                        print(json.dumps(result, indent=2))
                    else:
                        print("Error: Could not get VM IP", file=sys.stderr)
                        mgr._dump_network_info(result["name"])
                        mgr._dump_serial_log(result.get("serial_log"))
                        sys.exit(1)
            elif args.vm_command == "list":
                for vm in mgr.vm_list():
                    print(vm)
            elif args.vm_command == "status":
                result = mgr.vm_status(args.name)
                print(json.dumps(result, indent=2))
            elif args.vm_command == "delete":
                cp_url = getattr(args, "easyenclave_url", "")
                admin_token = getattr(args, "admin_token", "")

                def _direct_cf_cleanup(tunnel_id: str, hostname: str):
                    """Delete a Cloudflare tunnel and its DNS record directly via CF API."""
                    import urllib.request

                    cf_token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
                    cf_account = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
                    cf_zone = os.environ.get("CLOUDFLARE_ZONE_ID", "")
                    if not (cf_token and cf_account):
                        return
                    cf_headers = {
                        "Authorization": f"Bearer {cf_token}",
                        "Content-Type": "application/json",
                    }
                    cf_api = "https://api.cloudflare.com/client/v4"

                    # Delete tunnel (clean connections first)
                    if tunnel_id:
                        try:
                            req = urllib.request.Request(
                                f"{cf_api}/accounts/{cf_account}/cfd_tunnel/{tunnel_id}/connections",
                                method="DELETE",
                            )
                            for k, v in cf_headers.items():
                                req.add_header(k, v)
                            urllib.request.urlopen(req, timeout=10)
                        except Exception:
                            pass
                        try:
                            req = urllib.request.Request(
                                f"{cf_api}/accounts/{cf_account}/cfd_tunnel/{tunnel_id}",
                                method="DELETE",
                            )
                            for k, v in cf_headers.items():
                                req.add_header(k, v)
                            urllib.request.urlopen(req, timeout=10)
                            print(f"  Deleted Cloudflare tunnel {tunnel_id}")
                        except Exception as e:
                            print(f"  Failed to delete tunnel {tunnel_id}: {e}", file=sys.stderr)

                    # Delete DNS record
                    if hostname and cf_zone:
                        try:
                            req = urllib.request.Request(
                                f"{cf_api}/zones/{cf_zone}/dns_records?name={hostname}&type=CNAME",
                            )
                            for k, v in cf_headers.items():
                                req.add_header(k, v)
                            resp = urllib.request.urlopen(req, timeout=10)
                            records = json.loads(resp.read()).get("result", [])
                            if records:
                                record_id = records[0]["id"]
                                dreq = urllib.request.Request(
                                    f"{cf_api}/zones/{cf_zone}/dns_records/{record_id}",
                                    method="DELETE",
                                )
                                for k, v in cf_headers.items():
                                    dreq.add_header(k, v)
                                urllib.request.urlopen(dreq, timeout=10)
                                print(f"  Deleted DNS record for {hostname}")
                        except Exception as e:
                            print(f"  Failed to delete DNS for {hostname}: {e}", file=sys.stderr)

                def _cleanup_agent(vm_name: str):
                    """Best-effort: delete the agent + tunnel + DNS."""
                    if not cp_url:
                        return
                    import urllib.request

                    tunnel_id = ""
                    hostname = ""

                    try:
                        # Look up agent by vm_name to get tunnel_id and hostname
                        req = urllib.request.Request(f"{cp_url}/api/v1/agents")
                        resp = urllib.request.urlopen(req, timeout=5)
                        agents = json.loads(resp.read())
                        for agent in agents.get("agents", []):
                            if agent.get("vm_name") == vm_name:
                                aid = agent["agent_id"]
                                tunnel_id = agent.get("tunnel_id", "")
                                hostname = agent.get("hostname", "")

                                # Try CP-based delete (handles tunnel+DNS server-side)
                                dreq = urllib.request.Request(
                                    f"{cp_url}/api/v1/agents/{aid}",
                                    method="DELETE",
                                )
                                if admin_token:
                                    dreq.add_header("Authorization", f"Bearer {admin_token}")
                                urllib.request.urlopen(dreq, timeout=10)
                                print(f"  Cleaned up agent {aid} via control plane")
                                return
                    except Exception as e:
                        print(f"  CP cleanup failed: {e}", file=sys.stderr)
                        # Fall through to direct CF cleanup if we captured tunnel info
                        if tunnel_id or hostname:
                            print("  Falling back to direct Cloudflare cleanup...")
                            _direct_cf_cleanup(tunnel_id, hostname)

                if args.name == "all":
                    for vm in mgr.vm_list():
                        print(f"Deleting {vm}...")
                        _cleanup_agent(vm)
                        mgr.vm_delete(vm)
                else:
                    _cleanup_agent(args.name)
                    mgr.vm_delete(args.name)
            elif args.vm_command == "measure":
                mem, vcpus, disk, size_name = _resolve_size(args)
                result = mgr.vm_measure(
                    args.image,
                    args.timeout,
                    memory_gib=mem,
                    vcpu_count=vcpus,
                    disk_gib=disk,
                )
                if result.get("mrtd"):
                    if args.json:
                        # Output all measurements as JSON
                        print(
                            json.dumps(
                                {
                                    "mrtd": result["mrtd"],
                                    "rtmr0": result.get("rtmr0"),
                                    "rtmr1": result.get("rtmr1"),
                                    "rtmr2": result.get("rtmr2"),
                                    "rtmr3": result.get("rtmr3"),
                                }
                            )
                        )
                    else:
                        # Print just the MRTD for backward compat
                        print(result["mrtd"])
                else:
                    print("Error: Could not capture MRTD", file=sys.stderr)
                    sys.exit(1)

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except RuntimeError as e:
        print(f"Runtime error: {e}", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e.cmd}", file=sys.stderr)
        if e.stderr:
            print(e.stderr, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
