#!/usr/bin/env python3
"""TDX CLI - Manage TDX VM lifecycle.

Simple CLI for launching and managing TDX VMs with the launcher agent pre-installed.
VMs boot in "undeployed" state and register with the control plane.

Special command: `tdx control-plane new` launches a control plane in a TDX VM.
This bootstraps a new EasyEnclave network.

All deployments go through the control plane API - this CLI only handles VM lifecycle.
"""

import argparse
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

# Control plane mode config
CONTROL_PLANE_MODE = "control-plane"
AGENT_MODE = "agent"


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
        with open(path) as f:
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

    def _find_image(self, image_path: str | None = None) -> Path:
        """Find TDX VM image. Returns an absolute path."""
        search_paths = [
            image_path,
            os.environ.get("TDX_IMAGE_PATH"),
            # Customized image with launcher (built by build_image.sh)
            str(self.infra_dir / "output/tdx-runner.qcow2"),
            str(self.workspace / "infra/output/tdx-runner.qcow2"),
            # Legacy paths
            str(self.infra_dir / "vm_images/output/tdx-runner.qcow2"),
            str(self.workspace / "vm_images/output/tdx-runner.qcow2"),
            "/var/lib/tdx/images/tdx-runner.qcow2",
            # Base Canonical image (no launcher - fallback only)
            str(Path.home() / "tdx/guest-tools/image/tdx-guest-ubuntu-24.04-generic.qcow2"),
        ]
        for p in search_paths:
            if p and Path(p).exists():
                # Return absolute path so qemu-img can find it regardless of cwd
                return Path(p).resolve()
        raise FileNotFoundError("TDX image not found. Set TDX_IMAGE_PATH or provide --image path.")

    def _get_template(self) -> Path:
        """Get XML template path."""
        return self.infra_dir / "vm_templates" / "trust_domain.xml.template"

    def _create_cloud_init_iso(self, vm_id: str, config: dict) -> Path:
        """Create NoCloud ISO with VM configuration.

        Args:
            vm_id: Unique VM identifier
            config: Configuration dict to pass to launcher

        Returns:
            Path to cloud-init ISO
        """
        iso_dir = self.WORKDIR / f"cidata.{vm_id}"
        iso_dir.mkdir(parents=True, exist_ok=True)

        # user-data with cloud-config
        user_data = f"""#cloud-config
write_files:
  - path: /etc/easyenclave/config.json
    content: '{json.dumps(config)}'
    owner: root:root
    permissions: '0644'

# Enable login for debugging
password: tdx
chpasswd:
  expire: false
ssh_pwauth: true
"""
        (iso_dir / "user-data").write_text(user_data)

        # meta-data (required by NoCloud)
        meta_data = f"instance-id: {vm_id}\nlocal-hostname: tdx-{vm_id[:8]}\n"
        (iso_dir / "meta-data").write_text(meta_data)

        # Create ISO with genisoimage
        iso_path = self.WORKDIR / f"cidata.{vm_id}.iso"
        subprocess.run(
            [
                "genisoimage",
                "-output",
                str(iso_path),
                "-volid",
                "cidata",
                "-joliet",
                "-rock",
                str(iso_dir),
            ],
            check=True,
            capture_output=True,
        )
        iso_path.chmod(0o644)

        return iso_path

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

    def vm_new(
        self,
        image: str | None = None,
        mode: str = AGENT_MODE,
        config: dict | None = None,
    ) -> dict:
        """Create and boot a new TDX VM.

        The VM boots with the launcher agent pre-installed, which will
        either run the control plane (if mode=control-plane) or register
        with the control plane and poll for deployments (if mode=agent).

        Args:
            image: Path to TDX VM image (auto-detected if not provided)
            mode: Launcher mode (control-plane or agent)
            config: Additional config to pass to launcher

        Returns:
            Dict with vm_name, uuid, and info
        """
        image_path = self._find_image(image)
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
        overlay_path = self.WORKDIR / f"overlay.{rand_str}.qcow2"

        subprocess.run(
            [
                "qemu-img",
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                str(image_path),
                str(overlay_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        # Make overlay writable by QEMU (runs as ubuntu per qemu.conf)
        overlay_path.chmod(0o666)

        # Create cloud-init ISO with config
        launcher_config = {
            "mode": mode,
            "vm_id": rand_str,
            **(config or {}),
        }
        cloud_init_iso = self._create_cloud_init_iso(rand_str, launcher_config)

        # Create serial console log file with world-readable permissions
        # (libvirt will append to it, preserving permissions)
        serial_log = self.WORKDIR / f"console.{rand_str}.log"
        serial_log.touch(mode=0o644)

        # Generate domain XML
        xml_content = template.read_text()
        xml_content = xml_content.replace("BASE_IMG_PATH", str(image_path))
        xml_content = xml_content.replace("OVERLAY_IMG_PATH", str(overlay_path))
        xml_content = xml_content.replace("CLOUD_INIT_ISO", str(cloud_init_iso))
        xml_content = xml_content.replace("SERIAL_LOG_PATH", str(serial_log))
        xml_content = xml_content.replace("DOMAIN", self.DOMAIN_PREFIX)
        xml_content = xml_content.replace("HOSTDEV_DEVICES", "")

        xml_path = self.WORKDIR / f"{self.DOMAIN_PREFIX}.{rand_str}.xml"
        xml_path.write_text(xml_content)

        # Define and start VM
        self._virsh("define", str(xml_path), check=True)

        # Get UUID and rename
        result = self._virsh("domuuid", self.DOMAIN_PREFIX, text=True, check=True)
        vm_uuid = result.stdout.strip()

        # Determine template name for domain prefix
        template_name = template.stem.replace(".xml", "")
        vm_name = f"{self.DOMAIN_PREFIX}-{template_name}-{vm_uuid}"

        self._virsh("domrename", self.DOMAIN_PREFIX, vm_name, check=True)
        self._virsh("start", vm_name, check=True)

        # Get VM info
        result = self._virsh("dominfo", vm_name, text=True)

        return {
            "name": vm_name,
            "uuid": vm_uuid,
            "mode": mode,
            "serial_log": str(serial_log),
            "info": result.stdout,
        }

    def control_plane_new(self, image: str | None = None, port: int = 8080) -> dict:
        """Launch a control plane in a TDX VM.

        This bootstraps a new EasyEnclave network. The control plane runs
        directly in the VM without needing to poll an external control plane.

        If Cloudflare environment variables are set, the control plane will
        create a tunnel and be accessible at https://app.{domain}.

        Environment variables for Cloudflare tunnel:
        - CLOUDFLARE_API_TOKEN: API token with Tunnel and DNS edit permissions
        - CLOUDFLARE_ACCOUNT_ID: Cloudflare account ID
        - CLOUDFLARE_ZONE_ID: Zone ID for the domain
        - EASYENCLAVE_DOMAIN: Domain for hostnames (default: easyenclave.com)

        Args:
            image: Path to TDX VM image (auto-detected if not provided)
            port: Port for the control plane API (default 8080)

        Returns:
            Dict with vm_name, uuid, control_plane_url, and info
        """
        config = {
            "port": port,
            "easyenclave_repo": "https://github.com/easyenclave/easyenclave.git",
            # Cloudflare config for self-tunneling (if env vars are set)
            "cloudflare_api_token": os.environ.get("CLOUDFLARE_API_TOKEN"),
            "cloudflare_account_id": os.environ.get("CLOUDFLARE_ACCOUNT_ID"),
            "cloudflare_zone_id": os.environ.get("CLOUDFLARE_ZONE_ID"),
            "easyenclave_domain": os.environ.get("EASYENCLAVE_DOMAIN", "easyenclave.com"),
            # Intel Trust Authority for verifying agent attestations
            "intel_api_key": os.environ.get("INTEL_API_KEY"),
        }
        result = self.vm_new(image=image, mode=CONTROL_PLANE_MODE, config=config)
        result["control_plane_port"] = port

        # Add expected hostname if Cloudflare is configured
        if config.get("cloudflare_api_token"):
            result["control_plane_hostname"] = f"app.{config['easyenclave_domain']}"

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
        self._virsh("shutdown", name)
        time.sleep(2)

        # Then force destroy
        self._virsh("destroy", name)
        self._virsh("undefine", name)

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


def main():
    parser = argparse.ArgumentParser(
        description="TDX CLI - Manage TDX VM lifecycle",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tdx control-plane new               Launch control plane in TDX VM (bootstrap new network)
  tdx vm new                          Create new TDX VM (registers with control plane)
  tdx vm list                         List all TDX VMs
  tdx vm status <name>                Get VM status
  tdx vm delete <name>                Delete a TDX VM
  tdx vm delete all                   Delete all TDX VMs

To start a new EasyEnclave network:
  1. tdx control-plane new            Launch control plane
  2. tdx vm new                       Launch agent VMs that register with control plane
  3. POST /api/v1/deployments         Deploy workloads via API
        """,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Control plane commands
    cp_parser = subparsers.add_parser("control-plane", help="Control plane management")
    cp_sub = cp_parser.add_subparsers(dest="cp_command", required=True)

    cp_new_parser = cp_sub.add_parser("new", help="Launch control plane in TDX VM")
    cp_new_parser.add_argument("-i", "--image", help="Path to TDX image")
    cp_new_parser.add_argument(
        "-p", "--port", type=int, default=8080, help="API port (default 8080)"
    )
    cp_new_parser.add_argument(
        "--wait", action="store_true", help="Wait for control plane to be ready"
    )

    # VM commands
    vm_parser = subparsers.add_parser("vm", help="VM lifecycle management")
    vm_sub = vm_parser.add_subparsers(dest="vm_command", required=True)

    new_parser = vm_sub.add_parser("new", help="Create new TDX VM")
    new_parser.add_argument("-i", "--image", help="Path to TDX image")
    new_parser.add_argument(
        "--easyenclave-url",
        default="https://app.easyenclave.com",
        help="Control plane URL for agent registration (default: https://app.easyenclave.com)",
    )
    new_parser.add_argument(
        "--intel-api-key",
        default=os.environ.get("INTEL_API_KEY", ""),
        help="Intel Trust Authority API key (or set INTEL_API_KEY env var)",
    )
    new_parser.add_argument("--wait", action="store_true", help="Wait for agent to get IP")

    vm_sub.add_parser("list", help="List TDX VMs")

    status_parser = vm_sub.add_parser("status", help="Get VM status")
    status_parser.add_argument("name", help="VM name")

    del_parser = vm_sub.add_parser("delete", help="Delete TDX VM")
    del_parser.add_argument("name", help="VM name or 'all'")

    args = parser.parse_args()
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", "."))
    mgr = TDXManager(workspace)

    try:
        if args.command == "control-plane":
            if args.cp_command == "new":
                print("Launching control plane in TDX VM...", file=sys.stderr)
                result = mgr.control_plane_new(args.image, args.port)

                if args.wait:
                    print("\nWaiting for VM to get IP...", file=sys.stderr)
                    ip = mgr.get_vm_ip(result["name"])
                    if ip:
                        url = f"http://{ip}:{args.port}"
                        print(f"Control plane VM IP: {ip}", file=sys.stderr)
                        print(f"Control plane URL: {url}", file=sys.stderr)

                        # Wait for control plane to be ready
                        print("Waiting for control plane to start...", file=sys.stderr)
                        import urllib.error
                        import urllib.request

                        # Always include IP in result so workflow can proceed
                        result["ip"] = ip
                        result["control_plane_url"] = url

                        # Start tailing serial log in background
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

                        for _ in range(120):  # 4 minutes for docker build on first boot
                            try:
                                with urllib.request.urlopen(f"{url}/health", timeout=5) as resp:
                                    if resp.status == 200:
                                        stop_tail.set()
                                        print(
                                            f"\n=== Control plane ready at {url} ===",
                                            file=sys.stderr,
                                        )
                                        break
                            except (urllib.error.URLError, TimeoutError):
                                pass
                            time.sleep(2)
                        else:
                            stop_tail.set()
                            print("Warning: Control plane did not become ready", file=sys.stderr)

                        # Always print final result with IP
                        print(json.dumps(result, indent=2))
                    else:
                        print("Warning: Could not get VM IP", file=sys.stderr)
                        print(json.dumps(result, indent=2))
                else:
                    # No --wait, just print immediately
                    print(json.dumps(result, indent=2))

        elif args.command == "vm":
            if args.vm_command == "new":
                config = {
                    "control_plane_url": args.easyenclave_url,
                    "intel_api_key": args.intel_api_key,
                }
                result = mgr.vm_new(args.image, config=config)
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
                        print("Warning: Could not get VM IP", file=sys.stderr)
            elif args.vm_command == "list":
                for vm in mgr.vm_list():
                    print(vm)
            elif args.vm_command == "status":
                result = mgr.vm_status(args.name)
                print(json.dumps(result, indent=2))
            elif args.vm_command == "delete":
                if args.name == "all":
                    for vm in mgr.vm_list():
                        print(f"Deleting {vm}...")
                        mgr.vm_delete(vm)
                else:
                    mgr.vm_delete(args.name)

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
