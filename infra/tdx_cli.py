#!/usr/bin/env python3
"""TDX CLI - Manage TDX VMs and workloads.

Consolidates tdvirsh and GitHub Action shell scripts into a single Python CLI.
Supports VM lifecycle management and workload deployment with attestation.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path


class TDXManager:
    """Manages TDX VM lifecycle and workloads."""

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
        """Find TDX VM image."""
        search_paths = [
            image_path,
            os.environ.get("TDX_IMAGE_PATH"),
            str(self.infra_dir / "vm_images/output/tdx-runner.qcow2"),
            str(self.workspace / "vm_images/output/tdx-runner.qcow2"),
            "/var/lib/tdx/images/tdx-runner.qcow2",
            str(Path.home() / "tdx/guest-tools/image/tdx-guest-ubuntu-24.04-generic.qcow2"),
        ]
        for p in search_paths:
            if p and Path(p).exists():
                return Path(p)
        raise FileNotFoundError("TDX image not found. Set TDX_IMAGE_PATH or provide --image path.")

    def _get_template(self, shared: bool = False) -> Path:
        """Get XML template path."""
        name = "trust_domain_shared.xml.template" if shared else "trust_domain.xml.template"
        return self.infra_dir / "vm_templates" / name

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

    # =========================================================================
    # VM lifecycle methods (replacing tdvirsh)
    # =========================================================================

    def vm_new(self, image: str | None = None, share_dir: str | None = None) -> dict:
        """Create and boot a new TDX VM.

        Args:
            image: Path to TDX VM image (auto-detected if not provided)
            share_dir: Host directory to share with VM via 9P

        Returns:
            Dict with vm_name, uuid, and info
        """
        image_path = self._find_image(image)
        template = self._get_template(shared=bool(share_dir))

        if not template.exists():
            raise FileNotFoundError(f"XML template not found: {template}")

        # Create overlay image
        self.WORKDIR.mkdir(parents=True, exist_ok=True)
        rand_str = uuid.uuid4().hex[:15]
        overlay_path = self.WORKDIR / f"overlay.{rand_str}.qcow2"

        result = subprocess.run(
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

        # Generate domain XML
        xml_content = template.read_text()
        xml_content = xml_content.replace("BASE_IMG_PATH", str(image_path))
        xml_content = xml_content.replace("OVERLAY_IMG_PATH", str(overlay_path))
        xml_content = xml_content.replace("DOMAIN", self.DOMAIN_PREFIX)
        xml_content = xml_content.replace("HOSTDEV_DEVICES", "")
        if share_dir:
            xml_content = xml_content.replace("SHARED_DIR", str(Path(share_dir).resolve()))

        xml_path = self.WORKDIR / f"{self.DOMAIN_PREFIX}.xml"
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

        return {"name": vm_name, "uuid": vm_uuid, "info": result.stdout}

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

        # Note: Overlay cleanup is handled by cleaning up the share directory
        # The overlay path is stored in the VM XML, but we don't track it here

    def vm_list(self) -> list:
        """List all TDX VMs.

        Returns:
            List of VM names managed by tdvirsh
        """
        result = self._virsh("list", "--all", "--name", text=True)
        return [n for n in result.stdout.strip().split("\n") if n.startswith(self.DOMAIN_PREFIX)]

    # =========================================================================
    # Workload methods (replacing action shell code)
    # =========================================================================

    def measure(self, compose_path: str, config: dict) -> dict:
        """Run ephemeral workload with attestation.

        Launches TDX VM, runs workload, waits for attestation, then cleans up.

        Args:
            compose_path: Path to docker-compose.yml
            config: Configuration dict with intel_api_key, timeout_minutes, etc.

        Returns:
            Dict with vm_name, attestation, share_dir
        """
        share_dir = Path(tempfile.mkdtemp(prefix="tdx-share-"))
        vm_name = None

        try:
            # Setup shared directory
            self._setup_share_dir(share_dir, compose_path, config)

            # Launch VM
            vm_info = self.vm_new(share_dir=str(share_dir))
            vm_name = vm_info["name"]

            # Wait for attestation
            attestation = self._wait_for_file(
                share_dir / "attestation.json",
                timeout=config.get("timeout_minutes", 30) * 60,
            )
            return {
                "vm_name": vm_name,
                "attestation": attestation,
                "share_dir": str(share_dir),
            }
        finally:
            if vm_name:
                self.vm_delete(vm_name)
            shutil.rmtree(share_dir, ignore_errors=True)

    def launch(
        self, vm_name: str, compose_path: str | None = None, config: dict | None = None
    ) -> dict:
        """Launch persistent TDX VM.

        Args:
            vm_name: Name for identification (not used by libvirt directly)
            compose_path: Optional path to docker-compose.yml
            config: Optional configuration dict

        Returns:
            Dict with vm_name and share_dir
        """
        share_dir = Path(tempfile.mkdtemp(prefix="tdx-share-"))
        config = config or {}
        config["mode"] = "persistent"

        self._setup_share_dir(share_dir, compose_path, config)
        vm_info = self.vm_new(share_dir=str(share_dir))

        # Wait for ready
        self._wait_for_status(share_dir, "ready", timeout=config.get("timeout_minutes", 10) * 60)

        return {"vm_name": vm_info["name"], "share_dir": str(share_dir)}

    def deploy(self, service_name: str, service_url: str, compose_path: str, config: dict) -> dict:
        """Deploy with attestation and EasyEnclave registration.

        Args:
            service_name: Name for EasyEnclave registration
            service_url: Public URL of the service
            compose_path: Path to docker-compose.yml
            config: Configuration with intel_api_key, easyenclave_url, etc.

        Returns:
            Dict with vm_name, share_dir, attestation, registration, service_id, mrtd
        """
        share_dir = Path(tempfile.mkdtemp(prefix="tdx-share-"))
        config["mode"] = "persistent"
        config["service_name"] = service_name
        config["service_url"] = service_url

        self._setup_share_dir(share_dir, compose_path, config)
        vm_info = self.vm_new(share_dir=str(share_dir))

        # Wait for ready, attestation, and registration
        self._wait_for_status(share_dir, "ready", timeout=600)
        attestation = self._wait_for_file(share_dir / "attestation.json", timeout=120)
        registration = self._wait_for_file(share_dir / "registration.json", timeout=60)

        return {
            "vm_name": vm_info["name"],
            "share_dir": str(share_dir),
            "attestation": attestation,
            "registration": registration,
            "service_id": registration.get("service_id"),
            "mrtd": attestation.get("tdx", {}).get("measurements", {}).get("mrtd"),
        }

    def _setup_share_dir(self, share_dir: Path, compose_path: str | None, config: dict):
        """Setup shared directory with compose file and config.

        Args:
            share_dir: Directory to setup
            compose_path: Path to docker-compose.yml (optional)
            config: Configuration dict to write as config.json
        """
        if compose_path:
            compose_src = Path(compose_path)
            if not compose_src.exists():
                raise FileNotFoundError(f"Compose file not found: {compose_path}")

            shutil.copy(compose_src, share_dir / "docker-compose.yml")

            # Copy build context (files from compose file directory)
            skip_patterns = {".git", ".github", "node_modules", "__pycache__", ".venv", "venv"}
            for item in compose_src.parent.iterdir():
                if item.name in skip_patterns:
                    continue
                if item.name == compose_src.name:
                    continue  # Already copied
                try:
                    if item.is_file():
                        shutil.copy(item, share_dir)
                    elif item.is_dir():
                        shutil.copytree(
                            item,
                            share_dir / item.name,
                            ignore=shutil.ignore_patterns(*skip_patterns),
                        )
                except (PermissionError, OSError):
                    pass  # Skip files we can't copy

        (share_dir / "config.json").write_text(json.dumps(config, indent=2))

    def _wait_for_file(self, path: Path, timeout: int) -> dict:
        """Wait for file to appear and return JSON contents.

        Args:
            path: File path to wait for
            timeout: Timeout in seconds

        Returns:
            Parsed JSON contents of the file

        Raises:
            TimeoutError: If file doesn't appear within timeout
            RuntimeError: If error.log appears
        """
        start = time.time()
        while time.time() - start < timeout:
            if path.exists():
                return json.loads(path.read_text())
            error_log = path.parent / "error.log"
            if error_log.exists():
                raise RuntimeError(f"Error: {error_log.read_text()}")
            time.sleep(2)
        raise TimeoutError(f"Timeout waiting for {path}")

    def _wait_for_status(self, share_dir: Path, status: str, timeout: int):
        """Wait for status file to contain expected value.

        Args:
            share_dir: Share directory containing status file
            status: Expected status value
            timeout: Timeout in seconds

        Raises:
            TimeoutError: If status doesn't match within timeout
            RuntimeError: If error.log appears
        """
        start = time.time()
        status_file = share_dir / "status"
        while time.time() - start < timeout:
            if status_file.exists() and status_file.read_text().strip() == status:
                return
            error_log = share_dir / "error.log"
            if error_log.exists():
                raise RuntimeError(f"Error: {error_log.read_text()}")
            time.sleep(2)
        raise TimeoutError(f"Timeout waiting for status={status}")


def main():
    parser = argparse.ArgumentParser(
        description="TDX CLI - Manage TDX VMs and workloads",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tdx vm new                          Create new TDX VM
  tdx vm new -s /path/to/share        Create VM with shared directory
  tdx vm list                         List all TDX VMs
  tdx vm delete all                   Delete all TDX VMs

  tdx measure --compose docker-compose.yml --intel-api-key KEY
  tdx launch --name myvm --compose docker-compose.yml
  tdx deploy --service-name myapp --service-url https://example.com --compose docker-compose.yml --intel-api-key KEY
        """,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # VM commands (replacing tdvirsh)
    vm_parser = subparsers.add_parser("vm", help="VM lifecycle management")
    vm_sub = vm_parser.add_subparsers(dest="vm_command", required=True)

    new_parser = vm_sub.add_parser("new", help="Create new TDX VM")
    new_parser.add_argument("-i", "--image", help="Path to TDX image")
    new_parser.add_argument("-s", "--share-dir", help="Shared directory")

    vm_sub.add_parser("list", help="List TDX VMs")

    del_parser = vm_sub.add_parser("delete", help="Delete TDX VM")
    del_parser.add_argument("name", help="VM name or 'all'")

    # Workload commands
    measure_parser = subparsers.add_parser("measure", help="Run ephemeral workload")
    measure_parser.add_argument("--compose", required=True, help="Path to docker-compose.yml")
    measure_parser.add_argument("--intel-api-key", required=True, help="Intel TA API key")
    measure_parser.add_argument("--intel-api-url", default="https://api.trustauthority.intel.com")
    measure_parser.add_argument("--timeout", type=int, default=30, help="Timeout in minutes")
    measure_parser.add_argument("--health-endpoint", default="/health")
    measure_parser.add_argument("--compose-up-args", default="--build -d")

    launch_parser = subparsers.add_parser("launch", help="Launch persistent VM")
    launch_parser.add_argument("--name", required=True, help="VM name for identification")
    launch_parser.add_argument("--compose", help="Path to docker-compose.yml")
    launch_parser.add_argument("--intel-api-key", help="Intel TA API key (optional)")
    launch_parser.add_argument("--timeout", type=int, default=10, help="Timeout in minutes")
    launch_parser.add_argument("--compose-up-args", default="-d")

    deploy_parser = subparsers.add_parser("deploy", help="Deploy with registration")
    deploy_parser.add_argument("--service-name", required=True, help="EasyEnclave service name")
    deploy_parser.add_argument("--service-url", required=True, help="Public service URL")
    deploy_parser.add_argument("--compose", required=True, help="Path to docker-compose.yml")
    deploy_parser.add_argument("--intel-api-key", required=True, help="Intel TA API key")
    deploy_parser.add_argument("--intel-api-url", default="https://api.trustauthority.intel.com")
    deploy_parser.add_argument(
        "--easyenclave-url", default="https://app.easyenclave.com", help="EasyEnclave API URL"
    )
    deploy_parser.add_argument("--health-endpoint", default="/health")
    deploy_parser.add_argument("--compose-up-args", default="--build -d")
    deploy_parser.add_argument("--source-repo", help="Source repository URL")
    deploy_parser.add_argument("--source-commit", help="Source commit SHA")
    deploy_parser.add_argument("--tags", default="[]", help="JSON array of tags")

    args = parser.parse_args()
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", "."))
    mgr = TDXManager(workspace)

    try:
        if args.command == "vm":
            if args.vm_command == "new":
                result = mgr.vm_new(args.image, args.share_dir)
                print(json.dumps(result, indent=2))
            elif args.vm_command == "list":
                for vm in mgr.vm_list():
                    print(vm)
            elif args.vm_command == "delete":
                if args.name == "all":
                    for vm in mgr.vm_list():
                        print(f"Deleting {vm}...")
                        mgr.vm_delete(vm)
                else:
                    mgr.vm_delete(args.name)

        elif args.command == "measure":
            result = mgr.measure(
                args.compose,
                {
                    "intel_api_key": args.intel_api_key,
                    "intel_api_url": args.intel_api_url,
                    "timeout_minutes": args.timeout,
                    "health_endpoint": args.health_endpoint,
                    "compose_up_args": args.compose_up_args,
                },
            )
            print(json.dumps(result, indent=2))

        elif args.command == "launch":
            result = mgr.launch(
                args.name,
                args.compose,
                {
                    "timeout_minutes": args.timeout,
                    "intel_api_key": args.intel_api_key or "",
                    "compose_up_args": args.compose_up_args,
                },
            )
            print(json.dumps(result, indent=2))

        elif args.command == "deploy":
            tags = json.loads(args.tags) if args.tags else []
            result = mgr.deploy(
                args.service_name,
                args.service_url,
                args.compose,
                {
                    "intel_api_key": args.intel_api_key,
                    "intel_api_url": args.intel_api_url,
                    "easyenclave_url": args.easyenclave_url,
                    "health_endpoint": args.health_endpoint,
                    "compose_up_args": args.compose_up_args,
                    "source_repo": args.source_repo or "",
                    "source_commit": args.source_commit or "",
                    "tags": tags,
                },
            )
            print(json.dumps(result, indent=2))

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except TimeoutError as e:
        print(f"Timeout: {e}", file=sys.stderr)
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
