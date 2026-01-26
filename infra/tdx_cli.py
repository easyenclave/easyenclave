#!/usr/bin/env python3
"""TDX CLI - Manage TDX VM lifecycle.

Simple CLI for launching and managing TDX VMs with the launcher agent pre-installed.
VMs boot in "undeployed" state and register with the control plane.

All deployments go through the control plane API - this CLI only handles VM lifecycle.
"""

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path


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

    def _get_template(self) -> Path:
        """Get XML template path."""
        return self.infra_dir / "vm_templates" / "trust_domain.xml.template"

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

    def vm_new(self, image: str | None = None) -> dict:
        """Create and boot a new TDX VM.

        The VM boots with the launcher agent pre-installed, which will
        register with the control plane and poll for deployments.

        Args:
            image: Path to TDX VM image (auto-detected if not provided)

        Returns:
            Dict with vm_name, uuid, and info
        """
        image_path = self._find_image(image)
        template = self._get_template()

        if not template.exists():
            raise FileNotFoundError(f"XML template not found: {template}")

        # Create overlay image
        self.WORKDIR.mkdir(parents=True, exist_ok=True)
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

        # Generate domain XML
        xml_content = template.read_text()
        xml_content = xml_content.replace("BASE_IMG_PATH", str(image_path))
        xml_content = xml_content.replace("OVERLAY_IMG_PATH", str(overlay_path))
        xml_content = xml_content.replace("DOMAIN", self.DOMAIN_PREFIX)
        xml_content = xml_content.replace("HOSTDEV_DEVICES", "")

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
  tdx vm new                          Create new TDX VM (registers with control plane)
  tdx vm list                         List all TDX VMs
  tdx vm status <name>                Get VM status
  tdx vm delete <name>                Delete a TDX VM
  tdx vm delete all                   Delete all TDX VMs

Note: All deployments go through the control plane API.
VMs boot with the launcher agent which registers and polls for deployments.
        """,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # VM commands
    vm_parser = subparsers.add_parser("vm", help="VM lifecycle management")
    vm_sub = vm_parser.add_subparsers(dest="vm_command", required=True)

    new_parser = vm_sub.add_parser("new", help="Create new TDX VM")
    new_parser.add_argument("-i", "--image", help="Path to TDX image")

    vm_sub.add_parser("list", help="List TDX VMs")

    status_parser = vm_sub.add_parser("status", help="Get VM status")
    status_parser.add_argument("name", help="VM name")

    del_parser = vm_sub.add_parser("delete", help="Delete TDX VM")
    del_parser.add_argument("name", help="VM name or 'all'")

    args = parser.parse_args()
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", "."))
    mgr = TDXManager(workspace)

    try:
        if args.command == "vm":
            if args.vm_command == "new":
                result = mgr.vm_new(args.image)
                print(json.dumps(result, indent=2))
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
