#!/bin/bash
# run-local.sh — boot the sealed easyenclave image locally on this
# host via libvirt with real TDX launch security.
#
# Usage:
#   bash image/run-local.sh <qcow2> <agent.env>
#   bash image/run-local.sh --destroy
#
# Requires a TDX-capable host with:
#   - kvm_intel.tdx=Y (check: /sys/module/kvm_intel/parameters/tdx)
#   - libvirt + virt-install + qemu-system-x86 installed
#   - /usr/share/OVMF/OVMF_CODE.fd (apt install ovmf)
#   - genisoimage (apt install genisoimage)
#   - user in the libvirt group
#
# What it does:
#   1. Destroys any existing easyenclave-local domain (idempotent).
#   2. Builds a tiny iso9660 config disk with /agent.env via
#      genisoimage (no sudo, no mkfs, same pattern marketplace uses).
#   3. Copies the qcow2 and config disk into /var/lib/libvirt/images/
#      (sudo, because the dir is root-owned).
#   4. Calls virt-install with --launchSecurity type=tdx — real TDX
#      attestation, not mock. The sealed VM's configfs-tsm interface
#      reports against the same MRTD/RTMR measurements it would on GCP.
#   5. Attaches serial console via virsh console (Ctrl-] to exit).
#
# Lifecycle:
#   - Per-invocation: destroys prior instance, creates fresh one
#   - Destroy only:   ./run-local.sh --destroy
#
# TDX attestation is REAL on this host because kvm_intel has tdx=Y.
# On a non-TDX host this script fails at virt-install with a clear
# error (the --launchSecurity type=tdx flag is rejected).

set -euo pipefail

VM_NAME="easyenclave-local"
IMAGES_DIR="/var/lib/libvirt/images"

usage() {
    cat <<EOF >&2
Usage: run-local.sh <qcow2> <agent.env>
       run-local.sh --destroy

Arguments:
  qcow2       Path to easyenclave qcow2 image (from GH release or local make build)
  agent.env   KEY=VALUE file (one per line) — easyenclave reads this at PID 1 init
              via the secondary config disk path in src/init.rs.

Flags:
  --destroy   Destroy the existing easyenclave-local domain and exit.
EOF
    exit 1
}

destroy_existing() {
    if virsh dominfo "$VM_NAME" &>/dev/null; then
        echo "stopping existing $VM_NAME..."
        virsh destroy "$VM_NAME" 2>/dev/null || true
        virsh undefine "$VM_NAME" --remove-all-storage 2>/dev/null || true
    fi
}

if [[ "${1:-}" == "--destroy" ]]; then
    destroy_existing
    echo "done."
    exit 0
fi

QCOW2="${1:?}"; ENV_FILE="${2:?}"
[[ $# -eq 2 ]] || usage

[ -f "$QCOW2" ]    || { echo "qcow2 not found: $QCOW2" >&2; exit 1; }
[ -f "$ENV_FILE" ] || { echo "agent.env not found: $ENV_FILE" >&2; exit 1; }

# ── Preflight ────────────────────────────────────────────────────────────
TDX_FLAG=$(cat /sys/module/kvm_intel/parameters/tdx 2>/dev/null || echo "N")
if [ "$TDX_FLAG" != "Y" ]; then
    echo "warning: kvm_intel tdx=$TDX_FLAG — --launchSecurity type=tdx will fail" >&2
    echo "         ensure the host boots with kvm_intel.tdx=1 kernel param" >&2
fi

for bin in virsh virt-install genisoimage; do
    command -v "$bin" >/dev/null || {
        echo "required tool not found: $bin" >&2
        echo "try: sudo apt-get install libvirt-clients virtinst qemu-system-x86 genisoimage" >&2
        exit 1
    }
done

# ── Stop any prior instance ──────────────────────────────────────────────
destroy_existing

# ── Build the iso9660 config disk ────────────────────────────────────────
# easyenclave's src/init.rs:76-92 probes /dev/vdb (and /dev/sdb) for a
# secondary config disk in iso9660/ext4/vfat/ext2 and reads /agent.env
# from its root. iso9660 via genisoimage is the simplest offline build:
# no mkfs, no loop mount, no mtools — same tool marketplace uses to
# ship cloud-init media on the same baremetal host.
STAGING_DIR=$(mktemp -d)
CONFIG_ISO=$(mktemp --suffix=.iso)
trap 'rm -rf "$STAGING_DIR" "$CONFIG_ISO"' EXIT

install -m 0644 "$ENV_FILE" "${STAGING_DIR}/agent.env"
genisoimage -quiet -output "$CONFIG_ISO" -volid ee-config -joliet -rock "$STAGING_DIR"

# ── Copy images into libvirt's dir (root-owned, needs sudo) ─────────────
BOOT_DISK="${IMAGES_DIR}/${VM_NAME}.qcow2"
CONFIG_DISK="${IMAGES_DIR}/${VM_NAME}-config.iso"
sudo install -m 0644 "$QCOW2"      "$BOOT_DISK"
sudo install -m 0644 "$CONFIG_ISO" "$CONFIG_DISK"

# ── Launch with real TDX ─────────────────────────────────────────────────
# q35 machine + UEFI firmware + launchSecurity type=tdx is the minimum
# set for Intel TDX on libvirt. The default virbr0 NAT bridge gives
# DHCP on 192.168.122.x so easyenclave's dhclient at init gets a lease
# and can reach the outside world.
echo "easyenclave: libvirt launch"
echo "  vm:      $VM_NAME (TDX)"
echo "  image:   $QCOW2 → $BOOT_DISK"
echo "  config:  $ENV_FILE → /dev/vdb → /agent.env"
echo

virt-install \
    --name "$VM_NAME" \
    --ram 4096 \
    --vcpus 2 \
    --machine q35 \
    --disk "path=${BOOT_DISK},format=qcow2,bus=virtio" \
    --disk "path=${CONFIG_DISK},format=raw,bus=virtio" \
    --network bridge=virbr0 \
    --graphics none \
    --console pty,target_type=serial \
    --boot firmware=efi \
    --launchSecurity type=tdx \
    --import \
    --noautoconsole

echo
echo "attached to $VM_NAME serial console (Ctrl-] to detach):"
exec virsh console "$VM_NAME"
