#!/bin/bash
# Boot easyenclave locally with TDX via direct kernel boot.
#
# Uses qemu -kernel/-initrd/-append (no OVMF, no Secure Boot).
# TDX still works at the CPU level via -object tdx-guest.
#
# Usage:
#   bash image/test-local.sh [agent.env]
#
# If agent.env is provided, a config ISO is built and attached as
# a secondary disk. easyenclave reads /agent.env from it at boot
# and applies the contents as env vars (EE_BOOT_WORKLOADS, etc.).
#
# Serial output goes to stdout — you see the boot chain live.
# Ctrl-A X to quit qemu.
#
# Prerequisites:
#   - qemu-system-x86_64
#   - TDX-capable host (cat /sys/module/kvm_intel/parameters/tdx → Y)
#   - genisoimage (only if passing agent.env)
#   - Build artifacts in image/output/ (run `make build` first)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/output"
ENV_FILE="${1:-}"

# ── Check prerequisites ──────────────────────────────────────────────
for f in easyenclave.vmlinuz easyenclave.initrd easyenclave.cmdline easyenclave.qcow2; do
    [ -f "$OUTPUT_DIR/$f" ] || { echo "Missing $OUTPUT_DIR/$f — run 'make build' first"; exit 1; }
done

command -v qemu-system-x86_64 >/dev/null || { echo "qemu-system-x86_64 not found"; exit 1; }

TDX_SUPPORT=$(cat /sys/module/kvm_intel/parameters/tdx 2>/dev/null || echo "N")
if [ "$TDX_SUPPORT" != "Y" ]; then
    echo "WARNING: TDX not available on this host (kvm_intel.tdx=$TDX_SUPPORT)"
    echo "         Booting without TDX — attestation will fail but everything else works."
    TDX_FLAGS=""
else
    TDX_FLAGS="-machine q35,kernel-irqchip=split,confidential-guest-support=tdx -object tdx-guest,id=tdx"
fi

# ── Build config ISO (optional) ──────────────────────────────────────
CONFIG_DRIVE=""
if [ -n "$ENV_FILE" ]; then
    [ -f "$ENV_FILE" ] || { echo "agent.env not found: $ENV_FILE"; exit 1; }
    command -v genisoimage >/dev/null || { echo "genisoimage not found (apt install genisoimage)"; exit 1; }

    CONFIG_ISO=$(mktemp --suffix=.iso)
    trap 'rm -f "$CONFIG_ISO"' EXIT

    genisoimage -quiet -o "$CONFIG_ISO" -V CONFIG -r -J "$ENV_FILE"
    CONFIG_DRIVE="-drive file=$CONFIG_ISO,if=virtio,format=raw,media=cdrom,readonly=on"
    echo "Config ISO: $CONFIG_ISO (from $ENV_FILE)"
fi

# ── Boot ─────────────────────────────────────────────────────────────
CMDLINE=$(cat "$OUTPUT_DIR/easyenclave.cmdline")
echo "Kernel:  $OUTPUT_DIR/easyenclave.vmlinuz"
echo "Initrd:  $OUTPUT_DIR/easyenclave.initrd"
echo "Cmdline: $CMDLINE"
echo "Disk:    $OUTPUT_DIR/easyenclave.qcow2 (snapshot=on, never modified)"
echo "Network: virtio-net + qemu user-mode (DHCP 10.0.2.x, DNS forwarded)"
echo "TDX:     $TDX_SUPPORT"
echo ""
echo "Serial output below. Ctrl-A X to quit."
echo "════════════════════════════════════════════════════════════════"

# shellcheck disable=SC2086
exec qemu-system-x86_64 \
    -enable-kvm -cpu host -m 4G -smp 2 \
    ${TDX_FLAGS:--machine q35} \
    -kernel "$OUTPUT_DIR/easyenclave.vmlinuz" \
    -initrd "$OUTPUT_DIR/easyenclave.initrd" \
    -append "$CMDLINE" \
    -drive "file=$OUTPUT_DIR/easyenclave.qcow2,if=virtio,format=qcow2,snapshot=on" \
    $CONFIG_DRIVE \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
    -serial mon:stdio \
    -nographic
