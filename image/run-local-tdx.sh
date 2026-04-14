#!/bin/bash
# Boot the local-tdx ISO under QEMU with OVMF + TDX.
#
# This is the full boot chain: OVMF firmware → UKI on embedded ESP →
# kernel + initrd → squashfs+overlay init → easyenclave. Same path as
# a production TDX launch, different TDVF binary and different machine
# topology — the MRTD/RTMR values WILL differ from the GCP profile.
#
# Usage:
#   bash image/run-local-tdx.sh [agent.env]
#
# If agent.env is supplied, a second iso9660 volume is attached — the
# exact same config-disk plumbing easyenclave's init.rs already uses
# on GCP (see src/init.rs), so local and cloud configs are loaded by
# the same code path.
#
# Env knobs:
#   EE_MEM       memory size (default from profile, TARGET_DEFAULT_MEM)
#   EE_SMP       vCPU count (default from profile, TARGET_DEFAULT_VCPU)
#   OVMF_CODE    firmware path (default /usr/share/OVMF/OVMF_CODE.fd)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROFILE="$SCRIPT_DIR/targets/local-tdx/profile.env"
OUTPUT_DIR="$SCRIPT_DIR/output/local-tdx"
ISO="$OUTPUT_DIR/easyenclave.iso"
ENV_FILE="${1:-}"

[ -f "$PROFILE" ] || { echo "Missing $PROFILE"; exit 1; }
[ -f "$ISO" ] || { echo "Missing $ISO — run 'make build TARGET=local-tdx' first"; exit 1; }

# shellcheck disable=SC1090
. "$PROFILE"

EE_MEM="${EE_MEM:-$TARGET_DEFAULT_MEM}"
EE_SMP="${EE_SMP:-$TARGET_DEFAULT_VCPU}"
OVMF_CODE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE.fd}"

# ── Prereqs ─────────────────────────────────────────────────────────
command -v qemu-system-x86_64 >/dev/null || {
    echo "qemu-system-x86_64 not found (apt install qemu-system-x86)"
    exit 1
}
[ -f "$OVMF_CODE" ] || {
    echo "OVMF firmware not found at $OVMF_CODE"
    echo "  apt install ovmf         # generic UEFI firmware"
    echo "  or set OVMF_CODE=/path/to/TDVF.fd for a TDX-enlightened build"
    exit 1
}

TDX_SUPPORT=$(cat /sys/module/kvm_intel/parameters/tdx 2>/dev/null || echo "N")
if [ "$TDX_SUPPORT" != "Y" ]; then
    echo "WARNING: kvm_intel.tdx=$TDX_SUPPORT — booting without TDX."
    echo "         Attestation will fail; everything else works."
    TDX_FLAGS="-machine q35,kernel-irqchip=split"
else
    TDX_FLAGS="-machine q35,kernel-irqchip=split,confidential-guest-support=tdx -object tdx-guest,id=tdx"
fi

# ── Config disk (optional) ───────────────────────────────────────────
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
echo "Profile: local-tdx"
echo "ISO:     $ISO"
echo "OVMF:    $OVMF_CODE"
echo "Memory:  $EE_MEM"
echo "vCPU:    $EE_SMP"
echo "TDX:     $TDX_SUPPORT"
echo ""
echo "Serial output below. Ctrl-A X to quit."
echo "════════════════════════════════════════════════════════════════"

# shellcheck disable=SC2086
exec qemu-system-x86_64 \
    -enable-kvm -cpu host -m "$EE_MEM" -smp "$EE_SMP" \
    $TDX_FLAGS \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -cdrom "$ISO" \
    $CONFIG_DRIVE \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
    -serial mon:stdio \
    -nographic
