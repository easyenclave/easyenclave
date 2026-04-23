#!/bin/bash
# CI smoke boot. Boots the built image under QEMU WITHOUT TDX hardware
# (GitHub-hosted runners don't have it) and asserts that the full shell
# pipeline makes it all the way to Rust's attestation-detect FATAL —
# which is the expected non-TDX outcome. Anything that breaks *earlier*
# (root mount, vendor stage, mount --move, switch_root) is a real
# regression.
#
# Usage:
#   bash image/ci-smoke-boot.sh <gcp|azure|local-tdx> [output-dir]
#
# Env knobs:
#   TIMEOUT_SECS   max seconds to wait for all assertions (default 180)
#   QEMU_BIN       qemu binary (default qemu-system-x86_64)
#   KEEP_LOG       set to 1 to preserve the serial log on success
#
# Exit codes:
#   0  — all assertions observed
#   1  — one or more assertions missing before timeout
#   2  — prerequisite missing (bad args, missing artifacts, no qemu)
set -u

TARGET="${1:-}"
[ -n "$TARGET" ] || { echo "usage: $0 <gcp|azure|local-tdx> [output-dir]"; exit 2; }

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
OUTPUT_DIR="${2:-$SCRIPT_DIR/output/$TARGET}"
TIMEOUT_SECS="${TIMEOUT_SECS:-180}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"

[ -d "$OUTPUT_DIR" ] || { echo "smoke: $OUTPUT_DIR not found — run 'make build TARGET=$TARGET' first" >&2; exit 2; }
command -v "$QEMU_BIN" >/dev/null || { echo "smoke: $QEMU_BIN not on PATH" >&2; exit 2; }

# Per-target QEMU args. All three targets ship vmlinuz + initrd +
# cmdline; we always direct-kernel-boot (skipping OVMF) because we're
# testing the initrd + vendor shell layer, not the firmware/UKI chain.
# ext4-label targets attach the raw rootfs via virtio-blk; squashfs-
# overlay targets attach the iso as a virtio CDROM.
case "$TARGET" in
    gcp|azure)
        VENDOR_NAME="$TARGET"
        DISK="$OUTPUT_DIR/easyenclave.root.raw"
        [ -f "$DISK" ] || { echo "smoke: missing $DISK" >&2; exit 2; }
        DRIVE_ARG="-drive file=$DISK,if=virtio,format=raw,snapshot=on"
        ;;
    local-tdx)
        # local-tdx ships the rootfs inside the ISO as squashfs; the
        # initrd template probes /dev/sr0 first, which is what -cdrom
        # attaches.
        VENDOR_NAME="qemu"
        ISO="$OUTPUT_DIR/easyenclave.iso"
        [ -f "$ISO" ] || { echo "smoke: missing $ISO" >&2; exit 2; }
        DRIVE_ARG="-cdrom $ISO"
        ;;
    *)
        echo "smoke: unknown target '$TARGET' (expected gcp|azure|local-tdx)" >&2
        exit 2
        ;;
esac

for f in easyenclave.vmlinuz easyenclave.initrd easyenclave.cmdline; do
    [ -f "$OUTPUT_DIR/$f" ] || { echo "smoke: missing $OUTPUT_DIR/$f" >&2; exit 2; }
done

CMDLINE=$(cat "$OUTPUT_DIR/easyenclave.cmdline")
LOG=$(mktemp --suffix=-easyenclave-smoke.log)
PID_FILE=$(mktemp)

cleanup() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE" 2>/dev/null || true)
        [ -n "$PID" ] && kill "$PID" 2>/dev/null && sleep 1
        [ -n "$PID" ] && kill -9 "$PID" 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
    if [ "${KEEP_LOG:-0}" = "1" ] || [ "${SMOKE_FAILED:-0}" = "1" ]; then
        echo "smoke: serial log preserved at $LOG" >&2
    else
        rm -f "$LOG"
    fi
}
trap cleanup EXIT

echo "smoke: TARGET=$TARGET vendor=$VENDOR_NAME output=$OUTPUT_DIR timeout=${TIMEOUT_SECS}s"
echo "smoke: serial log → $LOG"

# KVM requires /dev/kvm. Runners usually have it; fall back to TCG (very
# slow, but functional) if not. We don't need TDX — even KVM without it
# boots fine up to the attestation-detect FATAL.
KVM_ARG=""
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    KVM_ARG="-enable-kvm -cpu host"
else
    echo "smoke: /dev/kvm not accessible — falling back to TCG (slow)" >&2
    KVM_ARG="-cpu qemu64"
fi

# shellcheck disable=SC2086
"$QEMU_BIN" \
    $KVM_ARG -m 2G -smp 2 \
    -machine q35 \
    -kernel "$OUTPUT_DIR/easyenclave.vmlinuz" \
    -initrd "$OUTPUT_DIR/easyenclave.initrd" \
    -append "$CMDLINE" \
    $DRIVE_ARG \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
    -no-reboot \
    -nographic -display none \
    -serial "file:$LOG" \
    > /dev/null 2>&1 &
QEMU_PID=$!
echo "$QEMU_PID" > "$PID_FILE"

# Assertions: these three lines prove the shell + Rust pipeline is intact.
# Stored as parallel arrays since busybox-portable shells don't have
# associative arrays and this script runs under bash (the CI runner's shell).
NAMES=("pid1" "vendor_stage" "attestation_gate")
PATTERNS=("easyenclave: running as PID 1" "vendor:${VENDOR_NAME}:" "FATAL: no attestation backend")
PASSED=(0 0 0)

elapsed=0
all_pass=0
last_size=0
while [ "$elapsed" -lt "$TIMEOUT_SECS" ]; do
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "smoke: qemu exited early after ${elapsed}s"
        break
    fi

    # Stream new serial content as it arrives so CI logs show boot progress live.
    if [ -f "$LOG" ]; then
        size=$(wc -c < "$LOG" 2>/dev/null || echo 0)
        if [ "$size" -gt "$last_size" ]; then
            tail -c "+$((last_size + 1))" "$LOG" | sed 's/^/[serial] /'
            last_size=$size
        fi
    fi

    all_pass=1
    for i in 0 1 2; do
        if [ "${PASSED[$i]}" -eq 0 ]; then
            if grep -qF -- "${PATTERNS[$i]}" "$LOG" 2>/dev/null; then
                PASSED[$i]=1
                echo "smoke:   ✓ ${NAMES[$i]} (matched: ${PATTERNS[$i]})"
            else
                all_pass=0
            fi
        fi
    done
    [ "$all_pass" -eq 1 ] && break

    sleep 2
    elapsed=$((elapsed + 2))
done

# Flush whatever serial output is still pending.
if [ -f "$LOG" ]; then
    size=$(wc -c < "$LOG" 2>/dev/null || echo 0)
    if [ "$size" -gt "$last_size" ]; then
        tail -c "+$((last_size + 1))" "$LOG" | sed 's/^/[serial] /'
    fi
fi

echo ""
echo "smoke: === summary (target=$TARGET) ==="
total=0
pass=0
for i in 0 1 2; do
    total=$((total + 1))
    if [ "${PASSED[$i]}" -eq 1 ]; then
        echo "smoke:   ✓ ${NAMES[$i]}"
        pass=$((pass + 1))
    else
        echo "smoke:   ✗ ${NAMES[$i]} (pattern: ${PATTERNS[$i]})"
    fi
done
echo "smoke: $pass/$total assertions passed"

if [ "$all_pass" -eq 1 ]; then
    exit 0
fi

SMOKE_FAILED=1
echo ""
echo "smoke: last 80 lines of serial log:"
tail -n 80 "$LOG" | sed 's/^/[tail] /'
exit 1
