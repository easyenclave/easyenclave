#!/bin/bash
# Runs on tdx2 under SSH from the hosted runner (ci-tdx-smoke-local.sh).
# Boots the local-tdx ISO under QEMU with real TDX (kvm_intel.tdx=Y +
# TDVF firmware + tdx-guest object), asserts the enclave works, does an
# HTTP workload check through a slirp port-forward, and tears down.
#
# Args:
#   $1  path to the easyenclave ISO on this host
#   $2  commit sha12 (for logging)
#
# Required on tdx2: qemu-system-x86_64, genisoimage, TDVF or OVMF
# firmware (/usr/share/tdvf/TDVF.fd preferred), TDX-enabled kernel +
# host.
set -euo pipefail

ISO="${1:?}"
SHA12="${2:?}"

[ -f "$ISO" ] || { echo "tdx2-smoke: missing ISO $ISO" >&2; exit 2; }

for cmd in qemu-system-x86_64 genisoimage curl; do
    command -v "$cmd" >/dev/null || { echo "tdx2-smoke: missing $cmd" >&2; exit 2; }
done

TDX_SUPPORT=$(cat /sys/module/kvm_intel/parameters/tdx 2>/dev/null || echo "N")
if [ "$TDX_SUPPORT" != "Y" ]; then
    echo "::error::tdx2-smoke: kvm_intel.tdx=$TDX_SUPPORT — TDX not enabled on this host"
    exit 2
fi

# Prefer real TDVF if present; fall back to generic OVMF.
OVMF_CODE=""
for candidate in /usr/share/tdvf/TDVF.fd /opt/intel-tdvf/TDVF.fd /usr/share/OVMF/OVMF_CODE.fd; do
    [ -f "$candidate" ] && OVMF_CODE="$candidate" && break
done
[ -n "$OVMF_CODE" ] || { echo "::error::tdx2-smoke: no TDVF/OVMF firmware found" >&2; exit 2; }

# Config disk: the qemu vendor stage inside the VM probes /dev/vdb and
# mounts iso9660, reads /agent.env, merges into /run/easyenclave/env.
CONFIG_DIR=$(mktemp -d)
cat > "$CONFIG_DIR/agent.env" <<'EECONF'
EE_OWNER=ci-smoke-local
EE_BOOT_WORKLOADS=[{"cmd":["sh","-c","echo ok > /tmp/index.html"],"app_name":"seed"},{"cmd":["busybox","httpd","-f","-p","80","-h","/tmp"],"app_name":"http"}]
EECONF
CONFIG_ISO=$(mktemp --suffix=.iso)
genisoimage -quiet -o "$CONFIG_ISO" -V CONFIG -r -J "$CONFIG_DIR/agent.env"

SERIAL_LOG=$(mktemp --suffix=-ee-serial.log)
QEMU_PID_FILE=$(mktemp)

# Random host port for hostfwd so parallel runs on the same tdx2 box
# don't collide (the matrix won't do this today, but cheap insurance).
HOST_PORT=$((20000 + RANDOM % 40000))

cleanup() {
    set +e
    PID=$(cat "$QEMU_PID_FILE" 2>/dev/null || true)
    if [ -n "$PID" ]; then
        kill "$PID" 2>/dev/null && sleep 1
        kill -9 "$PID" 2>/dev/null
    fi
    rm -rf "$CONFIG_DIR" "$CONFIG_ISO" "$QEMU_PID_FILE"
    if [ "${SMOKE_FAILED:-0}" = "1" ]; then
        echo "tdx2-smoke: preserving $SERIAL_LOG for debug"
    else
        rm -f "$SERIAL_LOG"
    fi
}
trap cleanup EXIT

echo "tdx2-smoke: sha12=$SHA12 firmware=$OVMF_CODE hostfwd=localhost:${HOST_PORT}→vm:80"

qemu-system-x86_64 \
    -enable-kvm -cpu host -m 4G -smp 2 \
    -machine q35,kernel-irqchip=split,confidential-guest-support=tdx \
    -object tdx-guest,id=tdx \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -cdrom "$ISO" \
    -drive "file=$CONFIG_ISO,if=virtio,format=raw,media=cdrom,readonly=on" \
    -netdev "user,id=n0,hostfwd=tcp::${HOST_PORT}-:80" \
    -device virtio-net-pci,netdev=n0 \
    -serial "file:$SERIAL_LOG" \
    -nographic -display none -no-reboot \
    > /dev/null 2>&1 &
QEMU_PID=$!
echo "$QEMU_PID" > "$QEMU_PID_FILE"

CHECKS=(
    "pid1|easyenclave: running as PID 1"
    "vendor_merged|vendor:qemu: merged .* config into"
    "attestation_tdx|attestation backend: tdx"
    "listening|easyenclave: listening on"
    "deployment_running|deployment .* running"
)
FATAL_PATTERNS="FATAL|Kernel panic|switch_root: can|Invalid ELF header"

declare -A PASSED
LAST_SIZE=0
ALL_DONE=false
# 60 iterations × 2s = 120s cap. TDVF + squashfs + overlay typically in
# ~15-25s on this host; we leave headroom for slow workload spawns.
for i in $(seq 1 60); do
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "tdx2-smoke: qemu exited early after ${i}×2s"
        break
    fi
    if [ -f "$SERIAL_LOG" ]; then
        SIZE=$(wc -c < "$SERIAL_LOG" 2>/dev/null || echo 0)
        if [ "$SIZE" -gt "$LAST_SIZE" ]; then
            tail -c "+$((LAST_SIZE + 1))" "$SERIAL_LOG" | sed 's/^/[serial] /'
            LAST_SIZE=$SIZE
        fi
        if grep -qE "$FATAL_PATTERNS" "$SERIAL_LOG"; then
            echo "::error::tdx2-smoke: fatal pattern in serial"
            break
        fi
        for check in "${CHECKS[@]}"; do
            IFS="|" read -r name pattern <<< "$check"
            [ -n "${PASSED[$name]:-}" ] && continue
            if grep -qE "$pattern" "$SERIAL_LOG"; then
                PASSED[$name]=1
                echo "tdx2-smoke:   ✓ $name"
            fi
        done
        ALL_DONE=true
        for check in "${CHECKS[@]}"; do
            IFS="|" read -r name _pat <<< "$check"
            [ -z "${PASSED[$name]:-}" ] && ALL_DONE=false && break
        done
        $ALL_DONE && break
    fi
    sleep 2
done

HTTP_OK=false
if $ALL_DONE; then
    echo "tdx2-smoke: probing http://localhost:${HOST_PORT}/"
    for i in $(seq 1 12); do
        code=$(curl -sS -o /dev/null -w '%{http_code}' \
            --connect-timeout 5 "http://localhost:${HOST_PORT}/" 2>/dev/null || echo 000)
        if [ "$code" = "200" ]; then
            echo "tdx2-smoke:   ✓ workload_http (200)"
            HTTP_OK=true
            break
        fi
        echo "tdx2-smoke: http $code, retrying... ($i/12)"
        sleep 2
    done
fi

echo ""
echo "tdx2-smoke: === summary ==="
PASS=0; TOTAL=0
for check in "${CHECKS[@]}"; do
    IFS="|" read -r name _pat <<< "$check"
    TOTAL=$((TOTAL + 1))
    if [ -n "${PASSED[$name]:-}" ]; then
        echo "tdx2-smoke:   ✓ $name"; PASS=$((PASS + 1))
    else
        echo "tdx2-smoke:   ✗ $name"
    fi
done
TOTAL=$((TOTAL + 1))
if $HTTP_OK; then
    echo "tdx2-smoke:   ✓ workload_http"; PASS=$((PASS + 1))
else
    echo "tdx2-smoke:   ✗ workload_http"
fi
echo "tdx2-smoke: $PASS/$TOTAL passed"

if $ALL_DONE && $HTTP_OK; then
    exit 0
fi
SMOKE_FAILED=1
exit 1
