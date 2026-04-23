#!/bin/bash
# Runs on tdx2 via SSH from ci-tdx-smoke-local-tdx-qcow2.sh. Boots the
# qcow2 under real TDX (kvm_intel.tdx=Y + OVMF.inteltdx.fd + tdx-guest
# object), mirrors dd's libvirt shape but driven by raw qemu. The ext4-
# label init template finds root on the attached virtio-blk disk.
#
# Args:
#   $1  path to easyenclave-*-local-tdx-qcow2.qcow2 on this host
#   $2  commit sha12 (for logging)
set -euo pipefail

QCOW2="${1:?}"
SHA12="${2:?}"

[ -f "$QCOW2" ] || { echo "tdx2-smoke: missing qcow2 $QCOW2" >&2; exit 2; }

for cmd in qemu-system-x86_64 genisoimage curl qemu-img; do
    command -v "$cmd" >/dev/null || { echo "tdx2-smoke: missing $cmd" >&2; exit 2; }
done

TDX_SUPPORT=$(cat /sys/module/kvm_intel/parameters/tdx 2>/dev/null || echo "N")
if [ "$TDX_SUPPORT" != "Y" ]; then
    echo "::error::tdx2-smoke: kvm_intel.tdx=$TDX_SUPPORT — TDX not enabled" >&2
    exit 2
fi

OVMF_CODE=""
for candidate in \
    /usr/local/share/ovmf/OVMF.inteltdx.fd \
    /usr/share/ovmf/OVMF.inteltdx.ms.fd \
    /usr/share/tdvf/TDVF.fd \
    /opt/intel-tdvf/TDVF.fd \
    /usr/share/OVMF/OVMF_CODE_4M.fd; do
    [ -f "$candidate" ] && OVMF_CODE="$candidate" && break
done
[ -n "$OVMF_CODE" ] || { echo "::error::tdx2-smoke: no TDVF/OVMF firmware found" >&2; exit 2; }

# Config disk: qemu vendor stage probes /dev/vdb, reads iso9660 /agent.env,
# merges into /run/easyenclave/env before PID 1 starts.
CONFIG_DIR=$(mktemp -d)
cat > "$CONFIG_DIR/agent.env" <<'EECONF'
EE_OWNER=ci-smoke-local-tdx-qcow2
EE_BOOT_WORKLOADS=[{"cmd":["sh","-c","echo ok > /tmp/index.html"],"app_name":"seed"},{"cmd":["busybox","httpd","-f","-p","80","-h","/tmp"],"app_name":"http"}]
EECONF
CONFIG_ISO=$(mktemp --suffix=.iso)
genisoimage -quiet -o "$CONFIG_ISO" -V CONFIG -r -J "$CONFIG_DIR/agent.env"

# COW overlay so the original qcow2 stays pristine (lets us rerun without
# re-scp'ing and matches dd's backing-file pattern). Separate-image keeps
# the TDX memory encryption the same; this is just disk CoW.
WORK_QCOW2=$(mktemp --suffix=.qcow2)
qemu-img create -q -f qcow2 -F qcow2 -b "$QCOW2" "$WORK_QCOW2" >/dev/null

SERIAL_LOG=$(mktemp --suffix=-ee-serial.log)
QEMU_PID_FILE=$(mktemp)
HOST_PORT=$((20000 + RANDOM % 40000))

cleanup() {
    set +e
    PID=$(cat "$QEMU_PID_FILE" 2>/dev/null || true)
    if [ -n "$PID" ]; then
        kill "$PID" 2>/dev/null && sleep 1
        kill -9 "$PID" 2>/dev/null
    fi
    rm -rf "$CONFIG_DIR" "$CONFIG_ISO" "$WORK_QCOW2" "$QEMU_PID_FILE"
    if [ "${SMOKE_FAILED:-0}" = "1" ]; then
        echo "tdx2-smoke: preserving $SERIAL_LOG for debug"
    else
        rm -f "$SERIAL_LOG"
    fi
}
trap cleanup EXIT

echo "tdx2-smoke: sha12=$SHA12 firmware=$OVMF_CODE hostfwd=localhost:${HOST_PORT}→vm:80"

MEM_BYTES=$((4 * 1024 * 1024 * 1024))
# TDX requires the memory-backend + -bios + -nodefaults combo; using
# -drive if=pflash fails on KVM 10.2 ("pflash with kvm requires KVM
# readonly memory support") and bare -machine q35 fails memory-convert
# during vCPU startup.
# With -nodefaults, QEMU doesn't auto-wire a virtio-blk-pci device for
# each `-drive if=virtio`. The FIRST drive happens to work (root ends up
# on /dev/vda) but the SECOND silently doesn't attach — the qemu vendor
# stage then reports "no config disk at /dev/vdb or /dev/sdb" and skips
# the config merge. Bind each drive to its own virtio-blk-pci explicitly.
qemu-system-x86_64 \
    -enable-kvm -cpu host -smp 2 \
    -m size=4194304k \
    -machine q35,usb=off,dump-guest-core=off,memory-backend=pc.ram,confidential-guest-support=lsec0,hpet=off,acpi=on \
    -object memory-backend-ram,id=pc.ram,size=${MEM_BYTES} \
    -object tdx-guest,id=lsec0 \
    -bios "$OVMF_CODE" \
    -drive "file=$WORK_QCOW2,if=none,id=rootdrv,format=qcow2" \
    -device virtio-blk-pci,drive=rootdrv \
    -drive "file=$CONFIG_ISO,if=none,id=cfgdrv,format=raw,readonly=on" \
    -device virtio-blk-pci,drive=cfgdrv \
    -netdev "user,id=n0,hostfwd=tcp::${HOST_PORT}-:80" \
    -device virtio-net-pci,netdev=n0 \
    -serial "file:$SERIAL_LOG" \
    -display none -no-reboot -no-user-config -nodefaults \
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
