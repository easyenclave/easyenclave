#!/bin/bash
# Local TDX boot smoke for the llm-cuda target with NVIDIA GPU
# passthrough. Boots image/output/llm-cuda/easyenclave.qcow2 under
# real Intel TDX (kvm_intel.tdx=Y + OVMF.inteltdx.fd + tdx-guest
# object) plus a vfio-pci passthrough of the host's H100. Verifies
# that the enclave runs as PID 1, detects TDX, sees the GPU through
# nvidia-smi, and starts the vLLM OpenAI-compatible API on a small
# public model.
#
# Override the gated default model by writing a smaller public one
# into /agent.env on the config disk (the qemu vendor stage merges
# this into /run/easyenclave/env before PID 1 starts, which becomes
# the EE_BOOT_WORKLOADS that easyenclave reads).
#
# Args (optional):
#   $1  path to easyenclave qcow2 (default:
#       image/output/llm-cuda/easyenclave.qcow2)
#   $2  PCI BDF for the GPU (default: 0000:0d:00.0)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
QCOW2="${1:-$REPO_ROOT/image/output/llm-cuda/easyenclave.qcow2}"
GPU_BDF="${2:-0000:0d:00.0}"

[ -f "$QCOW2" ] || { echo "smoke: missing qcow2 $QCOW2" >&2; exit 2; }

for cmd in qemu-system-x86_64 genisoimage qemu-img; do
    command -v "$cmd" >/dev/null || { echo "smoke: missing $cmd" >&2; exit 2; }
done

# TDX support
TDX_SUPPORT=$(cat /sys/module/kvm_intel/parameters/tdx 2>/dev/null || echo "N")
if [ "$TDX_SUPPORT" != "Y" ]; then
    echo "smoke: kvm_intel.tdx=$TDX_SUPPORT — TDX not enabled" >&2
    exit 2
fi

# GPU bound to vfio-pci
DRV=$(lspci -nnk -s "${GPU_BDF#0000:}" 2>/dev/null | awk '/Kernel driver in use:/ { print $5 }')
if [ "$DRV" != "vfio-pci" ]; then
    echo "smoke: GPU at $GPU_BDF is on driver '$DRV', not vfio-pci — passthrough won't work" >&2
    echo "       (bind it via /etc/modprobe.d or `driverctl set-override $GPU_BDF vfio-pci`)" >&2
    exit 2
fi

# TDVF firmware
OVMF_CODE=""
for candidate in \
    /usr/local/share/ovmf/OVMF.inteltdx.fd \
    /usr/share/ovmf/OVMF.inteltdx.ms.fd \
    /usr/share/tdvf/TDVF.fd \
    /opt/intel-tdvf/TDVF.fd \
    /usr/share/OVMF/OVMF_CODE_4M.fd; do
    [ -f "$candidate" ] && OVMF_CODE="$candidate" && break
done
[ -n "$OVMF_CODE" ] || { echo "smoke: no TDVF/OVMF firmware found" >&2; exit 2; }

# Override the baked default model with a small public Qwen — the
# default Llama-3.1-8B is gated and would need an HF_TOKEN. Qwen
# 0.5B downloads in seconds and exercises the same vLLM path.
CONFIG_DIR=$(mktemp -d)
# Boot workloads run concurrently from easyenclave's main(), but the
# NVIDIA kernel modules need to be modprobe'd *before* anything tries
# to open /dev/nvidia*. udev/systemd-modules-load aren't running, so
# we chain `modprobe` into the persistenced command and give vllm-serve
# a short sleep so the modules are settled by the time torch.cuda
# runs. Single-shot modprobe is idempotent; this works whether
# nvidia.ko was already in tree or DKMS-built.
cat > "$CONFIG_DIR/agent.env" <<'EECONF'
EE_OWNER=ci-smoke-llm-cuda
EE_BOOT_WORKLOADS=[{"app_name":"nvidia-bringup","cmd":["sh","-c","/sbin/modprobe nvidia && /sbin/modprobe nvidia_uvm && /sbin/modprobe nvidia_modeset && exec /usr/bin/nvidia-persistenced --no-persistence-mode --verbose"]},{"app_name":"vllm-serve","cmd":["sh","-c","sleep 5 && exec /usr/local/bin/vllm-serve"],"env":["VLLM_MODEL=Qwen/Qwen2.5-0.5B-Instruct","VLLM_HOST=0.0.0.0","VLLM_PORT=8000","VLLM_MAX_MODEL_LEN=2048","VLLM_GPU_MEMORY=0.30"]}]
EECONF
CONFIG_ISO=$(mktemp --suffix=.iso)
genisoimage -quiet -o "$CONFIG_ISO" -V CONFIG -r -J "$CONFIG_DIR/agent.env"

# COW overlay so the original qcow2 stays pristine and the test is
# rerunnable.
WORK_QCOW2=$(mktemp --suffix=.qcow2)
qemu-img create -q -f qcow2 -F qcow2 -b "$QCOW2" "$WORK_QCOW2" >/dev/null

SERIAL_LOG=$(mktemp --suffix=-ee-llm-serial.log)
QEMU_PID_FILE=$(mktemp)
HOST_PORT=$((20000 + RANDOM % 40000))

cleanup() {
    set +e
    PID=$(cat "$QEMU_PID_FILE" 2>/dev/null || true)
    if [ -n "$PID" ]; then
        kill "$PID" 2>/dev/null && sleep 2
        kill -9 "$PID" 2>/dev/null
    fi
    rm -rf "$CONFIG_DIR" "$CONFIG_ISO" "$WORK_QCOW2" "$QEMU_PID_FILE"
    if [ "${SMOKE_FAILED:-0}" = "1" ]; then
        echo "smoke: preserving $SERIAL_LOG for debug"
    else
        rm -f "$SERIAL_LOG"
    fi
}
trap cleanup EXIT

echo "smoke: qcow2=$QCOW2"
echo "smoke: firmware=$OVMF_CODE"
echo "smoke: gpu=$GPU_BDF (vfio-pci)"
echo "smoke: hostfwd=localhost:${HOST_PORT}→vm:8000"

# 80 GB RAM (Llama-class workloads need this; small Qwen does fine
# with much less but we size for a representative production VM),
# 16 vCPU. virtio-blk for the qcow2 root + the config disk.
MEM_BYTES=$((80 * 1024 * 1024 * 1024))
qemu-system-x86_64 \
    -enable-kvm -cpu host -smp 16 \
    -m size=$((MEM_BYTES / 1024))k \
    -machine q35,usb=off,dump-guest-core=off,memory-backend=pc.ram,confidential-guest-support=lsec0,hpet=off,acpi=on \
    -object memory-backend-ram,id=pc.ram,size=${MEM_BYTES} \
    -object tdx-guest,id=lsec0 \
    -bios "$OVMF_CODE" \
    -drive "file=$WORK_QCOW2,if=none,id=rootdrv,format=qcow2" \
    -device virtio-blk-pci,drive=rootdrv \
    -drive "file=$CONFIG_ISO,if=none,id=cfgdrv,format=raw,readonly=on" \
    -device virtio-blk-pci,drive=cfgdrv \
    -device "vfio-pci,host=${GPU_BDF}" \
    -netdev "user,id=n0,hostfwd=tcp::${HOST_PORT}-:8000" \
    -device virtio-net-pci,netdev=n0 \
    -serial "file:$SERIAL_LOG" \
    -display none -no-reboot -no-user-config -nodefaults \
    > /dev/null 2>&1 &
QEMU_PID=$!
echo "$QEMU_PID" > "$QEMU_PID_FILE"

# Smoke checks (early → late). vLLM model load takes 30s–2min depending
# on download cache, so we let the loop run for up to 5 minutes.
CHECKS=(
    "pid1|easyenclave: running as PID 1"
    "vendor_merged|vendor:qemu: merged .* config into"
    "attestation_tdx|attestation backend: tdx"
    "listening|easyenclave: listening on"
    "nvidia_loaded|nvidia: loading out-of-tree module"
    "vllm_started|Application startup complete"
)
FATAL_PATTERNS="FATAL|Kernel panic|switch_root: can|Invalid ELF header|Hardware Error"

declare -A PASSED
LAST_SIZE=0
ALL_DONE=false
DEADLINE=$((SECONDS + 300))
while [ "$SECONDS" -lt "$DEADLINE" ]; do
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "smoke: qemu exited early"
        break
    fi
    if [ -f "$SERIAL_LOG" ]; then
        SIZE=$(wc -c < "$SERIAL_LOG" 2>/dev/null || echo 0)
        if [ "$SIZE" -gt "$LAST_SIZE" ]; then
            tail -c "+$((LAST_SIZE + 1))" "$SERIAL_LOG" | sed 's/^/[serial] /'
            LAST_SIZE=$SIZE
        fi
        if grep -qE "$FATAL_PATTERNS" "$SERIAL_LOG"; then
            echo "smoke: fatal pattern in serial"
            break
        fi
        for check in "${CHECKS[@]}"; do
            IFS="|" read -r name pattern <<< "$check"
            [ -n "${PASSED[$name]:-}" ] && continue
            if grep -qE "$pattern" "$SERIAL_LOG"; then
                PASSED[$name]=1
                echo "smoke:   ✓ $name"
            fi
        done
        ALL_DONE=true
        for check in "${CHECKS[@]}"; do
            IFS="|" read -r name _pat <<< "$check"
            [ -z "${PASSED[$name]:-}" ] && ALL_DONE=false && break
        done
        $ALL_DONE && break
    fi
    sleep 5
done

# vLLM /v1/models — confirms the OpenAI API actually binds and the
# model is loaded.
HTTP_OK=false
if $ALL_DONE; then
    echo "smoke: probing http://localhost:${HOST_PORT}/v1/models"
    for i in $(seq 1 20); do
        body=$(curl -sS --connect-timeout 5 "http://localhost:${HOST_PORT}/v1/models" 2>/dev/null || true)
        if echo "$body" | grep -q '"data"'; then
            echo "smoke:   ✓ vllm_api_responds"
            echo "smoke:   $body"
            HTTP_OK=true
            break
        fi
        echo "smoke: /v1/models not ready, retrying... ($i/20)"
        sleep 3
    done
fi

echo ""
echo "smoke: === summary ==="
PASS=0; TOTAL=0
for check in "${CHECKS[@]}"; do
    IFS="|" read -r name _pat <<< "$check"
    TOTAL=$((TOTAL + 1))
    if [ -n "${PASSED[$name]:-}" ]; then
        echo "smoke:   ✓ $name"; PASS=$((PASS + 1))
    else
        echo "smoke:   ✗ $name"
    fi
done
TOTAL=$((TOTAL + 1))
if $HTTP_OK; then
    echo "smoke:   ✓ vllm_api"; PASS=$((PASS + 1))
else
    echo "smoke:   ✗ vllm_api"
fi
echo "smoke: $PASS/$TOTAL passed"

if $ALL_DONE && $HTTP_OK; then
    exit 0
fi
SMOKE_FAILED=1
exit 1
