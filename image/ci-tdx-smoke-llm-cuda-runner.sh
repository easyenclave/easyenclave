#!/bin/bash
# Runs on tdx2 via SSH from ci-tdx-smoke-llm-cuda.sh. Boots the
# qcow2 under real TDX (kvm_intel.tdx=Y + OVMF.inteltdx.fd + tdx-guest
# object), and — if an NVIDIA H100 is bound to vfio-pci on the host —
# attaches it via vfio-pci passthrough so the rootfs's NVIDIA driver
# can load and vLLM can come up.
#
# Two paths, picked at runtime:
#  - GPU mode:    H100 on vfio-pci → 16 GB / 1 GB hugepages /
#                 vfio-pci device / boot_workloads spawns
#                 nvidia-bringup + vllm-serve (Qwen 0.5B public model).
#  - Boot-only:   no GPU on vfio-pci → 4 GB / no hugepages /
#                 boot_workloads spawns a minimal seed + httpd to
#                 prove easyenclave's spawn path works.
#
# CI calls this in boot-only mode by default (the GHA runner has no
# H100 — the GPU is on a self-hosted tdx2 box; the runner will see
# vfio-pci-bound H100s only on machines explicitly configured for it).
#
# Args:
#   $1  path to easyenclave-*-llm-cuda.qcow2 on this host
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

# Discover an NVIDIA GPU (3D controller, vendor 10de) currently bound
# to vfio-pci. lspci's first column is BDF without the 0000: domain
# prefix; vfio-pci's QEMU `host=` arg expects the full BDF including
# the domain. lspci uses domain-omitted matching so re-add 0000:
# below.
GPU_BDF=""
for short_bdf in $(lspci -nn 2>/dev/null | awk '/3D controller .*\[10de:/ { print $1 }'); do
    bdf="0000:${short_bdf}"
    drv=$(lspci -nnk -s "$short_bdf" 2>/dev/null | awk '/Kernel driver in use:/ { print $5 }')
    if [ "$drv" = "vfio-pci" ]; then
        GPU_BDF="$bdf"
        echo "tdx2-smoke: GPU detected: $bdf on vfio-pci"
        break
    fi
done
if [ -z "$GPU_BDF" ]; then
    echo "tdx2-smoke: no NVIDIA GPU bound to vfio-pci — boot-only smoke"
fi

# Config disk: qemu vendor stage probes /dev/vdb, reads iso9660 /agent.env,
# merges into /run/easyenclave/env before PID 1 starts. Workload payload
# differs by mode — GPU mode runs the real vLLM stack; boot-only runs a
# trivial seed+httpd so we can curl http://vm:80/ and confirm
# boot_workloads' spawn path is intact.
CONFIG_DIR=$(mktemp -d)
if [ -n "$GPU_BDF" ]; then
    # Public Qwen 0.5B — Llama is gated and would need an HF_TOKEN.
    # nvidia modules are modprobe'd before persistenced opens /dev/nvidia*;
    # vllm-serve sleeps briefly so torch.cuda sees a settled driver state.
    cat > "$CONFIG_DIR/agent.env" <<'EECONF'
EE_OWNER=ci-smoke-llm-cuda-gpu
EE_BOOT_WORKLOADS=[{"app_name":"nvidia-bringup","cmd":["sh","-c","/sbin/modprobe nvidia && /sbin/modprobe nvidia_uvm && /sbin/modprobe nvidia_modeset && exec /usr/bin/nvidia-persistenced --no-persistence-mode --verbose"]},{"app_name":"vllm-serve","cmd":["sh","-c","sleep 5 && exec /usr/local/bin/vllm-serve"],"env":["VLLM_MODEL=Qwen/Qwen2.5-0.5B-Instruct","VLLM_HOST=0.0.0.0","VLLM_PORT=8000","VLLM_MAX_MODEL_LEN=2048","VLLM_GPU_MEMORY=0.30"]}]
EECONF
    HOST_GUEST_PORT=8000
else
    cat > "$CONFIG_DIR/agent.env" <<'EECONF'
EE_OWNER=ci-smoke-llm-cuda-boot-only
EE_BOOT_WORKLOADS=[{"cmd":["sh","-c","echo ok > /tmp/index.html"],"app_name":"seed"},{"cmd":["busybox","httpd","-f","-p","80","-h","/tmp"],"app_name":"http"}]
EECONF
    HOST_GUEST_PORT=80
fi
CONFIG_ISO=$(mktemp --suffix=.iso)
genisoimage -quiet -o "$CONFIG_ISO" -V CONFIG -r -J "$CONFIG_DIR/agent.env"

# COW overlay so the original qcow2 stays pristine. Same backing-file
# pattern dd uses in production libvirt.
WORK_QCOW2=$(mktemp --suffix=.qcow2)
qemu-img create -q -f qcow2 -F qcow2 -b "$QCOW2" "$WORK_QCOW2" >/dev/null

SERIAL_LOG=$(mktemp --suffix=-ee-serial.log)
QEMU_PID_FILE=$(mktemp)
HOST_PORT=$((20000 + RANDOM % 40000))
HUGEPAGES_ALLOCATED=0

cleanup() {
    set +e
    PID=$(cat "$QEMU_PID_FILE" 2>/dev/null || true)
    if [ -n "$PID" ]; then
        kill "$PID" 2>/dev/null && sleep 1
        kill -9 "$PID" 2>/dev/null
    fi
    if [ "$HUGEPAGES_ALLOCATED" -gt 0 ]; then
        # Best-effort: if some other VM has reserved them we can't
        # release, that's fine — the next run will reallocate.
        echo 0 | sudo tee /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages >/dev/null 2>&1 || true
    fi
    rm -rf "$CONFIG_DIR" "$CONFIG_ISO" "$WORK_QCOW2" "$QEMU_PID_FILE"
    if [ "${SMOKE_FAILED:-0}" = "1" ]; then
        echo "tdx2-smoke: preserving $SERIAL_LOG for debug"
    else
        rm -f "$SERIAL_LOG"
    fi
}
trap cleanup EXIT

echo "tdx2-smoke: sha12=$SHA12 firmware=$OVMF_CODE hostfwd=localhost:${HOST_PORT}→vm:${HOST_GUEST_PORT}"

if [ -n "$GPU_BDF" ]; then
    # TDX + VFIO with >32 GB guest RAM blows past the kernel's 16M
    # IOMMU DMA mapping cap (each 4 KB page = one mapping). 1 GB
    # hugepages collapse this to ~16 mappings for a 16 GB guest, so
    # vfio_ram_discard_register_listener stays under the limit. Allocate
    # 16 × 1 GB; release in cleanup. sudo because the sysfs entry is
    # root-only on this host. NB: 1 GB hugepages need contiguous
    # physical memory — under heavy fragmentation the allocation can
    # come up short, in which case we abort early rather than fall
    # back to a config that we know will hit the DMA limit.
    NEED_HP=16
    if ! echo "$NEED_HP" | sudo tee /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages >/dev/null; then
        echo "::error::tdx2-smoke: failed to set 1G hugepages count" >&2
        exit 2
    fi
    GOT_HP=$(cat /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages 2>/dev/null || echo 0)
    if [ "$GOT_HP" -lt "$NEED_HP" ]; then
        echo "::error::tdx2-smoke: only got $GOT_HP / $NEED_HP × 1G hugepages — host fragmented" >&2
        exit 2
    fi
    HUGEPAGES_ALLOCATED=$NEED_HP
    MEM_BYTES=$((16 * 1024 * 1024 * 1024))
    SMP=16
    EXTRA_QEMU_ARGS=(
        -object "memory-backend-memfd,id=pc.ram,size=${MEM_BYTES},hugetlb=on,hugetlbsize=1G,share=on"
        -device "vfio-pci,host=${GPU_BDF}"
    )
else
    # Boot-only path uses plain pages — no VFIO, no DMA-mapping pressure.
    MEM_BYTES=$((4 * 1024 * 1024 * 1024))
    SMP=2
    EXTRA_QEMU_ARGS=(
        -object "memory-backend-ram,id=pc.ram,size=${MEM_BYTES}"
    )
fi

# TDX requires the memory-backend + -bios + -nodefaults combo. With
# -nodefaults, QEMU doesn't auto-wire virtio-blk-pci for `-drive
# if=virtio` — bind each drive to its own virtio-blk-pci explicitly.
qemu-system-x86_64 \
    -enable-kvm -cpu host -smp "$SMP" \
    -m size="$((MEM_BYTES / 1024))k" \
    -machine q35,usb=off,dump-guest-core=off,memory-backend=pc.ram,confidential-guest-support=lsec0,hpet=off,acpi=on \
    "${EXTRA_QEMU_ARGS[@]}" \
    -object tdx-guest,id=lsec0 \
    -bios "$OVMF_CODE" \
    -drive "file=$WORK_QCOW2,if=none,id=rootdrv,format=qcow2" \
    -device virtio-blk-pci,drive=rootdrv \
    -drive "file=$CONFIG_ISO,if=none,id=cfgdrv,format=raw,readonly=on" \
    -device virtio-blk-pci,drive=cfgdrv \
    -netdev "user,id=n0,hostfwd=tcp::${HOST_PORT}-:${HOST_GUEST_PORT}" \
    -device virtio-net-pci,netdev=n0 \
    -serial "file:$SERIAL_LOG" \
    -display none -no-reboot -no-user-config -nodefaults \
    > /dev/null 2>&1 &
QEMU_PID=$!
echo "$QEMU_PID" > "$QEMU_PID_FILE"

# Boot-path checks every smoke needs to pass, GPU or not.
CHECKS=(
    "pid1|easyenclave: running as PID 1"
    "vendor_merged|vendor:qemu: merged .* config into"
    "attestation_tdx|attestation backend: tdx"
    "listening|easyenclave: listening on"
    "deployment_running|deployment .* running"
)
# Additional checks layered on when an H100 is attached.
if [ -n "$GPU_BDF" ]; then
    CHECKS+=(
        "nvidia_loaded|nvidia: loading out-of-tree module"
        "vllm_started|Application startup complete"
    )
fi
FATAL_PATTERNS="FATAL|Kernel panic|switch_root: can|Invalid ELF header|Hardware Error"

# vLLM model load takes 30s–2 min depending on cache; boot-only finishes
# in under 30s. Budget 5 min in GPU mode, 1 min otherwise.
DEADLINE_SECS=60
if [ -n "$GPU_BDF" ]; then DEADLINE_SECS=300; fi

declare -A PASSED
LAST_SIZE=0
ALL_DONE=false
DEADLINE=$((SECONDS + DEADLINE_SECS))
while [ "$SECONDS" -lt "$DEADLINE" ]; do
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "tdx2-smoke: qemu exited early"
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

# HTTP probe: confirms the workload is actually serving on the
# port we hostfwd'd to. /v1/models for vLLM, / for busybox httpd.
HTTP_OK=false
HTTP_NAME="workload_http"
if $ALL_DONE; then
    if [ -n "$GPU_BDF" ]; then
        HTTP_NAME="vllm_api"
        URL="http://localhost:${HOST_PORT}/v1/models"
        echo "tdx2-smoke: probing $URL"
        for i in $(seq 1 20); do
            body=$(curl -sS --connect-timeout 5 "$URL" 2>/dev/null || true)
            if echo "$body" | grep -q '"data"'; then
                echo "tdx2-smoke:   ✓ $HTTP_NAME"
                echo "tdx2-smoke:   $body"
                HTTP_OK=true
                break
            fi
            echo "tdx2-smoke: $URL not ready, retrying... ($i/20)"
            sleep 3
        done
    else
        URL="http://localhost:${HOST_PORT}/"
        echo "tdx2-smoke: probing $URL"
        for i in $(seq 1 12); do
            code=$(curl -sS -o /dev/null -w '%{http_code}' \
                --connect-timeout 5 "$URL" 2>/dev/null || echo 000)
            if [ "$code" = "200" ]; then
                echo "tdx2-smoke:   ✓ $HTTP_NAME (200)"
                HTTP_OK=true
                break
            fi
            echo "tdx2-smoke: http $code, retrying... ($i/12)"
            sleep 2
        done
    fi
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
    echo "tdx2-smoke:   ✓ $HTTP_NAME"; PASS=$((PASS + 1))
else
    echo "tdx2-smoke:   ✗ $HTTP_NAME"
fi
echo "tdx2-smoke: $PASS/$TOTAL passed"

if $ALL_DONE && $HTTP_OK; then
    exit 0
fi
SMOKE_FAILED=1
exit 1
