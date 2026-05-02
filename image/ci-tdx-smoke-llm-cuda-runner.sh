#!/bin/bash
# Runs on tdx2 via SSH from ci-tdx-smoke-llm-cuda.sh. Boots the
# qcow2 under real TDX (kvm_intel.tdx=Y + OVMF.inteltdx.fd + tdx-guest
# object) via libvirt, mirroring dd-local-prod's invocation. If an
# NVIDIA H100 is bound to vfio-pci on the host, the smoke domain
# inherits a <hostdev> for it so the rootfs's NVIDIA driver can
# attach.
#
# Why libvirt and not hand-rolled qemu: dd's libvirt-rendered qemu
# cmdline carries a long tail of TDX-specific quirks (sandbox flags,
# ICH9 globals, the -S/cont start-paused dance, USB controllers, TPM
# emulator, virtio-balloon, mem-lock=off, the right machine type
# string). Reproducing all of that in a hand-rolled qemu invocation is
# whack-a-mole; the previous version of this runner stalled TDVF
# before kernel handoff because of subtle missing pieces. Cribbing
# from the existing `easyenclave-local` base domain (which boots
# clean every day on this host) gets us to green in one step.
#
# Two paths, picked at runtime:
#  - GPU mode:    H100 on vfio-pci → 32 GiB / 16 vCPU /
#                 hostdev attached to a pcie-root-port /
#                 boot_workloads spawn nvidia-bringup + vllm-serve
#                 (Qwen 0.5B public model, no HF token needed).
#  - Boot-only:   no GPU on vfio-pci → 4 GiB / 2 vCPU / no hostdev /
#                 boot_workloads spawn a minimal seed + httpd.
#
# Args:
#   $1  path to easyenclave-*-llm-cuda.qcow2 on this host
#   $2  commit sha12 (used to scope all derived names)
set -euo pipefail

QCOW2="${1:?}"
SHA12="${2:?}"

[ -f "$QCOW2" ] || { echo "tdx2-smoke: missing qcow2 $QCOW2" >&2; exit 2; }

for cmd in virsh genisoimage qemu-img curl; do
    command -v "$cmd" >/dev/null || { echo "tdx2-smoke: missing $cmd" >&2; exit 2; }
done

TDX_SUPPORT=$(cat /sys/module/kvm_intel/parameters/tdx 2>/dev/null || echo "N")
if [ "$TDX_SUPPORT" != "Y" ]; then
    echo "::error::tdx2-smoke: kvm_intel.tdx=$TDX_SUPPORT — TDX not enabled" >&2
    exit 2
fi

BASE_DOMAIN="easyenclave-local"
if ! sudo virsh dominfo "$BASE_DOMAIN" >/dev/null 2>&1; then
    echo "::error::tdx2-smoke: base domain '$BASE_DOMAIN' not defined on this host" >&2
    exit 2
fi

# Discover an NVIDIA GPU (3D controller, vendor 10de) currently bound
# to vfio-pci. lspci's first column is BDF without the 0000: domain
# prefix; libvirt's <hostdev> source address takes the un-prefixed
# bus/slot/function fields.
GPU_BDF=""
for short_bdf in $(lspci -nn 2>/dev/null | awk '/3D controller .*\[10de:/ { print $1 }'); do
    drv=$(lspci -nnk -s "$short_bdf" 2>/dev/null | awk '/Kernel driver in use:/ { print $5 }')
    if [ "$drv" = "vfio-pci" ]; then
        GPU_BDF="$short_bdf"
        echo "tdx2-smoke: GPU detected: 0000:$GPU_BDF on vfio-pci"
        break
    fi
done
if [ -z "$GPU_BDF" ]; then
    echo "tdx2-smoke: no NVIDIA GPU bound to vfio-pci — boot-only smoke"
fi

# All staged artifacts live under /var/lib/libvirt/images/ so libvirt's
# AppArmor profile permits qemu to open them. Names scope by SHA12 so
# concurrent runs on different commits don't collide.
IMG_DIR=/var/lib/libvirt/images
VM="ee-smoke-$SHA12"
STAGED_QCOW2="$IMG_DIR/$VM.qcow2"
CONFIG_ISO="$IMG_DIR/$VM-config.iso"
SERIAL_LOG="/var/log/$VM.log"

# Boot workload payloads: GPU mode runs the real vLLM stack; boot-only
# runs a trivial seed+httpd so we can curl http://vm:80/ and confirm
# boot_workloads' spawn path is intact. Either path validates the
# easyenclave PID 1 + attestation + socket path.
CONFIG_DIR=$(mktemp -d)
if [ -n "$GPU_BDF" ]; then
    # Three-stage GPU bringup with sleep-based sequencing:
    #   1. nvidia-bringup: modprobe nvidia + persistenced (immediate)
    #   2. cc-bringup:     ppcie.verifier.verification --gpu-attestation-mode=LOCAL
    #                      (sleep 5 — wait for nvidia-persistenced to settle).
    #                      This is the H100 CC-mode handshake; without it the
    #                      GPU's GSP firmware rejects every memory-transfer
    #                      control with NV_ERR_INVALID_DATA and the driver
    #                      can't init the device. Mirrors confer-image's
    #                      nvidia-cc-attestation.service.
    #   3. vllm-serve:     sleep 30 — give cc-bringup time to complete
    #                      before torch.cuda probes the GPU.
    cat > "$CONFIG_DIR/agent.env" <<'EECONF'
EE_OWNER=ci-smoke-llm-cuda-gpu
EE_BOOT_WORKLOADS=[{"app_name":"nvidia-bringup","cmd":["sh","-c","/sbin/modprobe nvidia && /sbin/modprobe nvidia_uvm && /sbin/modprobe nvidia_modeset && exec /usr/bin/nvidia-persistenced --no-persistence-mode --verbose"]},{"app_name":"cc-bringup","cmd":["sh","-c","sleep 5 && cd /tmp && /opt/venv-attestation/bin/python -m ppcie.verifier.verification --gpu-attestation-mode=LOCAL --switch-attestation-mode=LOCAL && exec sleep infinity"]},{"app_name":"vllm-serve","cmd":["sh","-c","sleep 30 && exec /usr/local/bin/vllm-serve"],"env":["VLLM_MODEL=Qwen/Qwen2.5-0.5B-Instruct","VLLM_HOST=0.0.0.0","VLLM_PORT=8000","VLLM_MAX_MODEL_LEN=2048","VLLM_GPU_MEMORY=0.30"]}]
EECONF
else
    cat > "$CONFIG_DIR/agent.env" <<'EECONF'
EE_OWNER=ci-smoke-llm-cuda-boot-only
EE_BOOT_WORKLOADS=[{"cmd":["sh","-c","echo ok > /tmp/index.html"],"app_name":"seed"},{"cmd":["busybox","httpd","-f","-p","80","-h","/tmp"],"app_name":"http"}]
EECONF
fi

cleanup() {
    set +e
    sudo virsh destroy "$VM" 2>/dev/null
    sudo virsh undefine "$VM" --managed-save --snapshots-metadata 2>/dev/null
    sudo rm -f "$STAGED_QCOW2" "$CONFIG_ISO"
    rm -rf "$CONFIG_DIR"
    if [ "${SMOKE_FAILED:-0}" = "1" ]; then
        echo "tdx2-smoke: preserving $SERIAL_LOG for debug"
    else
        sudo rm -f "$SERIAL_LOG" 2>/dev/null
    fi
}
trap cleanup EXIT

echo "tdx2-smoke: sha12=$SHA12 vm=$VM"

# Stage the qcow2 as a backing-file overlay so the original stays
# pristine and reruns are cheap. Same backing-file pattern dd uses
# for its overlays.
sudo qemu-img create -q -f qcow2 -F qcow2 -b "$QCOW2" "$STAGED_QCOW2" >/dev/null
sudo chown libvirt-qemu:kvm "$STAGED_QCOW2"

# Build the iso9660 config disk the qemu vendor stage probes at /dev/vdb.
genisoimage -quiet -o "$CONFIG_ISO" -V CONFIG -r -J "$CONFIG_DIR/agent.env"
sudo chown libvirt-qemu:kvm "$CONFIG_ISO"

# Render domain XML by forking from the base TDX domain (which already
# has the QGS socket wired, OVMF.inteltdx.fd, pcie-root-port topology,
# and tdx-guest object). We only need to: rename, drop UUID/MAC for
# libvirt to regen, repoint disks, resize memory/vcpu, set a unique
# serial log, and (in GPU mode) inject <hostdev> for the H100.
DOMAIN_XML=$(mktemp)
sudo virsh dumpxml "$BASE_DOMAIN" > "$DOMAIN_XML"
sed -i "s|<name>$BASE_DOMAIN</name>|<name>$VM</name>|" "$DOMAIN_XML"
sed -i '/<uuid>/d' "$DOMAIN_XML"
sed -i '/<mac address=/d' "$DOMAIN_XML"
# Repoint disks: base has rootfs + config-iso paths matching its own
# names; rewrite both to our staged copies.
sed -i "s|$IMG_DIR/$BASE_DOMAIN\\.qcow2|$STAGED_QCOW2|g" "$DOMAIN_XML"
sed -i "s|$IMG_DIR/$BASE_DOMAIN-config\\.iso|$CONFIG_ISO|g" "$DOMAIN_XML"
# Unique serial log so concurrent runs / dd-local-* VMs don't collide
# on the file.
sed -i "s|/var/log/ee-local\\.log|$SERIAL_LOG|g" "$DOMAIN_XML"

if [ -n "$GPU_BDF" ]; then
    MEM_KIB=$((32 * 1024 * 1024))    # 32 GiB
    VCPUS=16
    # libvirt managed='yes' handles vfio bind/unbind around domain
    # start/destroy. PCIe addr 0e:00.0 lands the device on its own
    # virtual PCI bus inside the guest.
    # Parse BDF "bb:ss.f" into separate hex fields for libvirt's schema.
    GPU_BUS=${GPU_BDF%%:*}                      # 0d
    GPU_REST=${GPU_BDF#*:}                      # 00.0
    GPU_SLOT=${GPU_REST%%.*}                    # 00
    GPU_FN=${GPU_REST##*.}                      # 0
    HOSTDEV="    <hostdev mode='subsystem' type='pci' managed='yes'>
      <source>
        <address domain='0x0000' bus='0x${GPU_BUS}' slot='0x${GPU_SLOT}' function='0x${GPU_FN}'/>
      </source>
      <address type='pci' domain='0x0000' bus='0x0e' slot='0x00' function='0x0'/>
    </hostdev>
"
    python3 - "$DOMAIN_XML" "$HOSTDEV" <<'PY'
import sys
xml_path, hostdev = sys.argv[1], sys.argv[2]
with open(xml_path) as f: x = f.read()
x = x.replace('  </devices>', hostdev + '  </devices>')
with open(xml_path, 'w') as f: f.write(x)
PY
else
    MEM_KIB=$((4 * 1024 * 1024))     # 4 GiB
    VCPUS=2
fi
sed -i -E "s|<memory unit='KiB'>[0-9]+</memory>|<memory unit='KiB'>$MEM_KIB</memory>|" "$DOMAIN_XML"
sed -i -E "s|<currentMemory unit='KiB'>[0-9]+</currentMemory>|<currentMemory unit='KiB'>$MEM_KIB</currentMemory>|" "$DOMAIN_XML"
sed -i -E "s|<vcpu placement='static'>[0-9]+</vcpu>|<vcpu placement='static'>$VCPUS</vcpu>|" "$DOMAIN_XML"

# Define + start.
sudo virsh destroy "$VM" 2>/dev/null || true
sudo virsh undefine "$VM" --managed-save --snapshots-metadata 2>/dev/null || true
sudo virsh define "$DOMAIN_XML" >/dev/null
rm -f "$DOMAIN_XML"
sudo virsh start "$VM" >/dev/null
echo "tdx2-smoke: $VM started"

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

# vLLM model load takes 30s–2 min depending on cache; boot-only
# finishes in under 30s. Budget 5 min in GPU mode, 1 min otherwise.
DEADLINE_SECS=60
if [ -n "$GPU_BDF" ]; then DEADLINE_SECS=300; fi

declare -A PASSED
LAST_SIZE=0
ALL_DONE=false
DEADLINE=$((SECONDS + DEADLINE_SECS))
while [ "$SECONDS" -lt "$DEADLINE" ]; do
    if ! sudo virsh list --name 2>/dev/null | grep -q "^${VM}$"; then
        echo "tdx2-smoke: domain exited early"
        break
    fi
    if sudo test -f "$SERIAL_LOG"; then
        SIZE=$(sudo stat -c %s "$SERIAL_LOG" 2>/dev/null || echo 0)
        if [ "$SIZE" -gt "$LAST_SIZE" ]; then
            sudo tail -c "+$((LAST_SIZE + 1))" "$SERIAL_LOG" | tr -cd '[:print:][:space:]' | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' | sed 's/^/[serial] /'
            LAST_SIZE=$SIZE
        fi
        if sudo grep -qE "$FATAL_PATTERNS" "$SERIAL_LOG"; then
            echo "::error::tdx2-smoke: fatal pattern in serial"
            break
        fi
        for check in "${CHECKS[@]}"; do
            IFS="|" read -r name pattern <<< "$check"
            [ -n "${PASSED[$name]:-}" ] && continue
            if sudo grep -qE "$pattern" "$SERIAL_LOG"; then
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

# Find the host port libvirt's user-mode networking forwarded — for
# now we don't hostfwd through libvirt's bridge, so HTTP probe is
# skipped. The serial-pattern checks above are sufficient to confirm
# the workloads spawned and are running. Add an HTTP probe later if
# we want stronger end-to-end signal.

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
echo "tdx2-smoke: $PASS/$TOTAL passed"

if $ALL_DONE; then
    exit 0
fi
SMOKE_FAILED=1
exit 1
