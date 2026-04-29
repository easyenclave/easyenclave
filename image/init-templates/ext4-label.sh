#!/bin/sh
# Root-strategy: ext4 rootfs on a GPT disk, resolved by `root=LABEL=...`
# and mounted read-only (optionally via dm-verity). Writable runtime
# state comes from tmpfs mounts overlaid on the RO rootfs.
#
# Flow:
#   1. Mount /proc /sys /dev so we can read cmdline and enumerate devs.
#   2. Parse cmdline — root=/roothash= drive root acquisition; ee.*
#      params are stashed to become the newroot's env file.
#   3. Load storage + attestation modules. Network drivers are loaded
#      by the per-vendor stage (/init-vendor.sh).
#   4. Resolve LABEL/UUID → device, mount ro at /mnt/root.
#   5. Mount tmpfs at /mnt/root/{run,tmp,var/lib/easyenclave} so PID 1
#      has somewhere writable. Seed /run/easyenclave/env with ee.* vars.
#   6. Run the per-vendor stage — brings up networking and merges cloud
#      metadata into /run/easyenclave/env.
#   7. mount --move /proc /sys /dev into /mnt/root so PID 1 inherits
#      them. switch_root.

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

# Parse kernel cmdline. root-strategy consumes root= / roothash= /
# systemd.verity_*; ee.* lines are accumulated for the newroot env.
ROOTHASH=""
ROOT_DATA=""
ROOT_HASH=""
: > /tmp/ee-cmdline.env
for param in $(cat /proc/cmdline); do
    case "$param" in
        roothash=*) ROOTHASH="${param#roothash=}" ;;
        systemd.verity_root_data=*) ROOT_DATA="${param#systemd.verity_root_data=}" ;;
        systemd.verity_root_hash=*) ROOT_HASH="${param#systemd.verity_root_hash=}" ;;
        root=*) ROOT_DATA="${param#root=}" ;;
        ee.*)  echo "${param#ee.}" >> /tmp/ee-cmdline.env ;;
    esac
done

# Storage + attestation modules. Network drivers (gve/virtio_net/hv_netvsc)
# are per-vendor; loaded by /init-vendor.sh. Storage drivers must load
# HERE because findfs LABEL=root needs the block device enumerated before
# root mount. Azure's CVM OS disk is on Hyper-V VMBus (hv_storvsc, needs
# hv_vmbus as a prereq) — without those loaded the disk never shows up
# and findfs bails after 30s. GCP uses nvme / virtio; including all three
# families here keeps the template target-agnostic. Tolerate built-ins
# silently — modprobe returns non-zero when the driver is compiled into
# the kernel, which is fine.
for m in dm-verity nvme virtio_blk virtio_pci virtio_scsi hv_vmbus hv_storvsc tdx_guest tsm_report; do
    modprobe "$m" 2>/dev/null || echo "note: $m not loaded (may be built-in)"
done

# Resolve LABEL=/UUID= via findfs, with a retry loop to let hotplug
# settle. Same UKI boots GCP (nvme0n1p2) and libvirt/qemu (vda2) thanks
# to the `root` label set at mkfs time (image/mkimage.sh).
# findfs handles LABEL=/UUID=/PARTLABEL=/PARTUUID=. busybox's
# implementation supports all four, which lets a verity layout point
# at the hash partition by PARTLABEL=verity without baking a device
# path that varies across cloud/qemu hosts.
resolve_dev() {
    local spec="$1" name="$2" out
    case "$spec" in
        LABEL=*|UUID=*|PARTLABEL=*|PARTUUID=*)
            for _ in $(seq 1 30); do
                out=$(findfs "$spec" 2>/dev/null || true)
                [ -n "$out" ] && [ -e "$out" ] && { echo "$out"; return 0; }
                sleep 1
            done
            ;;
        ?*)
            for _ in $(seq 1 30); do
                [ -e "$spec" ] && { echo "$spec"; return 0; }
                sleep 1
            done
            ;;
    esac
    echo "FATAL: $name '$spec' not found after 30s" >&2
    return 1
}

if ! ROOT_DATA=$(resolve_dev "$ROOT_DATA" "root data"); then
    ls /dev/nvme* /dev/vd* /dev/sd* 2>/dev/null
    exec /bin/sh
fi
echo "Resolved root data to $ROOT_DATA"

if [ -n "$ROOT_HASH" ]; then
    if ! ROOT_HASH=$(resolve_dev "$ROOT_HASH" "verity hash"); then
        exec /bin/sh
    fi
    echo "Resolved verity hash to $ROOT_HASH"
fi

if [ -n "$ROOTHASH" ] && [ -n "$ROOT_DATA" ] && [ -n "$ROOT_HASH" ] && command -v veritysetup >/dev/null; then
    veritysetup open "$ROOT_DATA" verity-root "$ROOT_HASH" "$ROOTHASH" || {
        echo "FATAL: dm-verity setup failed"
        exec /bin/sh
    }
    # No -t flag: kernel auto-detects ext4 vs squashfs (vs whatever).
    # Same template handles both confer-image-style squashfs+verity
    # and the historical ext4+verity layout.
    mount -o ro /dev/mapper/verity-root /mnt/root
elif [ -n "$ROOT_DATA" ]; then
    mount -o ro "$ROOT_DATA" /mnt/root
else
    echo "FATAL: no root= or roothash= in cmdline"
    exec /bin/sh
fi

# Writable tmpfs overlays — rootfs is RO (dm-verity or bare ext4 ro).
# /run and /var/lib/easyenclave MUST be writable; /tmp is POSIX-ly
# expected to be. These mounts survive switch_root since they live
# under /mnt/root.
mount -t tmpfs tmpfs /mnt/root/run 2>/dev/null || mkdir -p /mnt/root/run
mount -t tmpfs tmpfs /mnt/root/tmp 2>/dev/null || mkdir -p /mnt/root/tmp
mkdir -p /mnt/root/var/lib/easyenclave
mount -t tmpfs tmpfs /mnt/root/var/lib/easyenclave
mkdir -p /mnt/root/run/easyenclave \
         /mnt/root/var/lib/easyenclave/workloads \
         /mnt/root/var/lib/easyenclave/shared

# Seed the env file with ee.* cmdline params. The vendor stage appends
# cloud-metadata-provided KEY=VALUE lines after.
cat /tmp/ee-cmdline.env > /mnt/root/run/easyenclave/env

# Per-vendor stage: network driver modprobe, DHCP, metadata fetch. Baked
# into the initrd by mkinitrd.sh from image/init-templates/vendors/
# <TARGET_VENDOR>.sh. Missing file = no vendor integration (fine for
# stripped-down local builds).
if [ -x /init-vendor.sh ]; then
    /init-vendor.sh /mnt/root || echo "vendor stage exited non-zero (non-fatal)"
else
    echo "no /init-vendor.sh — skipping vendor stage"
fi

# Carry the virtual filesystems forward so PID 1 inherits them.
mount --move /proc /mnt/root/proc
mount --move /sys  /mnt/root/sys
mount --move /dev  /mnt/root/dev

exec switch_root /mnt/root /sbin/init
