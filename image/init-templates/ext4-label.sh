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

# Storage + attestation modules. Network drivers (gve/virtio_net/hv_*)
# are per-vendor; loaded by /init-vendor.sh. Tolerate built-ins (busybox
# modprobe says "not found" if a driver is compiled into the kernel —
# the capability is still present).
for m in dm-verity nvme virtio_blk virtio_pci virtio_scsi tdx_guest tsm_report; do
    modprobe "$m" 2>/dev/null || echo "note: $m not loaded (may be built-in)"
done

# Resolve LABEL=/UUID= via findfs, with a retry loop to let hotplug
# settle. Same UKI boots GCP (nvme0n1p2) and libvirt/qemu (vda2) thanks
# to the `root` label set at mkfs time (image/mkimage.sh).
case "$ROOT_DATA" in
    LABEL=*|UUID=*)
        for i in $(seq 1 30); do
            RESOLVED=$(findfs "$ROOT_DATA" 2>/dev/null || true)
            [ -n "$RESOLVED" ] && [ -e "$RESOLVED" ] && { ROOT_DATA="$RESOLVED"; break; }
            sleep 1
        done
        ;;
    *)
        for i in $(seq 1 30); do
            [ -e "$ROOT_DATA" ] && break
            sleep 1
        done
        ;;
esac
echo "Resolved root to $ROOT_DATA"
[ -e "$ROOT_DATA" ] || { echo "FATAL: $ROOT_DATA not found after 30s"; ls /dev/nvme* /dev/vd* /dev/sd* 2>/dev/null; exec /bin/sh; }

if [ -n "$ROOTHASH" ] && [ -n "$ROOT_DATA" ] && [ -n "$ROOT_HASH" ] && command -v veritysetup >/dev/null; then
    veritysetup open "$ROOT_DATA" verity-root "$ROOT_HASH" "$ROOTHASH" || {
        echo "FATAL: dm-verity setup failed"
        exec /bin/sh
    }
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
