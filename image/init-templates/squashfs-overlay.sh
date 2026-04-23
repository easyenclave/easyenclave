#!/bin/sh
# Root-strategy: iso9660 on a CDROM device carrying rootfs.squashfs,
# loop-mounted RO and overlaid with a tmpfs upper layer for writes.
# Used by local-tdx for dev iteration — nothing persists across reboots.
#
# Flow mirrors ext4-label.sh:
#   1. Mount /proc /sys /dev.
#   2. Parse cmdline — we don't use root=/roothash= here (iso discovery
#      is by device probe), but ee.* vars still get captured for the
#      newroot env file.
#   3. Load iso/squashfs/overlay modules + attestation. Network drivers
#      come from the vendor stage.
#   4. Find CDROM, loop-mount squashfs, build tmpfs overlay at /mnt/root.
#   5. Seed /run/easyenclave/env from cmdline.
#   6. Run per-vendor stage (qemu for local — merges /agent.env from
#      the secondary config disk).
#   7. mount --move /proc /sys /dev, switch_root.

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

# Accumulate ee.* cmdline params for the newroot env file.
: > /tmp/ee-cmdline.env
for param in $(cat /proc/cmdline); do
    case "$param" in
        ee.*) echo "${param#ee.}" >> /tmp/ee-cmdline.env ;;
    esac
done

for m in tdx_guest tsm_report virtio_blk virtio_pci virtio_scsi sr_mod cdrom isofs loop squashfs overlay; do
    modprobe "$m" 2>/dev/null || echo "note: $m not loaded (may be built-in)"
done

mkdir -p /mnt/iso /mnt/lower /mnt/upper /mnt/work /mnt/root
ISO_DEV=""
for i in $(seq 1 30); do
    for dev in /dev/sr0 /dev/sr1 /dev/cdrom /dev/vda /dev/vdb; do
        [ -e "$dev" ] || continue
        if mount -t iso9660 -o ro "$dev" /mnt/iso 2>/dev/null; then
            if [ -f /mnt/iso/rootfs.squashfs ]; then
                ISO_DEV="$dev"
                break 2
            fi
            umount /mnt/iso 2>/dev/null || true
        fi
    done
    sleep 1
done
[ -n "$ISO_DEV" ] || { echo "FATAL: no iso9660 with rootfs.squashfs"; ls /dev/sr* /dev/vd* 2>/dev/null; exec /bin/sh; }
echo "Resolved iso to $ISO_DEV"

mount -t squashfs -o loop,ro /mnt/iso/rootfs.squashfs /mnt/lower || {
    echo "FATAL: squashfs mount failed"
    exec /bin/sh
}
mount -t tmpfs tmpfs /mnt/upper || true
mkdir -p /mnt/upper/u /mnt/upper/w
mount -t overlay overlay \
    -o "lowerdir=/mnt/lower,upperdir=/mnt/upper/u,workdir=/mnt/upper/w" \
    /mnt/root || {
    echo "FATAL: overlay mount failed"
    exec /bin/sh
}

# Carry iso9660 forward for post-boot inspection of rootfs.squashfs.
mkdir -p /mnt/root/mnt/iso
mount --move /mnt/iso /mnt/root/mnt/iso 2>/dev/null || true

# Writable runtime mounts. The overlay upper is already tmpfs-backed,
# so these are redundant for squashfs-overlay — but kept for symmetry
# with ext4-label (ensures `/run` is a fresh tmpfs on every boot, not
# tied to overlay upper-layer lifetime).
mount -t tmpfs tmpfs /mnt/root/run 2>/dev/null || :
mount -t tmpfs tmpfs /mnt/root/var/lib/easyenclave 2>/dev/null || :
mkdir -p /mnt/root/run/easyenclave \
         /mnt/root/var/lib/easyenclave/workloads \
         /mnt/root/var/lib/easyenclave/shared

cat /tmp/ee-cmdline.env > /mnt/root/run/easyenclave/env

if [ -x /init-vendor.sh ]; then
    /init-vendor.sh /mnt/root || echo "vendor stage exited non-zero (non-fatal)"
else
    echo "no /init-vendor.sh — skipping vendor stage"
fi

mount --move /proc /mnt/root/proc
mount --move /sys  /mnt/root/sys
mount --move /dev  /mnt/root/dev

exec switch_root /mnt/root /sbin/init
