#!/bin/sh
# Minimal init: load modules, find ISO, loop-mount squashfs, overlay on
# tmpfs for writable upper layer, switch_root.
#
# Root acquisition: iso9660 from a CDROM device, squashfs file inside it,
# overlayfs(tmpfs upper, squashfs lower).

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

# Load modules. Storage + network + iso/squashfs/overlay. Tolerate
# built-ins silently (modprobe prints "not found" when the driver is
# compiled in, which is fine — the capability is still present).
for m in tdx_guest tsm_report virtio_blk virtio_net virtio_pci virtio_scsi sr_mod cdrom isofs loop squashfs overlay; do
    modprobe "$m" 2>/dev/null || echo "note: $m not loaded (may be built-in)"
done

# Find the CDROM holding rootfs.squashfs. Try common names in order; the
# device ordering depends on host config (local QEMU tends to /dev/sr0,
# virtio-scsi hosts may see /dev/sr1 first).
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

# Loop-mount the sealed rootfs read-only.
mount -t squashfs -o loop,ro /mnt/iso/rootfs.squashfs /mnt/lower || {
    echo "FATAL: squashfs mount failed"
    exec /bin/sh
}

# Writable overlay: lower = sealed squashfs, upper = tmpfs.
# Result: the rootfs looks writable but nothing persists across reboots —
# which is the intended sealed-VM behavior.
mount -t tmpfs tmpfs /mnt/upper || true
mkdir -p /mnt/upper/u /mnt/upper/w
mount -t overlay overlay \
    -o "lowerdir=/mnt/lower,upperdir=/mnt/upper/u,workdir=/mnt/upper/w" \
    /mnt/root || {
    echo "FATAL: overlay mount failed"
    exec /bin/sh
}

# Carry the iso9660 mount forward so the running system can still read
# rootfs.squashfs (debugging) and any secondary data the image may add.
mkdir -p /mnt/root/mnt/iso
mount --move /mnt/iso /mnt/root/mnt/iso 2>/dev/null || true

umount /proc /sys
exec switch_root /mnt/root /sbin/init
