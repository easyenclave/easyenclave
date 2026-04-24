#!/bin/sh
# Qemu vendor stage — local/dev TDX VMs. No metadata service; config
# comes from the secondary config disk (iso9660/ext4/vfat at /dev/vdb
# or /dev/sdb with an /agent.env file) and/or the kernel cmdline. DHCP
# is best-effort — local QEMU usually has user-mode slirp or a bridge
# already providing 10.0.2.x / 192.168.x.x.

set -u
NEWROOT="${1:-/mnt/root}"
ENV_DIR="$NEWROOT/run/easyenclave"
ENV_FILE="$ENV_DIR/env"
VENDOR_NAME=qemu
mkdir -p "$ENV_DIR"

# shellcheck disable=SC1091
. /init-templates-vendors-lib.sh

for m in virtio_net virtio_blk virtio_pci virtio_scsi; do
    modprobe "$m" 2>/dev/null || :
done
# The config-disk probe below tries iso9660 first (that's the format
# genisoimage produces). Without the isofs module, the mount fails
# silently and we fall through to "no config disk" even when /dev/vdb
# is present. Load it here so the probe can use it.
modprobe isofs 2>/dev/null || :

ip link set lo up 2>/dev/null || :
IFACE=$(ls /sys/class/net 2>/dev/null | grep -v '^lo$' | head -n1 || true)
if [ -n "${IFACE:-}" ]; then
    ee_ifup "$IFACE"
fi

# Probe a secondary config disk for /agent.env. Local/libvirt deployments
# (local-tdx-qcow2 target) drop config on an auxiliary disk or ISO —
# there's no metadata service to pull it from.
CONFIG_MNT=/tmp/ee-config-disk
mkdir -p "$CONFIG_MNT"
MOUNTED=""
for dev in /dev/vdb /dev/sdb; do
    [ -e "$dev" ] || continue
    for fstype in iso9660 ext4 vfat ext2; do
        if mount -t "$fstype" -o ro "$dev" "$CONFIG_MNT" 2>/dev/null; then
            MOUNTED="$dev/$fstype"
            break 2
        fi
    done
done

if [ -n "$MOUNTED" ]; then
    ee_log "mounted config disk ($MOUNTED)"
    if [ -f "$CONFIG_MNT/agent.env" ]; then
        ee_append_config "$(cat "$CONFIG_MNT/agent.env")" || ee_log "agent.env merge failed"
    fi
    umount "$CONFIG_MNT" 2>/dev/null || :
else
    ee_log "no config disk at /dev/vdb or /dev/sdb"
fi
