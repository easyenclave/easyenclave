#!/bin/sh
# Minimal init: load modules, set up dm-verity, mount root, switch_root.
#
# Root acquisition: resolve `root=LABEL=...` via findfs, mount the ext4
# rootfs read-only (optionally via dm-verity).

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

# Parse kernel cmdline
ROOTHASH=""
ROOT_DATA=""
ROOT_HASH=""
for param in $(cat /proc/cmdline); do
    case "$param" in
        roothash=*) ROOTHASH="${param#roothash=}" ;;
        systemd.verity_root_data=*) ROOT_DATA="${param#systemd.verity_root_data=}" ;;
        systemd.verity_root_hash=*) ROOT_HASH="${param#systemd.verity_root_hash=}" ;;
        root=*) ROOT_DATA="${param#root=}" ;;
    esac
done

# Load kernel modules via modprobe — uses modules.dep to resolve transitive
# deps automatically. Kernel built-ins (ext4, dm-mod, virtio_blk, crc32c)
# are already present. If a target module is compiled in rather than
# shipped as .ko (e.g. Ubuntu's stock kernels with CONFIG_TDX_GUEST_DRIVER=y),
# busybox modprobe returns "not found"; we tolerate that because the
# driver is still in the kernel. If it's genuinely missing, easyenclave's
# attestation backend detection will fail later with a clearer error.
modprobe dm-verity 2>/dev/null || echo "note: dm-verity not loaded (may be built-in)"
modprobe nvme 2>/dev/null      || echo "note: nvme not loaded (may be built-in or N/A)"
modprobe tdx_guest 2>/dev/null || echo "note: tdx_guest not loaded (may be built-in)"
modprobe tsm_report 2>/dev/null || echo "note: tsm_report not loaded (may be built-in)"
# Network drivers — needed BEFORE switch_root so /sys/class/net has a
# non-lo interface by the time easyenclave's init.rs reads it to decide
# which interface to DHCP. Without this, easyenclave sees only "lo",
# skips the entire `if let Some(iface)` block, never runs udhcpc, never
# fetches GCE metadata, never deploys workloads — the VM silently
# reaches "listening on" with no network. GCP c3 machines use gVNIC
# (gve driver); other types use virtio-net.
modprobe gve 2>/dev/null       || echo "note: gve not loaded (not a c3/gvnic host?)"
modprobe virtio_net 2>/dev/null || echo "note: virtio_net not loaded (not a virtio host?)"

# Resolve LABEL=/UUID= to a device path. The cmdline uses
# `root=LABEL=root` so one UKI boots on both GCP (nvme0n1p2) and
# libvirt/qemu (vda2) — the kernel labels the ext4 rootfs with
# "root" at build time (see image/Makefile mkfs.ext4 -L root).
case "$ROOT_DATA" in
    LABEL=*|UUID=*)
        for i in $(seq 1 30); do
            RESOLVED=$(findfs "$ROOT_DATA" 2>/dev/null || true)
            [ -n "$RESOLVED" ] && [ -e "$RESOLVED" ] && { ROOT_DATA="$RESOLVED"; break; }
            sleep 1
        done
        ;;
    *)
        # Explicit device path — just wait for it.
        for i in $(seq 1 30); do
            [ -e "$ROOT_DATA" ] && break
            sleep 1
        done
        ;;
esac
echo "Resolved root to $ROOT_DATA"
[ -e "$ROOT_DATA" ] || { echo "FATAL: $ROOT_DATA not found after 30s"; ls /dev/nvme* /dev/vd* /dev/sd* 2>/dev/null; exec /bin/sh; }

if [ -n "$ROOTHASH" ] && [ -n "$ROOT_DATA" ] && [ -n "$ROOT_HASH" ] && command -v veritysetup >/dev/null; then
    # dm-verity: cryptographically verified root
    veritysetup open "$ROOT_DATA" verity-root "$ROOT_HASH" "$ROOTHASH" || {
        echo "FATAL: dm-verity setup failed"
        exec /bin/sh
    }
    mount -o ro /dev/mapper/verity-root /mnt/root
elif [ -n "$ROOT_DATA" ]; then
    # Fallback: direct mount (no verity)
    mount -o ro "$ROOT_DATA" /mnt/root
else
    echo "FATAL: no root= or roothash= in cmdline"
    exec /bin/sh
fi

# Switch to the real root and exec easyenclave
umount /proc /sys
exec switch_root /mnt/root /sbin/init
