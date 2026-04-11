#!/bin/bash
# Build a minimal initrd for easyenclave TDX VMs.
# Just enough to: load dm-verity/virtio modules, mount root, exec /sbin/init.
# ~2-5MB instead of mkosi's default ~300MB systemd initrd.
set -euo pipefail

OUTFILE="${1:-initrd.cpio.gz}"
KVER="${2:?Usage: mkinitrd.sh <outfile> <kernel-version>}"
MOD_SRC="/lib/modules/$KVER"

[ -d "$MOD_SRC" ] || { echo "FATAL: $MOD_SRC not found"; exit 1; }
echo "Building initrd for kernel $KVER (modules: $MOD_SRC)"

WORKDIR=$(mktemp -d)
trap "rm -rf $WORKDIR" EXIT

mkdir -p "$WORKDIR"/{bin,sbin,lib,lib64,dev,proc,sys,mnt/root,etc}

# Busybox as the userspace (static, ~1MB)
if command -v busybox >/dev/null 2>&1; then
    cp "$(which busybox)" "$WORKDIR/bin/busybox"
else
    # Download static busybox
    curl -fsSL -o "$WORKDIR/bin/busybox" \
        "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"
fi
chmod +x "$WORKDIR/bin/busybox"

# Symlink essential commands
for cmd in sh mount umount switch_root mkdir cat echo sleep modprobe insmod findfs ls; do
    ln -s busybox "$WORKDIR/bin/$cmd"
done

# Copy modules + full transitive dep tree using modprobe's resolution.
# modprobe --show-depends is the source of truth — don't hand-list deps.
# Preserve the kernel/... path structure so modules.dep entries still resolve
# in the initrd.
MODDIR="$WORKDIR/lib/modules/$KVER"
mkdir -p "$MODDIR"
for top in dm-verity nvme tdx-guest tsm-report; do
    modprobe --show-depends --set-version "$KVER" "$top" 2>/dev/null \
        | awk '/^insmod/ { print $2 }' \
        | while read -r src; do
            [ -z "$src" ] && continue
            rel=${src#"$MOD_SRC/"}
            dst="$MODDIR/$rel"
            mkdir -p "$(dirname "$dst")"
            cp --update=none "$src" "$dst"
        done
done

# Generate modules.dep inside the initrd so `modprobe` works at runtime
depmod -b "$WORKDIR" "$KVER"

# veritysetup for dm-verity (from cryptsetup-bin)
if command -v veritysetup >/dev/null 2>&1; then
    cp "$(which veritysetup)" "$WORKDIR/sbin/"
    # Copy its library deps
    ldd "$(which veritysetup)" 2>/dev/null | grep -o '/[^ ]*' | while read -r lib; do
        dir="$WORKDIR/$(dirname "$lib")"
        mkdir -p "$dir"
        cp -n "$lib" "$dir/" 2>/dev/null || true
    done
fi

# Init script
cat > "$WORKDIR/init" <<'INIT'
#!/bin/sh
# Minimal init: load modules, set up dm-verity, mount root, switch_root.

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
# deps automatically. Kernel built-ins (ext4, dm-mod, virtio_blk, crc32c) are
# already present.
modprobe dm-verity
modprobe nvme
# TDX attestation: tdx_guest provides the /dev/tdx_guest ioctl, tsm_report
# provides the configfs-tsm interface at /sys/kernel/config/tsm/report.
# Both are kernel modules (CONFIG_TDX_GUEST_DRIVER=m, CONFIG_TSM_REPORTS=m).
# Fast-fail if either won't load — an easyenclave VM with no attestation
# path is useless, so crash early rather than booting into a useless state.
modprobe tdx_guest || { echo "FATAL: tdx_guest modprobe failed — not a TDX guest?"; exec /bin/sh; }
modprobe tsm_report || { echo "FATAL: tsm_report modprobe failed"; exec /bin/sh; }

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
INIT
chmod +x "$WORKDIR/init"

# Create the cpio archive
(cd "$WORKDIR" && find . | cpio -o -H newc 2>/dev/null) | gzip -9 > "$OUTFILE"

SIZE=$(du -h "$OUTFILE" | cut -f1)
echo "Initrd built: $OUTFILE ($SIZE)"
