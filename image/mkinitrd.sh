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
for cmd in sh mount umount switch_root mkdir cat echo sleep modprobe insmod findfs ls seq; do
    ln -s busybox "$WORKDIR/bin/$cmd"
done

# Copy modules + full transitive dep tree using modprobe's resolution.
# modprobe --show-depends is the source of truth — don't hand-list deps.
# Preserve the kernel/... path structure so modules.dep entries still resolve
# in the initrd.
#
# Modules are decompressed as we go. Ubuntu kernels ship Zstd-compressed
# modules (.ko.zst) and busybox's insmod/modprobe applets use the legacy
# init_module() syscall, which cannot handle Zstd — the kernel would see
# raw Zstd bytes and print "Invalid ELF header magic". Real kmod uses
# finit_module(..., MODULE_INIT_COMPRESSED_FILE) to let the kernel
# decompress, but we deliberately don't ship kmod in the initrd. So
# decompress once at build time and let busybox load plain .ko files.
#
# Some modules may be compiled into the kernel (CONFIG_*=y) instead of
# shipped as .ko files. In that case `modprobe --show-depends` returns
# nothing and we must skip silently, not abort — the driver is still
# in the kernel, just not separately loadable.
MODDIR="$WORKDIR/lib/modules/$KVER"
mkdir -p "$MODDIR"

# Copy one module file from MOD_SRC into MODDIR, decompressing Zstd/xz/gz
# on the way so busybox's insmod (which only handles plain ELF .ko) can
# load it. Tolerates missing source files — modprobe's dep tree can
# reference stale entries on zombie/partial kernel installs, and we
# don't want the whole build to die for one missing dep.
copy_mod() {
    local src="$1"
    [ -z "$src" ] && return 0
    if [ ! -f "$src" ]; then
        echo "  skip (missing): $src"
        return 0
    fi
    local rel="${src#"$MOD_SRC/"}"
    local dst="$MODDIR/$rel"
    mkdir -p "$(dirname "$dst")"
    case "$src" in
        *.ko.zst) zstd -d -q -f -o "${dst%.zst}" "$src" || return 0 ;;
        *.ko.xz)  xz -d -c "$src" > "${dst%.xz}"       || return 0 ;;
        *.ko.gz)  gzip -d -c "$src" > "${dst%.gz}"     || return 0 ;;
        *)        cp --update=none "$src" "$dst"       || return 0 ;;
    esac
}

for top in dm-verity nvme tdx-guest tsm-report gve virtio_net; do
    deps=$(modprobe --show-depends --set-version "$KVER" "$top" 2>&1 || true)
    if ! echo "$deps" | grep -q '^insmod'; then
        echo "  $top: not available as a module on $KVER (built-in or absent)"
        continue
    fi
    count=0
    # shellcheck disable=SC2034
    while read -r line; do
        src=$(echo "$line" | awk '/^insmod/ { print $2 }')
        [ -z "$src" ] && continue
        copy_mod "$src"
        count=$((count + 1))
    done <<<"$deps"
    echo "  $top: $count files processed"
done

# Regenerate modules.dep from the decompressed tree. depmod scans the
# files it finds and writes fresh entries, so the paths will reference
# plain .ko (matching what busybox modprobe can actually load).
depmod -b "$WORKDIR" "$KVER"

# Diagnostic: list what ended up in the initrd module tree so build
# logs show whether tdx-guest/nvme/etc. landed as .ko files or fell
# through to "built-in" status. If modules.dep is empty, the init
# script's modprobe calls will all no-op, which is fine as long as
# the corresponding drivers are compiled into the kernel.
echo "=== initrd module tree for $KVER ==="
find "$MODDIR" -type f -name '*.ko' 2>/dev/null | sort | sed "s|$MODDIR/||" || true
echo "=== modules.dep ==="
cat "$MODDIR/modules.dep" 2>/dev/null || echo "(missing)"
echo "==="

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
INIT
chmod +x "$WORKDIR/init"

# Create the cpio archive
(cd "$WORKDIR" && find . | cpio -o -H newc 2>/dev/null) | gzip -9 > "$OUTFILE"

SIZE=$(du -h "$OUTFILE" | cut -f1)
echo "Initrd built: $OUTFILE ($SIZE)"
