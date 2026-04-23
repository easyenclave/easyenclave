#!/bin/bash
# Build a minimal initrd for easyenclave VMs, profile-driven.
# Just enough to: load the target's modules, mount its root, switch_root.
# ~2-5MB instead of mkosi's default ~300MB systemd initrd.
#
# Usage: mkinitrd.sh <outfile> <kernel-version> <profile-env>
#
# The profile env file (e.g. image/targets/gcp/profile.env) supplies:
#   TARGET_INITRD_MODULES   - space-separated module names to pull in
#   TARGET_ROOT_STRATEGY    - name of the init template under init-templates/
#   TARGET_VENDOR           - name of the vendor stage script under
#                             init-templates/vendors/ (gcp, azure, qemu).
#                             Missing = no vendor stage (the initrd will
#                             skip cloud metadata + network setup).
set -euo pipefail

OUTFILE="${1:?Usage: mkinitrd.sh <outfile> <kernel-version> <profile-env>}"
KVER="${2:?Usage: mkinitrd.sh <outfile> <kernel-version> <profile-env>}"
PROFILE="${3:?Usage: mkinitrd.sh <outfile> <kernel-version> <profile-env>}"
MOD_SRC="/lib/modules/$KVER"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

[ -f "$PROFILE" ] || { echo "FATAL: profile $PROFILE not found"; exit 1; }
[ -d "$MOD_SRC" ] || { echo "FATAL: $MOD_SRC not found"; exit 1; }

# shellcheck disable=SC1090
. "$PROFILE"

INIT_TEMPLATE="$SCRIPT_DIR/init-templates/${TARGET_ROOT_STRATEGY}.sh"
[ -f "$INIT_TEMPLATE" ] || { echo "FATAL: no init template for $TARGET_ROOT_STRATEGY at $INIT_TEMPLATE"; exit 1; }

VENDOR_SCRIPT=""
if [ -n "${TARGET_VENDOR:-}" ]; then
    VENDOR_SCRIPT="$SCRIPT_DIR/init-templates/vendors/${TARGET_VENDOR}.sh"
    [ -f "$VENDOR_SCRIPT" ] || { echo "FATAL: no vendor script for $TARGET_VENDOR at $VENDOR_SCRIPT"; exit 1; }
fi

echo "Building initrd for kernel $KVER"
echo "  profile:  $PROFILE"
echo "  strategy: $TARGET_ROOT_STRATEGY"
echo "  vendor:   ${TARGET_VENDOR:-<none>}"
echo "  modules:  $TARGET_INITRD_MODULES"

WORKDIR=$(mktemp -d)
trap "rm -rf $WORKDIR" EXIT

mkdir -p "$WORKDIR"/{bin,sbin,lib,lib64,dev,proc,sys,tmp,mnt/root,etc}

# Busybox as the userspace (static, ~1MB)
if command -v busybox >/dev/null 2>&1; then
    cp "$(which busybox)" "$WORKDIR/bin/busybox"
else
    # Download static busybox
    curl -fsSL -o "$WORKDIR/bin/busybox" \
        "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"
fi
chmod +x "$WORKDIR/bin/busybox"

# Symlink essential commands. The vendor stage needs `ip`, `udhcpc`,
# `wget`, `base64`, `grep`, `head`, `tail`, `tr`, `cut`, and the usual
# coreutils wrappers (busybox applets). Adding a symlink is free at
# runtime — busybox routes applets by argv[0].
for cmd in sh mount umount switch_root mkdir cat echo sleep modprobe insmod \
           findfs ls losetup ip udhcpc wget base64 grep head tail tr cut \
           sed awk seq printf chmod touch rm ln env; do
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

for top in $TARGET_INITRD_MODULES; do
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

# veritysetup for dm-verity (from cryptsetup-bin). Only meaningful for
# strategies that use dm-verity (ext4-label does; squashfs-overlay
# doesn't). Copying unconditionally adds ~200KB + libs; cheap insurance.
if command -v veritysetup >/dev/null 2>&1; then
    cp "$(which veritysetup)" "$WORKDIR/sbin/"
    # Copy its library deps
    ldd "$(which veritysetup)" 2>/dev/null | grep -o '/[^ ]*' | while read -r lib; do
        dir="$WORKDIR/$(dirname "$lib")"
        mkdir -p "$dir"
        cp -n "$lib" "$dir/" 2>/dev/null || true
    done
fi

# Install the profile-specified init template.
cp "$INIT_TEMPLATE" "$WORKDIR/init"
chmod +x "$WORKDIR/init"

# Install the per-vendor stage script at /init-vendor.sh, plus the
# udhcpc hook it needs to actually configure the interface after DHCP.
# The hook is the same one the rootfs ships at /usr/share/udhcpc/
# default.script — keeping one source of truth for classless-static-
# route handling.
if [ -n "$VENDOR_SCRIPT" ]; then
    cp "$VENDOR_SCRIPT" "$WORKDIR/init-vendor.sh"
    chmod +x "$WORKDIR/init-vendor.sh"

    # Shared vendor-stage helpers (ee_log, ee_ifup, ee_append_config).
    # Path under / so the sourced path in vendor scripts is stable.
    LIB_SRC="$SCRIPT_DIR/init-templates/vendors/_lib.sh"
    if [ -f "$LIB_SRC" ]; then
        cp "$LIB_SRC" "$WORKDIR/init-templates-vendors-lib.sh"
    else
        echo "FATAL: vendor helper lib $LIB_SRC missing"
        exit 1
    fi

    HOOK_SRC="$SCRIPT_DIR/mkosi.extra/usr/share/udhcpc/default.script"
    if [ -f "$HOOK_SRC" ]; then
        mkdir -p "$WORKDIR/usr/share/udhcpc"
        cp "$HOOK_SRC" "$WORKDIR/usr/share/udhcpc/default.script"
        chmod +x "$WORKDIR/usr/share/udhcpc/default.script"
    else
        echo "WARN: udhcpc hook $HOOK_SRC missing — DHCP-derived routes won't install"
    fi
fi

# Create the cpio archive
(cd "$WORKDIR" && find . | cpio -o -H newc 2>/dev/null) | gzip -9 > "$OUTFILE"

SIZE=$(du -h "$OUTFILE" | cut -f1)
echo "Initrd built: $OUTFILE ($SIZE)"
