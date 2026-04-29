#!/bin/bash
# Produce the target's final bootable image(s) from the built artifacts.
#
# Usage: mkimage.sh <profile-env> <output-dir>
#
# Inputs expected in <output-dir>:
#   easyenclave.efi        (UKI; always required)
#   easyenclave.rootfs/    (mkosi-populated directory; for disk format)
#
# Outputs depend on TARGET_FORMAT:
#   disk → rootfs.img (ext4), easyenclave.root.raw (GPT disk),
#          easyenclave.qcow2 (if `qcow2` in TARGET_OUTPUTS),
#          easyenclave-<sha12>-gcp.tar.gz (if `gcp-tar.gz` in TARGET_OUTPUTS),
#          easyenclave.vhd (if `vhd` in TARGET_OUTPUTS; fixed-size for Azure)
set -euo pipefail

PROFILE="${1:?Usage: mkimage.sh <profile-env> <output-dir>}"
OUT="${2:?Usage: mkimage.sh <profile-env> <output-dir>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

[ -f "$PROFILE" ] || { echo "mkimage: profile $PROFILE not found"; exit 1; }
# shellcheck disable=SC1090
. "$PROFILE"

UKI="$OUT/easyenclave.efi"
ROOTFS_DIR="$OUT/easyenclave.rootfs"
[ -f "$UKI" ] || { echo "mkimage: no UKI at $UKI"; exit 1; }
[ -d "$ROOTFS_DIR" ] || { echo "mkimage: no rootfs tree at $ROOTFS_DIR"; exit 1; }

echo "mkimage: format=$TARGET_FORMAT strategy=$TARGET_ROOT_STRATEGY"

case "$TARGET_FORMAT" in
    disk)
        # 1. Pack the rootfs tree into a plain ext4 image. Size auto-fits
        #    the rootfs contents (was hard-coded to 256MB, which only
        #    worked for the minimal busybox + easyenclave-binary image —
        #    blew up the moment llm-cuda added a kernel package). Slack
        #    of 40% covers ext4 journal + reserved blocks + per-file
        #    inode/block overhead; floor at 256MB so the existing
        #    minimal targets keep producing the same partition size
        #    they always did.
        ROOTFS_IMG="$OUT/rootfs.img"
        rm -f "$ROOTFS_IMG"
        ROOTFS_BYTES=$(sudo du -sb "$ROOTFS_DIR" | awk '{print $1}')
        ROOTFS_MB=$(( (ROOTFS_BYTES * 14 / 10 / 1048576 + 63) / 64 * 64 ))
        [ "$ROOTFS_MB" -lt 256 ] && ROOTFS_MB=256
        echo "mkimage: rootfs partition $ROOTFS_MB MB (contents $((ROOTFS_BYTES / 1048576)) MB)"
        dd if=/dev/zero of="$ROOTFS_IMG" bs=1M count="$ROOTFS_MB" status=none
        sudo mkfs.ext4 -F -L root -d "$ROOTFS_DIR" "$ROOTFS_IMG" 2>&1 | tail -3

        # 2. Assemble GPT disk: ESP (with UKI) + rootfs.
        bash "$SCRIPT_DIR/assemble-disk.sh" "$OUT"

        # 3. Derived formats.
        case " $TARGET_OUTPUTS " in
            *" qcow2 "*)
                qemu-img convert -f raw -O qcow2 -c \
                    "$OUT/easyenclave.root.raw" \
                    "$OUT/easyenclave.qcow2"
                ;;
        esac
        case " $TARGET_OUTPUTS " in
            *" gcp-tar.gz "*)
                # Name is chosen by the caller (CI packages it with a sha12
                # suffix). mkimage just produces the canonical disk.raw +
                # tar.gz pair.
                cp "$OUT/easyenclave.root.raw" "$OUT/disk.raw"
                tar -czf "$OUT/easyenclave-gcp.tar.gz" -C "$OUT" disk.raw
                rm -f "$OUT/disk.raw"
                ;;
        esac
        case " $TARGET_OUTPUTS " in
            *" vhd "*)
                # Azure Managed Disk upload requires a *fixed-size* VHD
                # (vpc subformat=fixed) with virtual size aligned to
                # 1 MiB. `force_size=on` keeps qemu-img from padding the
                # geometry field to the next CHS boundary, which would
                # otherwise round the logical size up and break the
                # alignment assertion Azure runs at import time.
                qemu-img convert -f raw -O vpc \
                    -o subformat=fixed,force_size=on \
                    "$OUT/easyenclave.root.raw" \
                    "$OUT/easyenclave.vhd"
                ;;
        esac
        ;;

    *)
        echo "mkimage: unknown TARGET_FORMAT=$TARGET_FORMAT"
        exit 1
        ;;
esac
