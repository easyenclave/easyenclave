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
#   iso  → rootfs.squashfs, easyenclave.iso
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
        # 1. Pack the rootfs tree into a plain ext4 image.
        ROOTFS_IMG="$OUT/rootfs.img"
        rm -f "$ROOTFS_IMG"
        dd if=/dev/zero of="$ROOTFS_IMG" bs=1M count=256 status=none
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

    iso)
        # 1. Squashfs of the rootfs. zstd is a good balance of size/speed;
        # xz would be ~10-15% smaller but much slower to build.
        SQUASHFS="$OUT/rootfs.squashfs"
        rm -f "$SQUASHFS"
        sudo mksquashfs "$ROOTFS_DIR" "$SQUASHFS" -comp zstd -quiet
        sudo chown "$(id -u):$(id -g)" "$SQUASHFS"

        # 2. ESP image with the UKI as the El Torito EFI boot entry.
        ESP_IMG=$(mktemp)
        trap 'rm -f "$ESP_IMG"' EXIT
        bash "$SCRIPT_DIR/lib/mkesp.sh" "$UKI" "$ESP_IMG" 48

        # 3. Hybrid ISO with an embedded ESP partition. xorriso's
        #    -append_partition + -isohybrid-gpt-basdat produces an ISO
        #    that UEFI firmware boots directly via its El Torito EFI
        #    entry, while iso9660 still contains our rootfs.squashfs.
        STAGE=$(mktemp -d)
        trap 'rm -rf "$STAGE"; rm -f "$ESP_IMG"' EXIT
        cp "$SQUASHFS" "$STAGE/rootfs.squashfs"

        xorriso -as mkisofs \
            -V EE_ISO \
            -o "$OUT/easyenclave.iso" \
            -isohybrid-gpt-basdat \
            -partition_offset 16 \
            -append_partition 2 0xef "$ESP_IMG" \
            -e --interval:appended_partition_2:all:: \
            -no-emul-boot \
            -iso-level 3 \
            -joliet \
            -rational-rock \
            "$STAGE"

        SIZE=$(du -h "$OUT/easyenclave.iso" | cut -f1)
        echo "ISO built: $OUT/easyenclave.iso ($SIZE)"
        ;;

    *)
        echo "mkimage: unknown TARGET_FORMAT=$TARGET_FORMAT"
        exit 1
        ;;
esac
