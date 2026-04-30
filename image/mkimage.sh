#!/bin/bash
# Produce the target's final bootable image(s) from the built artifacts.
#
# Usage: mkimage.sh <profile-env> <output-dir>
#
# Inputs expected in <output-dir>:
#   easyenclave.efi        (UKI; always required)
#   ext4-label strategy:
#     rootfs.img             (built earlier by lib/mkroot.sh)
#   dm-verity-squashfs strategy:
#     rootfs.squashfs        (built earlier by lib/mkroot.sh)
#     rootfs.verity          (built earlier by lib/mkroot.sh)
#     roothash.txt           (consumed by Makefile pre-ukify; required here
#                             only as evidence the strategy ran cleanly)
#
# Outputs depend on TARGET_FORMAT:
#   disk → easyenclave.root.raw (GPT disk),
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
[ -f "$UKI" ] || { echo "mkimage: no UKI at $UKI"; exit 1; }

echo "mkimage: format=$TARGET_FORMAT strategy=$TARGET_ROOT_STRATEGY"

case "$TARGET_FORMAT" in
    disk)
        # 1. Build the per-strategy root payload. ext4-label produces
        #    rootfs.img; dm-verity-squashfs produces rootfs.squashfs +
        #    rootfs.verity + roothash.txt. The Makefile is responsible
        #    for invoking lib/mkroot.sh BEFORE this script runs (so the
        #    roothash can be folded into the cmdline before ukify), so
        #    the artifacts are expected to already be on disk here.
        case "$TARGET_ROOT_STRATEGY" in
            ext4-label)
                [ -f "$OUT/rootfs.img" ] || { echo "mkimage: missing $OUT/rootfs.img — has lib/mkroot.sh been run?"; exit 1; }
                ;;
            dm-verity-squashfs)
                for f in rootfs.squashfs rootfs.verity roothash.txt; do
                    [ -f "$OUT/$f" ] || { echo "mkimage: missing $OUT/$f — has lib/mkroot.sh been run?"; exit 1; }
                done
                ;;
            *)
                echo "mkimage: unknown strategy '$TARGET_ROOT_STRATEGY'" >&2
                exit 1
                ;;
        esac

        # 2. Assemble GPT disk: ESP (with UKI) + per-strategy root.
        bash "$SCRIPT_DIR/assemble-disk.sh" "$OUT" "$PROFILE"

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
