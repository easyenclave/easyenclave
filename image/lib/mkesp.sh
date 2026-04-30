#!/bin/bash
# Build a FAT32 ESP image containing the given UKI at EFI/BOOT/BOOTX64.EFI.
#
# Usage: mkesp.sh <uki-path> <out-image-path> [size-mb]
#
# Shared by assemble-disk.sh (GCP disk ESP) and mkimage.sh (ISO El Torito).

set -euo pipefail

UKI="${1:?Usage: mkesp.sh <uki> <out> [size-mb]}"
OUT="${2:?Usage: mkesp.sh <uki> <out> [size-mb]}"
SIZE_MB="${3:-64}"

[ -f "$UKI" ] || { echo "mkesp: no UKI at $UKI"; exit 1; }

dd if=/dev/zero of="$OUT" bs=1M count="$SIZE_MB" status=none
mkfs.vfat -F 32 "$OUT" >/dev/null
mmd -i "$OUT" ::EFI ::EFI/BOOT
mcopy -i "$OUT" "$UKI" ::EFI/BOOT/BOOTX64.EFI
