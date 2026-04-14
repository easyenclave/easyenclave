#!/bin/bash
# Assemble a bootable GPT disk from:
#   - UKI (kernel+initrd+cmdline as one EFI binary) → ESP partition
#   - rootfs.img (populated ext4) → root partition
#
# Layout:
#   GPT header + 1MB alignment
#   Partition 1: ESP (FAT32, 64MB)  — contains /EFI/BOOT/BOOTX64.EFI (the UKI)
#   Partition 2: root (ext4)        — populated rootfs
#
# TDX boot flow:
#   UEFI firmware → ESP/EFI/BOOT/BOOTX64.EFI (UKI) → kernel + initrd → init → easyenclave
set -euo pipefail

OUTPUT_DIR="${1:-.}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
UKI="${OUTPUT_DIR}/easyenclave.efi"
ROOT_IMG="${OUTPUT_DIR}/rootfs.img"
DISK="${OUTPUT_DIR}/easyenclave.root.raw"
ESP_SIZE=64  # MB

[ -f "$UKI" ] || { echo "No UKI at $UKI"; exit 1; }
[ -f "$ROOT_IMG" ] || { echo "No rootfs at $ROOT_IMG"; exit 1; }

# ESP with the UKI as the default boot entry (shared helper — also
# used by the iso target for El Torito).
ESP_IMG=$(mktemp)
trap 'rm -f "$ESP_IMG"' EXIT
bash "$SCRIPT_DIR/lib/mkesp.sh" "$UKI" "$ESP_IMG" $ESP_SIZE

# Partition layout
ESP_BYTES=$((ESP_SIZE * 1024 * 1024))
ROOT_BYTES=$(stat -c%s "$ROOT_IMG")
TOTAL_BYTES=$((1024*1024 + ESP_BYTES + ROOT_BYTES + 1024*1024))

dd if=/dev/zero of="$DISK" bs=1 count=0 seek=$TOTAL_BYTES 2>/dev/null

ESP_START=2048  # sector 2048 = 1MB aligned
ESP_SECTORS=$((ESP_BYTES / 512))
ROOT_START=$((ESP_START + ESP_SECTORS))
ROOT_SECTORS=$((ROOT_BYTES / 512))

sfdisk "$DISK" <<EOF >/dev/null
label: gpt
sector-size: 512
${ESP_START},${ESP_SECTORS},U
${ROOT_START},${ROOT_SECTORS},4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709
EOF

# Write partition contents
dd if="$ESP_IMG" of="$DISK" bs=512 seek=$ESP_START conv=notrunc 2>/dev/null
dd if="$ROOT_IMG" of="$DISK" bs=512 seek=$ROOT_START conv=notrunc 2>/dev/null

SIZE=$(du -h "$DISK" | cut -f1)
echo "Bootable disk assembled: $DISK ($SIZE)"
echo "  ESP:  ${ESP_SIZE}MB (UKI at EFI/BOOT/BOOTX64.EFI)"
echo "  Root: $((ROOT_BYTES / 1024 / 1024))MB (populated ext4)"
