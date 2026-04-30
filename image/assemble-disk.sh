#!/bin/bash
# Assemble a bootable GPT disk from build artifacts.
#
# Two layouts, dispatched by TARGET_ROOT_STRATEGY:
#
#   ext4-label                              dm-verity-squashfs
#   ┌───────────────────┐                   ┌───────────────────┐
#   │ ESP (64MB, FAT32) │                   │ ESP (64MB, FAT32) │
#   ├───────────────────┤                   ├───────────────────┤
#   │ root (ext4, RW    │                   │ root (squashfs,   │
#   │ at mount-time     │                   │ read-only)        │
#   │ unless dm-verity) │                   │  PARTLABEL=root   │
#   │  LABEL=root       │                   ├───────────────────┤
#   └───────────────────┘                   │ verity (Merkle    │
#                                           │ tree)             │
#                                           │  PARTLABEL=verity │
#                                           └───────────────────┘
#
# Every partition is 1MB-aligned. Sector size 512.
#
# TDX boot flow:
#   UEFI firmware → ESP/EFI/BOOT/BOOTX64.EFI (UKI) → kernel + initrd
#   → /init (mounts root, optionally veritysetup-opens it) → easyenclave
set -euo pipefail

OUTPUT_DIR="${1:-.}"
PROFILE="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
UKI="${OUTPUT_DIR}/easyenclave.efi"
DISK="${OUTPUT_DIR}/easyenclave.root.raw"
ESP_SIZE=64  # MB

[ -f "$UKI" ] || { echo "No UKI at $UKI"; exit 1; }

# Resolve strategy from profile if provided. Falls back to ext4-label
# for backward compatibility (the gcp/azure/local-tdx-qcow2 profiles
# don't set the second arg today).
STRATEGY="ext4-label"
if [ -n "$PROFILE" ] && [ -f "$PROFILE" ]; then
    # shellcheck disable=SC1090
    . "$PROFILE"
    STRATEGY="${TARGET_ROOT_STRATEGY:-ext4-label}"
fi

# ESP with the UKI as the default boot entry.
ESP_IMG=$(mktemp)
trap 'rm -f "$ESP_IMG"' EXIT
bash "$SCRIPT_DIR/lib/mkesp.sh" "$UKI" "$ESP_IMG" "$ESP_SIZE"
ESP_BYTES=$((ESP_SIZE * 1024 * 1024))

case "$STRATEGY" in
    ext4-label)
        ROOT_IMG="${OUTPUT_DIR}/rootfs.img"
        [ -f "$ROOT_IMG" ] || { echo "No rootfs at $ROOT_IMG"; exit 1; }
        ROOT_BYTES=$(stat -c%s "$ROOT_IMG")
        TOTAL_BYTES=$((1024*1024 + ESP_BYTES + ROOT_BYTES + 1024*1024))

        # rm first so a stale image from an earlier build doesn't
        # carry filesystem signatures sfdisk would refuse to clobber.
        rm -f "$DISK"
        dd if=/dev/zero of="$DISK" bs=1 count=0 seek="$TOTAL_BYTES" 2>/dev/null

        ESP_START=2048  # 1MB aligned
        ESP_SECTORS=$((ESP_BYTES / 512))
        ROOT_START=$((ESP_START + ESP_SECTORS))
        ROOT_SECTORS=$((ROOT_BYTES / 512))

        # Keyword-only sfdisk script form (positional+keyword mix
        # rejects `name=` with "unsupported command"; full keyword
        # works cleanly).
        sfdisk "$DISK" <<EOF >/dev/null
label: gpt
sector-size: 512
start=${ESP_START},size=${ESP_SECTORS},type=U,name=esp
start=${ROOT_START},size=${ROOT_SECTORS},type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709,name=root
EOF

        dd if="$ESP_IMG"  of="$DISK" bs=512 seek="$ESP_START"  conv=notrunc 2>/dev/null
        dd if="$ROOT_IMG" of="$DISK" bs=512 seek="$ROOT_START" conv=notrunc 2>/dev/null

        SIZE=$(du -h "$DISK" | cut -f1)
        echo "Bootable disk assembled: $DISK ($SIZE)"
        echo "  ESP:  ${ESP_SIZE}MB (UKI at EFI/BOOT/BOOTX64.EFI)"
        echo "  Root: $((ROOT_BYTES / 1024 / 1024))MB (ext4, LABEL=root)"
        ;;

    dm-verity-squashfs)
        SQFS="${OUTPUT_DIR}/rootfs.squashfs"
        VERITY="${OUTPUT_DIR}/rootfs.verity"
        [ -f "$SQFS" ]   || { echo "No squashfs at $SQFS"; exit 1; }
        [ -f "$VERITY" ] || { echo "No verity hash at $VERITY"; exit 1; }
        SQFS_BYTES=$(stat -c%s "$SQFS")
        VERITY_BYTES=$(stat -c%s "$VERITY")

        # Pad each partition up to a 1MB boundary so consecutive starts
        # stay aligned without arithmetic on raw byte counts.
        align_up() { local v=$1 a=$((1024*1024)); echo $(( (v + a - 1) / a * a )); }
        SQFS_PART_BYTES=$(align_up "$SQFS_BYTES")
        VERITY_PART_BYTES=$(align_up "$VERITY_BYTES")
        TOTAL_BYTES=$((1024*1024 + ESP_BYTES + SQFS_PART_BYTES + VERITY_PART_BYTES + 1024*1024))

        # rm first so a stale image from an earlier build doesn't
        # carry filesystem signatures sfdisk would refuse to clobber.
        rm -f "$DISK"
        dd if=/dev/zero of="$DISK" bs=1 count=0 seek="$TOTAL_BYTES" 2>/dev/null

        ESP_START=2048
        ESP_SECTORS=$((ESP_BYTES / 512))
        ROOT_START=$((ESP_START + ESP_SECTORS))
        ROOT_SECTORS=$((SQFS_PART_BYTES / 512))
        VERITY_START=$((ROOT_START + ROOT_SECTORS))
        VERITY_SECTORS=$((VERITY_PART_BYTES / 512))

        # GPT partition type GUIDs from the Discoverable Partitions
        # spec — same values systemd-repart and confer-image use.
        # 4F68BCE3-... = Linux x86-64 root (used as a generic data
        # partition here); we differentiate via PARTLABEL.
        # systemd's verity-data and verity-hash GUIDs would technically
        # be more semantically correct, but findfs PARTLABEL= lookup
        # already disambiguates without needing a special GUID — and
        # using the same GUID family keeps the layout legible to
        # tooling that doesn't speak DPS.
        # Keyword-only sfdisk script form — see ext4-label branch.
        sfdisk "$DISK" <<EOF >/dev/null
label: gpt
sector-size: 512
start=${ESP_START},size=${ESP_SECTORS},type=U,name=esp
start=${ROOT_START},size=${ROOT_SECTORS},type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709,name=root
start=${VERITY_START},size=${VERITY_SECTORS},type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709,name=verity
EOF

        dd if="$ESP_IMG" of="$DISK" bs=512 seek="$ESP_START"    conv=notrunc 2>/dev/null
        dd if="$SQFS"    of="$DISK" bs=512 seek="$ROOT_START"   conv=notrunc 2>/dev/null
        dd if="$VERITY"  of="$DISK" bs=512 seek="$VERITY_START" conv=notrunc 2>/dev/null

        SIZE=$(du -h "$DISK" | cut -f1)
        echo "Bootable disk assembled: $DISK ($SIZE)"
        echo "  ESP:    ${ESP_SIZE}MB (UKI at EFI/BOOT/BOOTX64.EFI)"
        echo "  Root:   $((SQFS_PART_BYTES / 1024 / 1024))MB (squashfs, PARTLABEL=root)"
        echo "  Verity: $((VERITY_PART_BYTES / 1024 / 1024))MB (Merkle tree, PARTLABEL=verity)"
        ;;

    *)
        echo "assemble-disk: unknown strategy '$STRATEGY'" >&2
        exit 1
        ;;
esac
