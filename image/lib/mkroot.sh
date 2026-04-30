#!/bin/bash
# Build the per-strategy root partition payload from a populated rootfs
# directory. Called by mkimage.sh before disk assembly.
#
# Usage: mkroot.sh <strategy> <rootfs-dir> <output-dir>
#
# Strategies:
#   ext4-label
#     Produces:
#       <output-dir>/rootfs.img         (mkfs.ext4 -L root, contents copied)
#     Auto-sized partition (40% slack over `du -sb`, floor 256MB).
#
#   dm-verity-squashfs
#     Produces:
#       <output-dir>/rootfs.squashfs    (mksquashfs, zstd, no-padding off)
#       <output-dir>/rootfs.verity      (Merkle tree from veritysetup format)
#       <output-dir>/roothash.txt       (hex roothash, single line)
#     The Makefile reads roothash.txt and appends `roothash=<hex>` plus
#     the systemd.verity_root_{data,hash}=PARTLABEL=... cmdline entries
#     before ukify embeds the cmdline into the UKI. The roothash thus
#     ends up under measurement (RTMR) — the whole rootfs is bound.
set -euo pipefail

STRATEGY="${1:?Usage: mkroot.sh <strategy> <rootfs-dir> <output-dir>}"
ROOTFS_DIR="${2:?Usage: mkroot.sh <strategy> <rootfs-dir> <output-dir>}"
OUT="${3:?Usage: mkroot.sh <strategy> <rootfs-dir> <output-dir>}"

[ -d "$ROOTFS_DIR" ] || { echo "mkroot: no rootfs at $ROOTFS_DIR"; exit 1; }
mkdir -p "$OUT"

case "$STRATEGY" in
    ext4-label)
        ROOTFS_IMG="$OUT/rootfs.img"
        rm -f "$ROOTFS_IMG"
        ROOTFS_BYTES=$(sudo du -sb "$ROOTFS_DIR" | awk '{print $1}')
        ROOTFS_MB=$(( (ROOTFS_BYTES * 14 / 10 / 1048576 + 63) / 64 * 64 ))
        [ "$ROOTFS_MB" -lt 256 ] && ROOTFS_MB=256
        echo "mkroot[ext4]: partition $ROOTFS_MB MB (contents $((ROOTFS_BYTES / 1048576)) MB)"
        dd if=/dev/zero of="$ROOTFS_IMG" bs=1M count="$ROOTFS_MB" status=none
        sudo mkfs.ext4 -F -L root -d "$ROOTFS_DIR" "$ROOTFS_IMG" 2>&1 | tail -3
        ;;

    dm-verity-squashfs)
        # confer-image-style: read-only squashfs root + dm-verity Merkle
        # tree on a sibling partition. The roothash is what gets bound
        # into the UKI cmdline → measured into RTMR → the whole rootfs
        # is part of the attested image.
        SQFS="$OUT/rootfs.squashfs"
        VERITY="$OUT/rootfs.verity"
        ROOTHASH_FILE="$OUT/roothash.txt"
        rm -f "$SQFS" "$VERITY" "$ROOTHASH_FILE"

        echo "mkroot[verity]: building squashfs from $ROOTFS_DIR"
        # zstd compression: smaller and faster than gzip/xz at boot.
        # -no-fragments -noI -noD: keep block structure regular, helps
        # with reproducibility. -all-root: every file owned by root,
        # since the rootfs is read-only at runtime anyway.
        # -mkfs-time / -all-time 0: clamp timestamps for SOURCE_DATE_EPOCH-
        # equivalent reproducibility. 4K block size to align well with
        # verity's 4K data-block default.
        sudo mksquashfs "$ROOTFS_DIR" "$SQFS" \
            -comp zstd \
            -b 1048576 \
            -no-fragments \
            -all-root \
            -all-time 0 \
            -mkfs-time 0 \
            -no-progress \
            -quiet 2>&1 | tail -5

        SQFS_SIZE=$(stat -c%s "$SQFS")
        echo "mkroot[verity]: squashfs $((SQFS_SIZE / 1048576)) MB"

        # veritysetup format <data> <hash> -> emits a roothash line.
        # --salt=- disables the random salt that veritysetup uses by
        # default; with a salt, every build produces a different
        # roothash even on identical inputs, which kills attestation
        # reproducibility (the goal of this whole strategy). The
        # salt's only purpose is to defeat precomputed Merkle-tree
        # attacks, which aren't part of our threat model — the data
        # is in the public image, not a secret. confer-image gets
        # the same property via mkosi.conf's `Seed=` (UUID seeded
        # everywhere it's plumbed); we get it via no-salt.
        # --data-block-size / --hash-block-size match the kernel
        # default; explicit so the build is stable across host
        # cryptsetup versions.
        echo "mkroot[verity]: computing dm-verity Merkle tree (deterministic, no salt)"
        VERITY_OUT=$(sudo veritysetup format \
            --salt=- \
            --data-block-size=4096 \
            --hash-block-size=4096 \
            "$SQFS" "$VERITY")
        echo "$VERITY_OUT" | sed 's/^/  /'

        ROOTHASH=$(echo "$VERITY_OUT" | awk '/^Root hash:/ { print $3 }')
        if [ -z "$ROOTHASH" ]; then
            echo "mkroot[verity]: FATAL: could not extract Root hash from veritysetup output"
            exit 1
        fi
        echo "$ROOTHASH" > "$ROOTHASH_FILE"
        echo "mkroot[verity]: roothash=$ROOTHASH"

        # Outputs of veritysetup/mksquashfs default to mode 600 root-owned
        # because we're running under sudo. The next pipeline stage
        # (assemble-disk.sh) is unprivileged and just dd's the bytes —
        # make the artifacts readable so the caller doesn't have to
        # also be sudo'd.
        chmod 0644 "$SQFS" "$VERITY" "$ROOTHASH_FILE"
        ;;

    *)
        echo "mkroot: unknown strategy '$STRATEGY'" >&2
        echo "  supported: ext4-label, dm-verity-squashfs" >&2
        exit 1
        ;;
esac
