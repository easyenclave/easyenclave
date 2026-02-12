#!/bin/bash
# Set up /data for Docker storage and workloads.
#
# Two modes:
#   1. Data disk present (/dev/vdb): encrypt with ephemeral dm-crypt key,
#      format ext4, mount at /data. The host sees only ciphertext.
#   2. No data disk: fall back to zram swap + tmpfs (all in TDX-encrypted RAM).
#
# Runs as a oneshot systemd service before Docker and the launcher.
set -e

# Get total RAM in KiB
mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)

if [ -b /dev/vdb ]; then
    # ── Mode 1: encrypted data disk ──────────────────────────────────
    # Generate ephemeral key (lives only in TDX-protected guest RAM).
    dd if=/dev/urandom of=/run/data-disk.key bs=32 count=1 2>/dev/null

    # Open dm-crypt on the raw block device
    cryptsetup open --type plain \
        --cipher aes-xts-plain64 --key-size 256 \
        --key-file /run/data-disk.key \
        /dev/vdb data_crypt

    # Shred key file — kernel dm-crypt holds the key internally now
    shred -u /run/data-disk.key

    # Format (fresh dm-crypt device has no filesystem).
    # lazy_itable_init + lazy_journal_init defer inode/journal zeroing to
    # background, cutting 500G format from ~60s to <2s.
    mkfs.ext4 -q -E lazy_itable_init=1,lazy_journal_init=1 -L data /dev/mapper/data_crypt
    mount -o nosuid,nodev /dev/mapper/data_crypt /data

    # No zram needed — Docker storage lives on the data disk, not RAM.
else
    # ── Mode 2: zram + tmpfs (no data disk) ──────────────────────────
    # zram = 4x RAM for proportional swap at every size.
    zram_kb=$((mem_kb * 4))

    modprobe zram num_devices=1
    echo lz4 > /sys/block/zram0/comp_algorithm
    echo "${zram_kb}K" > /sys/block/zram0/disksize
    mkswap /dev/zram0
    swapon -p 100 /dev/zram0

    # Mount /data as tmpfs backed by RAM + zram
    tmpfs_kb=$((mem_kb + zram_kb))
    mount -t tmpfs -o "nosuid,nodev,size=${tmpfs_kb}k" tmpfs /data
fi

mkdir -p /data/docker /data/containerd /data/workload /data/easyenclave
