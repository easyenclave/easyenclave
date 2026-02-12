#!/bin/bash
# Set up zram swap and mount /data as swap-backed tmpfs.
# zram compresses pages in TDX-encrypted guest memory — the host sees nothing.
# With lz4 compression, effective capacity is ~2-3x physical RAM.
# Runs as a oneshot systemd service before Docker and the launcher.
set -e

# Get total RAM in KiB
mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)

# Create zram device sized to match RAM (lz4 compressed → ~2-3x effective)
modprobe zram num_devices=1
echo lz4 > /sys/block/zram0/comp_algorithm
echo "${mem_kb}K" > /sys/block/zram0/disksize
mkswap /dev/zram0
swapon -p 100 /dev/zram0

# Mount /data as tmpfs. With zram swap, cold pages get compressed and
# swapped out, so we can safely size it larger than physical RAM.
# Size = 150% of RAM; with swap backing this won't OOM.
tmpfs_kb=$((mem_kb * 3 / 2))
mount -t tmpfs -o "nosuid,nodev,size=${tmpfs_kb}k" tmpfs /data

mkdir -p /data/docker /data/workload /data/easyenclave
