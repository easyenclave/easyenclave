#!/bin/bash
# Set up zram swap and mount /data as swap-backed tmpfs.
# zram compresses pages in TDX-encrypted guest memory — the host sees nothing.
# With lz4 compression, effective capacity is ~2-3x the zram device size.
# Runs as a oneshot systemd service before Docker and the launcher.
set -e

# Get total RAM in KiB
mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)

# zram = 4x RAM. Gives proportional swap at every size:
#   tiny (4G)     → 16G zram
#   standard (16G) → 64G zram
#   llm (128G)    → 512G zram
zram_kb=$((mem_kb * 4))

modprobe zram num_devices=1
echo lz4 > /sys/block/zram0/comp_algorithm
echo "${zram_kb}K" > /sys/block/zram0/disksize
mkswap /dev/zram0
swapon -p 100 /dev/zram0

# tmpfs sized to RAM + zram. With lz4 compression the actual capacity
# is higher, but this is a safe upper bound for the filesystem.
tmpfs_kb=$((mem_kb + zram_kb))
mount -t tmpfs -o "nosuid,nodev,size=${tmpfs_kb}k" tmpfs /data

mkdir -p /data/docker /data/workload /data/easyenclave
