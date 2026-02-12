#!/bin/bash
# Mount /data from a virtio data disk (/dev/vdb) or fall back to tmpfs.
# When a data disk is present, it is encrypted with dm-crypt using an
# ephemeral key generated in guest memory. The host only sees ciphertext
# on the qcow2 — the key never leaves TDX-protected RAM.
# Runs as a oneshot systemd service before Docker and the launcher.
set -e

if [ -b /dev/vdb ]; then
    # Generate ephemeral encryption key (lives only in TDX-protected guest RAM)
    dd if=/dev/urandom of=/run/data-disk.key bs=32 count=1 2>/dev/null

    # Open dm-crypt on the raw block device
    cryptsetup open --type plain \
        --cipher aes-xts-plain64 --key-size 256 \
        --key-file /run/data-disk.key \
        /dev/vdb data

    # Shred the key file — kernel dm-crypt holds the key internally now
    shred -u /run/data-disk.key

    # Format on first open (fresh dm-crypt device has no filesystem)
    mkfs.ext4 -q -L data /dev/mapper/data
    mount -o nosuid,nodev /dev/mapper/data /data
else
    mount -t tmpfs -o nosuid,nodev,size=1G tmpfs /data
fi

mkdir -p /data/docker /data/workload /data/easyenclave
