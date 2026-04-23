#!/bin/sh
# GCP vendor stage. Runs in the initrd after the root-strategy template
# has mounted the new rootfs at $1 (default /mnt/root). Responsibilities:
#
#   1. Load the GCP network driver (gve on c3/c4, virtio_net elsewhere).
#   2. Bring up the first non-lo interface via DHCP (busybox udhcpc),
#      or apply EE_IP/EE_GATEWAY static overrides if seeded from cmdline.
#   3. Fetch the `ee-config` instance attribute and merge it into the
#      newroot's /run/easyenclave/env. Accepted formats: KEY=VALUE per
#      line, or the legacy flat-JSON `{"K":"V",...}` (auto-flattened).
#
# Failures are non-fatal: on a non-GCE host, metadata fetch just returns
# empty and the VM boots with whatever config.json and inherited env
# already provide.

set -u
NEWROOT="${1:-/mnt/root}"
ENV_DIR="$NEWROOT/run/easyenclave"
ENV_FILE="$ENV_DIR/env"
VENDOR_NAME=gcp
mkdir -p "$ENV_DIR"

# shellcheck disable=SC1091
. /init-templates-vendors-lib.sh

for m in gve virtio_net; do
    modprobe "$m" 2>/dev/null || :
done

ip link set lo up 2>/dev/null || :

IFACE=$(ls /sys/class/net 2>/dev/null | grep -v '^lo$' | head -n1 || true)
if [ -z "${IFACE:-}" ]; then
    ee_log "no non-lo interface — skipping network + metadata"
    exit 0
fi

ee_ifup "$IFACE"

URL="http://169.254.169.254/computeMetadata/v1/instance/attributes/ee-config"
ee_log "fetching $URL"
BODY=$(wget -q -T 2 --header="Metadata-Flavor: Google" -O - "$URL" 2>/dev/null || true)
if [ -n "$BODY" ]; then
    ee_append_config "$BODY" || ee_log "metadata merge failed"
else
    ee_log "no ee-config (non-GCE host or attribute unset)"
fi
