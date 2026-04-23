#!/bin/sh
# Azure vendor stage. Mirrors gcp.sh but targets Azure TDX CVMs:
#
#   1. Hyper-V drivers (hv_vmbus, hv_netvsc, hv_storvsc). Azure TDX VMs
#      present virtual hardware through VMBus, not virtio.
#   2. DHCP (or EE_IP static overrides). Azure's DHCP sends option 121
#      for the IMDS route.
#   3. Fetch customData from IMDS:
#      GET http://169.254.169.254/metadata/instance/compute/customData
#          ?api-version=2021-02-01&format=text
#      Header: Metadata: true
#      Response is a base64-encoded string (the raw bytes supplied at
#      VM create time). We base64-decode and accept KEY=VALUE per line
#      or legacy flat-JSON — same contract as gcp.sh.
#
# Non-fatal on non-Azure hosts. Logs to serial for diagnosis.

set -u
NEWROOT="${1:-/mnt/root}"
ENV_DIR="$NEWROOT/run/easyenclave"
ENV_FILE="$ENV_DIR/env"
VENDOR_NAME=azure
mkdir -p "$ENV_DIR"

# shellcheck disable=SC1091
. /init-templates-vendors-lib.sh

for m in hv_vmbus hv_netvsc hv_storvsc virtio_net; do
    modprobe "$m" 2>/dev/null || :
done

ip link set lo up 2>/dev/null || :

IFACE=$(ls /sys/class/net 2>/dev/null | grep -v '^lo$' | head -n1 || true)
if [ -z "${IFACE:-}" ]; then
    ee_log "no non-lo interface — skipping network + metadata"
    exit 0
fi

ee_ifup "$IFACE"

URL="http://169.254.169.254/metadata/instance/compute/customData?api-version=2021-02-01&format=text"
ee_log "fetching customData from IMDS"
B64=$(wget -q -T 2 --header="Metadata: true" -O - "$URL" 2>/dev/null || true)
# IMDS may return a JSON-quoted string; strip surrounding quotes if present.
B64=${B64#\"}
B64=${B64%\"}
if [ -n "$B64" ]; then
    DECODED=$(printf '%s' "$B64" | base64 -d 2>/dev/null || true)
    if [ -n "$DECODED" ]; then
        ee_append_config "$DECODED" || ee_log "customData merge failed"
    else
        ee_log "customData was not valid base64 — skipping"
    fi
else
    ee_log "no customData (not an Azure VM or customData unset)"
fi
