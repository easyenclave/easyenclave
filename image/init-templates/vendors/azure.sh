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

# Azure exposes boot-time config through TWO IMDS endpoints:
#   - /metadata/instance/compute/customData (set via --custom-data;
#     traditional path, requires waagent to land in some scenarios)
#   - /metadata/instance/compute/userData (set via --user-data; newer,
#     agent-independent, always in IMDS)
# Empirically on CVMs without waagent, customData can return empty even
# when passed on vm create — userData is more reliable. Try userData
# first; fall back to customData so existing deployments still work.
try_imds_blob() {
    path="$1"; version="$2"
    wget -q -T 2 --header="Metadata: true" -O - \
        "http://169.254.169.254/metadata/instance/compute/${path}?api-version=${version}&format=text" 2>/dev/null || true
}

B64=$(try_imds_blob userData 2021-01-01)
SRC=userData
if [ -z "$B64" ]; then
    B64=$(try_imds_blob customData 2021-02-01)
    SRC=customData
fi
B64=${B64#\"}; B64=${B64%\"}

ee_log "fetch from IMDS: source=$SRC ${B64:+(${#B64} b64 chars)}"
if [ -n "$B64" ]; then
    DECODED=$(printf '%s' "$B64" | base64 -d 2>/dev/null || true)
    if [ -n "$DECODED" ]; then
        ee_append_config "$DECODED" || ee_log "merge from $SRC failed"
    else
        ee_log "$SRC was not valid base64 — skipping"
    fi
else
    ee_log "no userData or customData (not an Azure VM, or neither was set on vm create)"
fi
