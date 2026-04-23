#!/bin/bash
# GCP real-TDX integration test.
#
# Spins up an EPHEMERAL GCE TDX CVM from the gcp target artifact,
# asserts the enclave boots + attests + serves a workload, tears it
# down. Completely independent of the gcp-promote job — that one
# publishes the staging/stable image family; this one just verifies
# the build.
#
# Required env:
#   GCP_PROJECT    gcloud project id
#   GCS_BUCKET     bucket to stage the tar.gz in (must be in GCP_PROJECT)
#   SHA12          commit sha12 (for artifact + VM name)
#
# Assumes: gcloud authenticated via the workflow's workload-identity
# binding. Artifacts live under image/output/gcp/ with the sha12 + -gcp
# filename convention the build job establishes.
set -euo pipefail

: "${GCP_PROJECT:?}"
: "${GCS_BUCKET:?}"
: "${SHA12:?}"

ZONE="${GCP_ZONE:-us-central1-c}"
MACHINE_TYPE="${GCP_MACHINE_TYPE:-c3-standard-4}"
TARBALL="easyenclave-${SHA12}-gcp.tar.gz"
GCS_URI="gs://${GCS_BUCKET}/ephemeral-${SHA12}/${TARBALL}"
IMAGE_NAME="ee-smoke-${SHA12}"
VM_NAME="ee-smoke-$(date +%s)"

[ -f "image/output/gcp/${TARBALL}" ] || { echo "missing image/output/gcp/${TARBALL}" >&2; exit 2; }

cleanup() {
    set +e
    echo "smoke:gcp: cleanup"
    gcloud compute instances delete "$VM_NAME" \
        --project="$GCP_PROJECT" --zone="$ZONE" --quiet 2>/dev/null || true
    gcloud compute images delete "$IMAGE_NAME" \
        --project="$GCP_PROJECT" --quiet 2>/dev/null || true
    gsutil -m rm -rf "gs://${GCS_BUCKET}/ephemeral-${SHA12}/" 2>/dev/null || true
}
trap cleanup EXIT

echo "smoke:gcp: stage tar.gz at $GCS_URI"
gcloud storage cp "image/output/gcp/${TARBALL}" "$GCS_URI"

echo "smoke:gcp: create ephemeral image $IMAGE_NAME"
gcloud compute images create "$IMAGE_NAME" \
    --project="$GCP_PROJECT" \
    --source-uri="$GCS_URI" \
    --guest-os-features=UEFI_COMPATIBLE,TDX_CAPABLE,GVNIC \
    --labels=easyenclave=smoke,commit="$SHA12"

# Keep using legacy JSON for ee-config on GCP so the vendor-stage's
# JSON-flatten path gets real-boot coverage. Unit test covers the
# parser; this confirms it works at boot.
cat > /tmp/ee-config.json <<'EECONF'
{
  "EE_OWNER": "ci-smoke",
  "EE_BOOT_WORKLOADS": "[{\"cmd\":[\"sh\",\"-c\",\"echo ok > /tmp/index.html\"],\"app_name\":\"seed\"},{\"cmd\":[\"busybox\",\"httpd\",\"-f\",\"-p\",\"80\",\"-h\",\"/tmp\"],\"app_name\":\"http\"}]"
}
EECONF

gcloud compute firewall-rules describe ee-smoke-allow-http \
    --project="$GCP_PROJECT" >/dev/null 2>&1 || \
gcloud compute firewall-rules create ee-smoke-allow-http \
    --project="$GCP_PROJECT" --allow=tcp:80 \
    --target-tags=ee-smoke-test --source-ranges=0.0.0.0/0 --quiet

echo "smoke:gcp: create TDX VM $VM_NAME"
gcloud compute instances create "$VM_NAME" \
    --project="$GCP_PROJECT" --zone="$ZONE" \
    --machine-type="$MACHINE_TYPE" \
    --confidential-compute-type=TDX --maintenance-policy=TERMINATE \
    --image="$IMAGE_NAME" --image-project="$GCP_PROJECT" \
    --boot-disk-size=10GB \
    --metadata-from-file=ee-config=/tmp/ee-config.json \
    --tags=ee-smoke-test

# Assertions. Fail-fast on fatal patterns that indicate a broken boot.
CHECKS=(
    "pid1|easyenclave: running as PID 1"
    "vendor_merged|vendor:gcp: merged .* config into"
    "attestation_tdx|attestation backend: tdx"
    "listening|easyenclave: listening on"
    "deployment_running|deployment .* running"
)
FATAL_PATTERNS="FATAL|Kernel panic|switch_root: can|Invalid ELF header"

declare -A PASSED
LAST_LINES=0
ALL_DONE=false
for i in $(seq 1 36); do
    out=$(gcloud compute instances get-serial-port-output "$VM_NAME" \
        --project="$GCP_PROJECT" --zone="$ZONE" 2>/dev/null || true)
    TOTAL=$(echo "$out" | wc -l)
    if [ "$TOTAL" -gt "$LAST_LINES" ]; then
        echo "$out" | tail -n +$((LAST_LINES + 1)) | sed 's/^/[serial] /'
        LAST_LINES=$TOTAL
    fi
    if echo "$out" | grep -qE "$FATAL_PATTERNS"; then
        echo "::error::smoke:gcp: fatal pattern in serial"
        break
    fi
    for check in "${CHECKS[@]}"; do
        IFS="|" read -r name pattern <<< "$check"
        [ -n "${PASSED[$name]:-}" ] && continue
        if echo "$out" | grep -qE "$pattern"; then
            PASSED[$name]=1
            echo "smoke:gcp:   ✓ $name"
        fi
    done
    ALL_DONE=true
    for check in "${CHECKS[@]}"; do
        IFS="|" read -r name _pat <<< "$check"
        [ -z "${PASSED[$name]:-}" ] && ALL_DONE=false && break
    done
    $ALL_DONE && break
    echo "smoke:gcp: waiting... ($i/36)"
    sleep 10
done

HTTP_OK=false
if $ALL_DONE; then
    VM_IP=$(gcloud compute instances describe "$VM_NAME" \
        --project="$GCP_PROJECT" --zone="$ZONE" \
        --format='value(networkInterfaces[0].accessConfigs[0].natIP)')
    echo "smoke:gcp: probing http://$VM_IP:80/"
    for i in $(seq 1 12); do
        code=$(curl -sS -o /dev/null -w '%{http_code}' \
            --connect-timeout 5 "http://$VM_IP:80/" 2>/dev/null || echo 000)
        if [ "$code" = "200" ]; then
            echo "smoke:gcp:   ✓ workload_http (200)"
            HTTP_OK=true
            break
        fi
        echo "smoke:gcp: http $code, retrying... ($i/12)"
        sleep 5
    done
fi

echo ""
echo "smoke:gcp: === summary ==="
PASS=0; TOTAL=0
for check in "${CHECKS[@]}"; do
    IFS="|" read -r name _pat <<< "$check"
    TOTAL=$((TOTAL + 1))
    if [ -n "${PASSED[$name]:-}" ]; then
        echo "smoke:gcp:   ✓ $name"; PASS=$((PASS + 1))
    else
        echo "smoke:gcp:   ✗ $name"
    fi
done
TOTAL=$((TOTAL + 1))
if $HTTP_OK; then
    echo "smoke:gcp:   ✓ workload_http"; PASS=$((PASS + 1))
else
    echo "smoke:gcp:   ✗ workload_http"
fi
echo "smoke:gcp: $PASS/$TOTAL passed"

if $ALL_DONE && $HTTP_OK; then
    exit 0
fi
echo "::error::smoke:gcp failed ($PASS/$TOTAL)"
exit 1
