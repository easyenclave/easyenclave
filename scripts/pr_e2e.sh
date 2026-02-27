#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

require_cmd cargo
require_cmd docker
require_cmd gcloud
require_cmd curl
require_cmd jq

require_var PR_NUMBER
require_var GCP_PROJECT_ID
require_var GCP_SERVICE_ACCOUNT_KEY
require_var CLOUDFLARE_ACCOUNT_ID
require_var CLOUDFLARE_API_TOKEN
require_var CLOUDFLARE_ZONE_ID
require_var ITA_API_KEY
require_var EE_GCP_SOURCE_IMAGE_FAMILY
require_var EE_GCP_SOURCE_IMAGE_PROJECT

GCP_ZONE="${GCP_ZONE:-us-central1-a}"
GCP_MACHINE_TYPE="${GCP_MACHINE_TYPE:-c3-standard-4}"
EASYENCLAVE_DOMAIN="${EASYENCLAVE_DOMAIN:-easyenclave.com}"
ITA_APPRAISAL_URL="${ITA_APPRAISAL_URL:-https://api.trustauthority.intel.com/appraisal/v2/attest}"
PR_PREFIX="ee-pr-${PR_NUMBER}"
CP_VM_NAME="${PR_PREFIX}-cp"
AGENT_VM_NAME="${PR_PREFIX}-agent"
CP_HOSTNAME="${PR_PREFIX}-cp.weave.${EASYENCLAVE_DOMAIN}"
AGENT_HOSTNAME="${PR_PREFIX}-agent.weave.${EASYENCLAVE_DOMAIN}"
KEEP_PR_RESOURCES="${KEEP_PR_RESOURCES:-false}"

CF_TUNNEL_ID=""
CF_DNS_ID=""

cleanup_runtime_resources() {
  if [ "$KEEP_PR_RESOURCES" = "true" ]; then
    echo "[pr-e2e] KEEP_PR_RESOURCES=true, skipping runtime cleanup"
    return
  fi

  if [ -n "$CF_DNS_ID" ]; then
    curl -fsS -X DELETE \
      -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
      "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records/${CF_DNS_ID}" >/dev/null || true
  fi

  if [ -n "$CF_TUNNEL_ID" ]; then
    curl -fsS -X DELETE \
      -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
      "https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/${CF_TUNNEL_ID}" >/dev/null || true
  fi

  gcloud compute instances delete "$CP_VM_NAME" "$AGENT_VM_NAME" --zone "$GCP_ZONE" --quiet >/dev/null || true
}
trap cleanup_runtime_resources EXIT

wait_for_status() {
  local vm_name="$1"
  local expected="$2"
  local timeout_seconds="${3:-360}"
  local start
  start="$(date +%s)"

  while true; do
    local status
    status="$(gcloud compute instances describe "$vm_name" --zone "$GCP_ZONE" --format='value(status)' 2>/dev/null || true)"
    if [ "$status" = "$expected" ]; then
      return 0
    fi

    if [ $(( $(date +%s) - start )) -ge "$timeout_seconds" ]; then
      echo "timeout waiting for $vm_name to reach status $expected (current=$status)" >&2
      return 1
    fi
    sleep 5
  done
}

wait_for_serial_marker() {
  local vm_name="$1"
  local marker="$2"
  local timeout_seconds="${3:-300}"
  local start
  start="$(date +%s)"

  while true; do
    if gcloud compute instances get-serial-port-output "$vm_name" \
      --zone "$GCP_ZONE" \
      --port 1 \
      --start=0 \
      --format='value(contents)' | grep -q "$marker"; then
      return 0
    fi

    if [ $(( $(date +%s) - start )) -ge "$timeout_seconds" ]; then
      echo "timeout waiting for serial marker $marker on $vm_name" >&2
      return 1
    fi

    sleep 10
  done
}

create_tdx_vm() {
  local vm_name="$1"
  local role="$2"

  local startup
  startup="$(mktemp)"
  cat > "$startup" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
ROLE="$(curl -fsH 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/attributes/ee-role' || echo unknown)"
echo "EE_BOOT_ROLE=${ROLE}" >/dev/ttyS0
if [ -e /sys/kernel/config/tsm/report/quote ] || [ -e /dev/tdx-guest ] || [ -e /dev/tdx_guest ]; then
  echo "EE_TDX_QUOTE_READY=1" >/dev/ttyS0
else
  echo "EE_TDX_QUOTE_READY=0" >/dev/ttyS0
fi
SCRIPT

  gcloud compute instances create "$vm_name" \
    --zone "$GCP_ZONE" \
    --machine-type "$GCP_MACHINE_TYPE" \
    --maintenance-policy TERMINATE \
    --provisioning-model STANDARD \
    --confidential-compute-type TDX \
    --image-family "$EE_GCP_SOURCE_IMAGE_FAMILY" \
    --image-project "$EE_GCP_SOURCE_IMAGE_PROJECT" \
    --metadata "serial-port-enable=true,ee-role=${role}" \
    --metadata-from-file "startup-script=$startup" \
    --labels "eepr=${PR_NUMBER},eerole=${role},eestack=v2" \
    --quiet

  rm -f "$startup"
}

echo "[pr-e2e] validating Rust workspace"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
CP_ALLOW_INSECURE_TEST_OIDC=true CP_ALLOW_INSECURE_TEST_ATTESTATION=true cargo test --workspace

echo "[pr-e2e] building VM image"
image/build.sh

echo "[pr-e2e] authenticating to GCP"
gcloud_auth_with_key_json GCP_SERVICE_ACCOUNT_KEY GCP_PROJECT_ID

echo "[pr-e2e] checking TDX-capable machine type in ${GCP_ZONE}"
gcloud compute machine-types describe "$GCP_MACHINE_TYPE" --zone "$GCP_ZONE" --format='value(name,guestCpus,memoryMb)'

echo "[pr-e2e] creating TDX VMs"
create_tdx_vm "$CP_VM_NAME" cp
create_tdx_vm "$AGENT_VM_NAME" agent

wait_for_status "$CP_VM_NAME" RUNNING
wait_for_status "$AGENT_VM_NAME" RUNNING

echo "[pr-e2e] validating confidential VM type"
for vm in "$CP_VM_NAME" "$AGENT_VM_NAME"; do
  vm_type="$(gcloud compute instances describe "$vm" --zone "$GCP_ZONE" --format='value(confidentialInstanceConfig.confidentialInstanceType)')"
  if [ "$vm_type" != "TDX" ]; then
    echo "instance $vm is not TDX (found: $vm_type)" >&2
    exit 1
  fi
done

echo "[pr-e2e] waiting for serial quote markers"
wait_for_serial_marker "$CP_VM_NAME" "EE_BOOT_ROLE=cp"
wait_for_serial_marker "$AGENT_VM_NAME" "EE_BOOT_ROLE=agent"
wait_for_serial_marker "$AGENT_VM_NAME" "EE_TDX_QUOTE_READY=1"

echo "[pr-e2e] checking Cloudflare tunnel and DNS create/delete flow"
CF_CREATE_RESP="$(curl -fsS -X POST \
  -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data "{\"name\":\"${PR_PREFIX}-agent\",\"config_src\":\"cloudflare\"}" \
  "https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel")"
printf '%s' "$CF_CREATE_RESP" | jq -e '.success == true' >/dev/null
CF_TUNNEL_ID="$(printf '%s' "$CF_CREATE_RESP" | jq -r '.result.id')"

CF_DNS_RESP="$(curl -fsS -X POST \
  -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data "{\"type\":\"CNAME\",\"name\":\"${AGENT_HOSTNAME}\",\"content\":\"${CF_TUNNEL_ID}.cfargotunnel.com\",\"proxied\":true}" \
  "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records")"
printf '%s' "$CF_DNS_RESP" | jq -e '.success == true' >/dev/null
CF_DNS_ID="$(printf '%s' "$CF_DNS_RESP" | jq -r '.result.id')"

echo "[pr-e2e] checking ITA appraisal API access"
ITA_STATUS="$(curl -sS -o /tmp/ita-pr-e2e.json -w '%{http_code}' \
  -X POST \
  -H "x-api-key: ${ITA_API_KEY}" \
  -H 'Content-Type: application/json' \
  --data '{"quote":"invalid"}' \
  "$ITA_APPRAISAL_URL")"
if [ "$ITA_STATUS" = "401" ] || [ "$ITA_STATUS" = "403" ]; then
  echo "ITA API key appears invalid (status=$ITA_STATUS)" >&2
  cat /tmp/ita-pr-e2e.json >&2 || true
  exit 1
fi

echo "[pr-e2e] reserved hostnames for this PR:"
echo "  - ${CP_HOSTNAME}"
echo "  - ${AGENT_HOSTNAME}"

echo "[pr-e2e] completed TDX/CF/ITA lifecycle checks for ${PR_PREFIX}"
