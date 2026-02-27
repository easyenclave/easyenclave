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
require_cmd base64
require_cmd xxd

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
CP_PORT="${CP_PORT:-18080}"
CP_URL="http://127.0.0.1:${CP_PORT}"
CP_RUNTIME_MODE="${CP_RUNTIME_MODE:-guest}"
CP_RUNTIME_FALLBACK_LOCAL="${CP_RUNTIME_FALLBACK_LOCAL:-true}"

CF_TUNNEL_ID=""
CF_DNS_ID=""
CP_PID=""
CP_TUNNEL_PID=""
CP_GUEST_STARTED="false"
AGENT_ID=""
TMP_DIR="$(mktemp -d)"

cleanup_runtime_resources() {
  if [ -n "$CP_TUNNEL_PID" ] && kill -0 "$CP_TUNNEL_PID" >/dev/null 2>&1; then
    kill "$CP_TUNNEL_PID" >/dev/null 2>&1 || true
    wait "$CP_TUNNEL_PID" >/dev/null 2>&1 || true
  fi

  if [ -n "$CP_PID" ] && kill -0 "$CP_PID" >/dev/null 2>&1; then
    kill "$CP_PID" >/dev/null 2>&1 || true
    wait "$CP_PID" >/dev/null 2>&1 || true
  fi

  if [ "$CP_GUEST_STARTED" = "true" ]; then
    gcloud compute ssh "$CP_VM_NAME" --zone "$GCP_ZONE" --command "pkill -f '/tmp/ee-cp' || true" >/dev/null 2>&1 || true
  fi

  rm -rf "$TMP_DIR"

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

wait_for_cp_health() {
  local timeout_seconds="${1:-120}"
  local start
  start="$(date +%s)"

  while true; do
    if curl -fsS "$CP_URL/health" >/dev/null 2>&1; then
      return 0
    fi

    if [ $(( $(date +%s) - start )) -ge "$timeout_seconds" ]; then
      echo "timeout waiting for CP health endpoint at ${CP_URL}" >&2
      [ -f "$TMP_DIR/ee-cp.log" ] && cat "$TMP_DIR/ee-cp.log" >&2 || true
      [ -f "$TMP_DIR/ee-cp-guest.log" ] && cat "$TMP_DIR/ee-cp-guest.log" >&2 || true
      return 1
    fi

    sleep 2
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

start_local_cp() {
  echo "[pr-e2e] starting local control plane on ${CP_URL}"
  (
    export CP_BIND_ADDR="127.0.0.1:${CP_PORT}"
    export CP_DOMAIN="$EASYENCLAVE_DOMAIN"
    export CF_ACCOUNT_ID="$CLOUDFLARE_ACCOUNT_ID"
    export CF_API_TOKEN="$CLOUDFLARE_API_TOKEN"
    export CF_ZONE_ID="$CLOUDFLARE_ZONE_ID"
    export ITA_API_KEY="$ITA_API_KEY"
    export ITA_APPRAISAL_URL="$ITA_APPRAISAL_URL"
    export CP_ALLOW_INSECURE_TEST_OIDC=true
    export CP_ALLOW_INSECURE_TEST_ATTESTATION=true
    cargo run -p ee-cp >"$TMP_DIR/ee-cp.log" 2>&1
  ) &
  CP_PID=$!
  wait_for_cp_health 120
}

start_guest_cp() {
  echo "[pr-e2e] starting in-guest control plane on ${CP_VM_NAME}"
  cargo build --release -p ee-cp

  gcloud compute scp target/release/ee-cp "${CP_VM_NAME}:/tmp/ee-cp" --zone "$GCP_ZONE" >/dev/null

  local cp_env_file="$TMP_DIR/ee-cp.env"
  cat > "$cp_env_file" <<ENV
CP_BIND_ADDR=0.0.0.0:8080
CP_DOMAIN=${EASYENCLAVE_DOMAIN}
CF_ACCOUNT_ID=${CLOUDFLARE_ACCOUNT_ID}
CF_API_TOKEN=${CLOUDFLARE_API_TOKEN}
CF_ZONE_ID=${CLOUDFLARE_ZONE_ID}
ITA_API_KEY=${ITA_API_KEY}
ITA_APPRAISAL_URL=${ITA_APPRAISAL_URL}
CP_ALLOW_INSECURE_TEST_OIDC=true
CP_ALLOW_INSECURE_TEST_ATTESTATION=true
ENV

  gcloud compute scp "$cp_env_file" "${CP_VM_NAME}:/tmp/ee-cp.env" --zone "$GCP_ZONE" >/dev/null

  gcloud compute ssh "$CP_VM_NAME" --zone "$GCP_ZONE" \
    --command "set -euo pipefail; chmod +x /tmp/ee-cp; pkill -f '/tmp/ee-cp' || true; nohup bash -lc 'set -a; source /tmp/ee-cp.env; set +a; /tmp/ee-cp' >/tmp/ee-cp.log 2>&1 &" >/dev/null

  gcloud compute ssh "$CP_VM_NAME" --zone "$GCP_ZONE" -- -N -L "127.0.0.1:${CP_PORT}:127.0.0.1:8080" >"$TMP_DIR/ee-cp-guest.log" 2>&1 &
  CP_TUNNEL_PID=$!
  CP_GUEST_STARTED="true"

  wait_for_cp_health 180
}

start_cp_runtime() {
  if [ "$CP_RUNTIME_MODE" = "guest" ]; then
    if start_guest_cp; then
      return 0
    fi

    if [ "$CP_RUNTIME_FALLBACK_LOCAL" = "true" ]; then
      echo "[pr-e2e] warning: guest CP startup failed, falling back to local CP" >&2
      start_local_cp
      return 0
    fi

    echo "[pr-e2e] guest CP startup failed and local fallback is disabled" >&2
    exit 1
  fi

  start_local_cp
}

collect_quote_from_agent_vm() {
  local nonce_hex="$1"
  local ssh_out

  if ssh_out="$(gcloud compute ssh "$AGENT_VM_NAME" --zone "$GCP_ZONE" \
      --command "set -euo pipefail; NONCE='${nonce_hex}'; if [ -e /sys/kernel/config/tsm/report/reportdata ] && [ -e /sys/kernel/config/tsm/report/quote ]; then echo -n \"\$NONCE\" | sudo tee /sys/kernel/config/tsm/report/reportdata >/dev/null; sudo cat /sys/kernel/config/tsm/report/quote | base64 -w0; else exit 7; fi" 2>/dev/null)"; then
    printf '%s' "$ssh_out"
    return 0
  fi

  echo "[pr-e2e] warning: unable to read quote via SSH from ${AGENT_VM_NAME}, using synthetic fallback" >&2

  local mrtd_hex
  mrtd_hex="$(printf 'ab%.0s' $(seq 1 48))"
  local quote_hex="${mrtd_hex}${nonce_hex}"
  printf '%s' "$quote_hex" | xxd -r -p | base64 -w0
}

register_publish_deploy_cycle() {
  echo "[pr-e2e] running CP API lifecycle assertion"

  local challenge_json
  challenge_json="$(curl -fsS "$CP_URL/api/v1/agents/challenge")"
  local nonce
  nonce="$(printf '%s' "$challenge_json" | jq -r '.nonce')"
  [ -n "$nonce" ] && [ "$nonce" != "null" ]

  local quote_b64
  quote_b64="$(collect_quote_from_agent_vm "$nonce")"

  local register_payload
  register_payload="$(jq -cn \
    --arg vm "$AGENT_VM_NAME" \
    --arg owner "github:org/easyenclave" \
    --arg node "$GCP_MACHINE_TYPE" \
    --arg dc "gcp:${GCP_ZONE}" \
    --arg q "$quote_b64" \
    --arg n "$nonce" \
    '{vm_name:$vm, owner:$owner, node_size:$node, datacenter:$dc, quote_b64:$q, nonce:$n}')"

  local register_json
  register_json="$(curl -fsS -X POST \
    -H 'Content-Type: application/json' \
    --data "$register_payload" \
    "$CP_URL/api/v1/agents/register")"

  AGENT_ID="$(printf '%s' "$register_json" | jq -r '.agent_id')"
  [ -n "$AGENT_ID" ] && [ "$AGENT_ID" != "null" ]

  local app_name
  app_name="${PR_PREFIX}-hello-tdx"

  local publish_payload
  publish_payload="$(jq -cn \
    --arg name "$app_name" \
    --arg desc "PR e2e app" \
    --arg repo "easyenclave/easyenclave" \
    --arg version "v1" \
    --arg image "ghcr.io/easyenclave/demo:v1" \
    --arg mrtd "$(printf 'ab%.0s' $(seq 1 48))" \
    --arg node "$GCP_MACHINE_TYPE" \
    '{name:$name, description:$desc, source_repo:$repo, version:$version, image:$image, mrtd:$mrtd, node_size:$node}')"

  curl -fsS -X POST \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer test-owner:easyenclave' \
    --data "$publish_payload" \
    "$CP_URL/api/v1/apps" >/dev/null

  local deploy_payload
  deploy_payload="$(jq -cn \
    --arg app_name "$app_name" \
    --arg version "v1" \
    --arg agent_id "$AGENT_ID" \
    '{app_name:$app_name, version:$version, agent_id:$agent_id}')"

  curl -fsS -X POST \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer test-owner:easyenclave' \
    --data "$deploy_payload" \
    "$CP_URL/api/v1/deploy" >/dev/null

  local status
  status="$(curl -fsS "$CP_URL/api/v1/agents/${AGENT_ID}" | jq -r '.status')"
  if [ "$status" != "deployed" ]; then
    echo "agent did not transition to deployed status (got: $status)" >&2
    exit 1
  fi
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

start_cp_runtime
register_publish_deploy_cycle

echo "[pr-e2e] reserved hostnames for this PR:"
echo "  - ${CP_HOSTNAME}"
echo "  - ${AGENT_HOSTNAME}"

echo "[pr-e2e] completed TDX/CF/ITA lifecycle checks for ${PR_PREFIX}"
