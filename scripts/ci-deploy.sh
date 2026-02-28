#!/usr/bin/env bash
# Deploy control plane, launch agents, and bootstrap apps.
#
# Required env vars:
#   TRUSTED_AGENT_MRTDS  - from ci-reproducibility-check.sh
#   TRUSTED_AGENT_RTMRS  - from ci-reproducibility-check.sh
#   TRUSTED_AGENT_MRTDS_BY_SIZE - from ci-reproducibility-check.sh
#   TRUSTED_AGENT_RTMRS_BY_SIZE - from ci-reproducibility-check.sh
#   ITA_API_KEY          - Intel Trust Authority API key (passed into agent VMs so they can mint ITA tokens)
# NOTE: The control plane now measures app versions itself (digest resolution + optional cosign),
# so we do not deploy or pin "measuring-enclave-*" capacity in CI.
#
# Optional env vars:
#   CP_URL      - control plane URL (default: https://app.easyenclave.com)
#   NUM_TINY_AGENTS    - number of additional tiny agents to launch (default: 1)
#   NUM_STANDARD_AGENTS - number of additional standard agents to launch (default: 0)
#   NUM_LLM_AGENTS     - number of additional LLM-sized agents to launch (default: 0)
#   CP_BOOTSTRAP_SIZES - comma-separated bootstrap measurer sizes for control-plane new (default: tiny)
#   AGENT_DATACENTER - explicit datacenter label override (e.g. baremetal:github-runner-a)
#   AGENT_CLOUD_PROVIDER - provider label if AGENT_DATACENTER is unset (default: baremetal)
#   AGENT_DATACENTER_AZ - availability zone/datacenter shard label (default: github-runner)
#   AGENT_DATACENTER_REGION - optional region label for placement metadata
#   AGENT_VERIFY_WAIT_ATTEMPTS - polling attempts while waiting for agent verification (default: 90)
#   AGENT_VERIFY_WAIT_SECONDS - sleep between verification polls (default: 10)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

CP_URL="${CP_URL:-https://app.easyenclave.com}"
NUM_TINY_AGENTS="${NUM_TINY_AGENTS:-1}"
NUM_STANDARD_AGENTS="${NUM_STANDARD_AGENTS:-0}"
NUM_LLM_AGENTS="${NUM_LLM_AGENTS:-0}"
AGENT_DATACENTER="${AGENT_DATACENTER:-}"
AGENT_CLOUD_PROVIDER="${AGENT_CLOUD_PROVIDER:-gcp}"
AGENT_DATACENTER_AZ="${AGENT_DATACENTER_AZ:-us-central1-f}"
AGENT_DATACENTER_REGION="${AGENT_DATACENTER_REGION:-}"
CP_BOOTSTRAP_SIZES="${CP_BOOTSTRAP_SIZES:-tiny}"
AGENT_VERIFY_WAIT_ATTEMPTS="${AGENT_VERIFY_WAIT_ATTEMPTS:-90}"
AGENT_VERIFY_WAIT_SECONDS="${AGENT_VERIFY_WAIT_SECONDS:-10}"

# ===================================================================
# Helpers
# ===================================================================

load_json_map() {
  local env_name="$1"
  local trusted_key="$2"
  local env_value loaded
  local trusted_file="infra/output/reproducibility/trusted_values.json"

  env_value="${!env_name:-}"
  if [ -n "$env_value" ]; then
    if echo "$env_value" | jq -e 'type == "object"' >/dev/null 2>&1; then
      echo "$env_value"
      return 0
    fi
    echo "::warning::$env_name is not valid JSON object; falling back to $trusted_file"
  fi

  if [ -f "$trusted_file" ]; then
    loaded="$(jq -c --arg key "$trusted_key" '.[$key] // {}' "$trusted_file" 2>/dev/null || echo '{}')"
    if echo "$loaded" | jq -e 'type == "object"' >/dev/null 2>&1; then
      echo "$loaded"
      return 0
    fi
    echo "::warning::Could not parse '$trusted_key' from $trusted_file; continuing with empty map"
  fi

  echo "{}"
}

require_ci_measured_profile() {
  local node_size="$1"
  local mrtds_by_size_json mrtd

  mrtds_by_size_json="$(load_json_map TRUSTED_AGENT_MRTDS_BY_SIZE mrtds_by_size)"
  mrtd="$(echo "$mrtds_by_size_json" | jq -r --arg ns "$node_size" '.[$ns] // ""' 2>/dev/null || echo "")"
  if [ -z "$mrtd" ] || [ "$mrtd" = "null" ]; then
    echo "::error::Missing CI-measured baseline for node_size='$node_size' (TRUSTED_AGENT_MRTDS_BY_SIZE['$node_size'])."
    echo "::error::Fix: run ./scripts/ci-build-measure.sh with MEASURE_SIZES including '$node_size' and pass its mrtds_by_size output into this job."
    exit 1
  fi
}

# ===================================================================
# 0. Agent trust material is still required (trusted MRTDs) for agent verification.
# App version measurement is handled directly by the control plane.

# ===================================================================
# 1. Deploy control plane (GCP-only path)
# ===================================================================
echo "==> Deploying control plane on GCP..."
CP_BOOT_JSON="$(
  python3 infra/tdx_cli.py control-plane new \
    --wait \
    --port 8080 \
    --no-bootstrap-measurers \
    --bootstrap-sizes "$CP_BOOTSTRAP_SIZES"
)"

CP_INTERNAL_URL="$(echo "$CP_BOOT_JSON" | jq -r '.control_plane_url // ""')"
CP_PUBLIC_HOSTNAME="$(echo "$CP_BOOT_JSON" | jq -r '.control_plane_hostname // ""')"
BOOTSTRAP_AGENT_COUNT="$(echo "$CP_BOOT_JSON" | jq -r '(.bootstrap_agents // []) | length' 2>/dev/null || echo 0)"

if [ -z "$CP_INTERNAL_URL" ] || [ "$CP_INTERNAL_URL" = "null" ]; then
  echo "::error::control-plane new did not return control_plane_url"
  echo "$CP_BOOT_JSON" | head -c 5000 || true
  exit 1
fi

if [ -n "$CP_PUBLIC_HOSTNAME" ] && [ "$CP_PUBLIC_HOSTNAME" != "null" ]; then
  # Prefer public hostname when it becomes reachable, but don't block bootstrap on DNS propagation.
  echo "Control plane hostname advertised: https://$CP_PUBLIC_HOSTNAME"
  CP_URL_CANDIDATE="https://$CP_PUBLIC_HOSTNAME"
else
  CP_URL_CANDIDATE=""
fi

# Keep bootstrap traffic on the internal URL for determinism.
# Public hostname can briefly route to a previous control plane during DNS/tunnel cutover.
CP_URL="$CP_INTERNAL_URL"
export CP_URL
CP_PUBLIC_URL=""

# ===================================================================
# 3. Wait for control plane to answer health (internal URL)
# ===================================================================
echo "==> Waiting for control plane health at $CP_URL ..."
for _i in {1..30}; do
  if curl -sf "$CP_URL/health" > /dev/null 2>&1; then
    echo "Control plane is up"
    break
  fi
  sleep 10
done
if ! curl -sf "$CP_URL/health" > /dev/null 2>&1; then
  echo "::error::Control plane not ready after 5 minutes"
  exit 1
fi

# Best-effort: wait briefly for the public URL (Cloudflare) to become reachable.
if [ -n "${CP_URL_CANDIDATE:-}" ]; then
  echo "==> Waiting briefly for public URL $CP_URL_CANDIDATE ..."
  for _i in {1..30}; do
    if curl -sf "$CP_URL_CANDIDATE/health" > /dev/null 2>&1; then
      echo "Public URL is up: $CP_URL_CANDIDATE"
      CP_PUBLIC_URL="$CP_URL_CANDIDATE"
      export CP_PUBLIC_URL
      break
    fi
    sleep 2
  done
fi

# Export URLs for callers (reusable workflow outputs).
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "cp_internal_url=$CP_INTERNAL_URL"
    echo "cp_public_url=$CP_PUBLIC_URL"
    if [ -n "${CP_PUBLIC_URL:-}" ]; then
      echo "cp_url=$CP_PUBLIC_URL"
    else
      echo "cp_url=$CP_INTERNAL_URL"
    fi
  } >> "$GITHUB_OUTPUT"
fi

echo "Agent registration URL: $CP_URL"

# Get admin password (from env or auto-generated by control plane)
# (No admin login required for CI: app version measurement is performed by the control plane itself.)

# ===================================================================
# 4. Launch additional agents in parallel
# ===================================================================
if ! [[ "$BOOTSTRAP_AGENT_COUNT" =~ ^[0-9]+$ ]]; then
  BOOTSTRAP_AGENT_COUNT=0
fi

TOTAL_ADDITIONAL_AGENTS=$((NUM_TINY_AGENTS + NUM_STANDARD_AGENTS + NUM_LLM_AGENTS))
TOTAL_AGENTS=$((BOOTSTRAP_AGENT_COUNT + TOTAL_ADDITIONAL_AGENTS))
if [ "$TOTAL_AGENTS" -le 0 ]; then
  echo "::error::No agents available (bootstrap=0 and additional requested=0)"
  exit 1
fi
if [ "$TOTAL_ADDITIONAL_AGENTS" -gt 0 ] && [ -z "${ITA_API_KEY:-}" ] && [ -z "${INTEL_API_KEY:-}" ]; then
  echo "::error::Missing ITA_API_KEY (Intel Trust Authority API key). Agents must mint ITA tokens for registration."
  exit 1
fi
echo "Bootstrap agents already launched by control-plane new: $BOOTSTRAP_AGENT_COUNT"
echo "==> Launching $TOTAL_ADDITIONAL_AGENTS additional agents ($NUM_TINY_AGENTS tiny, $NUM_STANDARD_AGENTS standard, $NUM_LLM_AGENTS LLM)..."

AGENT_LOCATION_ARGS=()
if [ -n "$AGENT_DATACENTER" ]; then
  AGENT_LOCATION_ARGS+=(--datacenter "$AGENT_DATACENTER")
  echo "Using explicit agent datacenter label: $AGENT_DATACENTER"
else
  AGENT_LOCATION_ARGS+=(--cloud-provider "$AGENT_CLOUD_PROVIDER")
  if [ -n "$AGENT_DATACENTER_AZ" ]; then
    AGENT_LOCATION_ARGS+=(--availability-zone "$AGENT_DATACENTER_AZ")
  fi
  if [ -n "$AGENT_DATACENTER_REGION" ]; then
    AGENT_LOCATION_ARGS+=(--region "$AGENT_DATACENTER_REGION")
  fi
  echo "Using agent placement metadata: provider=$AGENT_CLOUD_PROVIDER az=$AGENT_DATACENTER_AZ region=${AGENT_DATACENTER_REGION:-none}"
fi

if [ "$TOTAL_ADDITIONAL_AGENTS" -gt 0 ]; then
  for _i in $(seq 1 "$NUM_TINY_AGENTS"); do
    python3 infra/tdx_cli.py vm new --size tiny \
      "${AGENT_LOCATION_ARGS[@]}" \
      --easyenclave-url "$CP_URL" \
      --intel-api-key "${ITA_API_KEY:-${INTEL_API_KEY:-}}" \
      --wait &
  done
  for _i in $(seq 1 "$NUM_STANDARD_AGENTS"); do
    python3 infra/tdx_cli.py vm new --size standard \
      "${AGENT_LOCATION_ARGS[@]}" \
      --easyenclave-url "$CP_URL" \
      --intel-api-key "${ITA_API_KEY:-${INTEL_API_KEY:-}}" \
      --wait &
  done
  for _i in $(seq 1 "$NUM_LLM_AGENTS"); do
    python3 infra/tdx_cli.py vm new --size llm \
      "${AGENT_LOCATION_ARGS[@]}" \
      --easyenclave-url "$CP_URL" \
      --intel-api-key "${ITA_API_KEY:-${INTEL_API_KEY:-}}" \
      --wait &
  done
fi

# TODO(azure): re-enable Azure-labeled agent launch once Azure confidential VM reliability is fixed.
wait
echo "Additional agent launches complete; expected verified total: $TOTAL_AGENTS"

# ===================================================================
# 5. Wait for agents to register and verify
# ===================================================================
agents_to_array() {
  jq -c 'if type == "array" then . else (.agents // []) end'
}

echo "==> Waiting for $TOTAL_AGENTS agents to register and be verified..."
for i in $(seq 1 "$AGENT_VERIFY_WAIT_ATTEMPTS"); do
  AGENTS_RAW=$(curl -sf "$CP_URL/api/v1/agents" 2>/dev/null || echo '{"agents":[]}')
  AGENTS="$(echo "$AGENTS_RAW" | agents_to_array)"
  VERIFIED=$(echo "$AGENTS" | jq '[.[] | select(.verified == true)] | length')
  TOTAL_SEEN=$(echo "$AGENTS" | jq 'length')
  if [ "$VERIFIED" -ge "$TOTAL_AGENTS" ]; then
    echo "All $TOTAL_AGENTS agents verified"
    break
  elif [ "$VERIFIED" -ge $((TOTAL_AGENTS - 1)) ]; then
    echo "Warning: only $VERIFIED/$TOTAL_AGENTS agents verified"
  fi
  echo "$VERIFIED/$TOTAL_AGENTS agents verified ($TOTAL_SEEN seen), waiting... ($i/$AGENT_VERIFY_WAIT_ATTEMPTS)"
  if [ $((i % 6)) -eq 0 ]; then
    echo "  Agent snapshot:"
    echo "$AGENTS" | jq -r '
      [.[] | {
        agent_id,
        vm_name,
        node_size,
        status,
        health_status,
        verified,
        datacenter,
        verification_error
      }]' || true
  fi
  sleep "$AGENT_VERIFY_WAIT_SECONDS"
done

VERIFIED="$(curl -sf "$CP_URL/api/v1/agents" 2>/dev/null | agents_to_array | jq '[.[] | select(.verified == true)] | length')"
if [ "$VERIFIED" -lt "$TOTAL_AGENTS" ]; then
  waited_seconds=$((AGENT_VERIFY_WAIT_ATTEMPTS * AGENT_VERIFY_WAIT_SECONDS))
  echo "::error::Not all agents verified after ${waited_seconds}s ($VERIFIED/$TOTAL_AGENTS)"
  echo "::error::Dumping unverified agents (to surface root cause without VM logs)..."
  curl -sf "$CP_URL/api/v1/agents" 2>/dev/null \
    | agents_to_array \
    | jq -r '
      .[]
      | select(.verified != true)
      | "agent_id=\(.agent_id) vm=\(.vm_name) status=\(.status) health=\(.health_status) size=\(.node_size) dc=\(.datacenter) err=\(.verification_error // \"\")"
    ' 2>/dev/null \
    | head -n 30 \
    | while IFS= read -r line; do
        [ -n "$line" ] || continue
        echo "::error::$line"
      done
  echo ""
  echo "=== Agent VM serial logs (last 80 lines each) ==="
  for log in /var/tmp/tdvirsh/console.*.log; do
    [ -f "$log" ] || continue
    echo ""
    echo "--- $log ---"
    tail -80 "$log"
  done
  echo ""
  echo "=== Control plane container logs ==="
  curl -sf "$CP_URL/api/v1/logs/control-plane?limit=50" 2>/dev/null | jq -r '.logs[]?.message' || true
  exit 1
fi

echo "==> Deploy complete! (No measuring-enclave bootstrap; CP measures versions directly.)"
