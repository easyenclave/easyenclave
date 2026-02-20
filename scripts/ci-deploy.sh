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
AGENT_CLOUD_PROVIDER="${AGENT_CLOUD_PROVIDER:-baremetal}"
AGENT_DATACENTER_AZ="${AGENT_DATACENTER_AZ:-github-runner}"
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

verify_app_version_variant() {
  local app_name="$1"
  local version="$2"
  local node_size="${3:-}"
  local qs=""
  local version_json actual_node_size actual_status attested_node_size

  if [ -n "$node_size" ]; then
    qs="?node_size=$node_size"
  fi

  version_json=$(curl -sf "$CP_URL/api/v1/apps/$app_name/versions/$version$qs")
  actual_node_size=$(echo "$version_json" | jq -r '.node_size // ""')
  actual_status=$(echo "$version_json" | jq -r '.status // ""')

  if [ "$actual_node_size" != "$node_size" ]; then
    echo "::error::Version node_size mismatch for $app_name@$version: expected '$node_size', got '$actual_node_size'"
    return 1
  fi
  if [ "$actual_status" != "attested" ]; then
    echo "::error::Version is not attested for $app_name@$version (node_size='$node_size', status='$actual_status')"
    return 1
  fi

  if [ -n "$node_size" ]; then
    attested_node_size=$(echo "$version_json" | jq -r '.attestation.node_size // ""')
    if [ "$attested_node_size" != "$node_size" ]; then
      echo "::error::Attestation node_size mismatch for $app_name@$version: expected '$node_size', got '$attested_node_size'"
      return 1
    fi
  fi

  # Most app version measurements (digest resolution + signature policy) do not set .mrtd.
  # MRTD is only meaningful for special bootstrap/manual measurement types.

  return 0
}

# deploy_app APP_NAME DESCRIPTION IMAGE TAGS SERVICE_CONFIG [NODE_SIZE]
#   Registers app, publishes version, waits attested, deploys, waits healthy.
#   NODE_SIZE (optional): filter agents by node_size (e.g. "llm").
deploy_app() {
  local app_name="$1" description="$2" image="$3" tags="$4" service_config="$5"
  local node_size="${6:-}"
  local compose_b64 version publish_resp version_id
  local deployed=false http_code detail selected_agent
  local max_attempts

  echo ""
  echo "===== Deploying $app_name ====="

  # Register app (idempotent)
  curl -f -X POST "$CP_URL/api/v1/apps" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"$app_name\", \"description\": \"$description\"${tags:+, \"tags\": $tags}}" \
    2>&1 || echo "App may already exist (ok)"

  # Build compose and publish version
  compose_b64=$(echo "$image" | make_compose "$app_name" | base64 -w 0)
  # Avoid collisions across parallel CI steps and reruns.
  version="bootstrap-$(date -u +%Y%m%d-%H%M%S-%N)"

  echo "Publishing $app_name version $version (node_size=$node_size)..."
  local publish_body="{\"version\": \"$version\", \"compose\": \"$compose_b64\""
  if [ -n "$node_size" ]; then
    publish_body="$publish_body, \"node_size\": \"$node_size\""
  fi
  publish_body="$publish_body}"
  publish_resp=$(curl -sf -X POST "$CP_URL/api/v1/apps/$app_name/versions" \
    -H "Content-Type: application/json" \
    -d "$publish_body")
  version_id=$(echo "$publish_resp" | jq -r '.version_id')
  echo "Published $app_name@$version ($version_id)"

  echo "Waiting for $app_name@$version to be attested..."
  for i in {1..60}; do
    vjson="$(curl -sf "$CP_URL/api/v1/apps/$app_name/versions/$version?node_size=$node_size" 2>/dev/null || echo '{}')"
    vstatus="$(echo "$vjson" | jq -r '.status // ""' 2>/dev/null || true)"
    if [ "$vstatus" = "attested" ]; then
      echo "Version attested: $app_name@$version (node_size='$node_size')"
      break
    fi
    if [ "$vstatus" = "failed" ] || [ "$vstatus" = "rejected" ]; then
      echo "::error::Version measurement failed for $app_name@$version (status=$vstatus)"
      echo "$vjson" | jq -r '.rejection_reason // .detail // empty' || true
      exit 1
    fi
    echo "  status=$vstatus ($i/60); waiting 2s..."
    sleep 2
  done

  verify_app_version_variant "$app_name" "$version" "$node_size"
  echo "Verified app store variant for $app_name@$version (node_size='$node_size')"

  # Find undeployed agent and deploy (retry)
  max_attempts="${DEPLOY_APP_MAX_ATTEMPTS:-}"
  if [ -z "$max_attempts" ]; then
    max_attempts=12
    if [ "$node_size" = "llm" ]; then
      max_attempts=24
    fi
  fi

  for attempt in $(seq 1 "$max_attempts"); do
    local deploy_body
    deploy_body=$(jq -cn \
      --argjson config "$service_config" \
      --arg node_size "$node_size" \
      '{config: $config}
        + (if $node_size != "" then {node_size: $node_size} else {} end)')

    http_code=$(curl -s -o /tmp/deploy_resp.json -w "%{http_code}" \
      -X POST "$CP_URL/api/v1/apps/$app_name/versions/$version/deploy" \
      -H "Content-Type: application/json" \
      -d "$deploy_body")
    detail=$(jq -r '.detail // empty' /tmp/deploy_resp.json 2>/dev/null || true)

    if [ "$http_code" -lt 400 ]; then
      selected_agent=$(jq -r '.agent_id // empty' /tmp/deploy_resp.json 2>/dev/null || true)
      if [ -z "$selected_agent" ]; then
        selected_agent=$(jq -r '.agent_id // empty' < <(curl -sf "$CP_URL/api/v1/deployments/$(jq -r '.deployment_id' /tmp/deploy_resp.json)") 2>/dev/null || true)
      fi
      echo "Deployed $app_name to agent ${selected_agent:-unknown}"
      deployed=true
      break
    fi

    echo "  HTTP $http_code: $detail"
    if [ "$http_code" = "503" ] || echo "$detail" | grep -qi "No eligible agents"; then
      echo "No eligible agents, waiting 30s... ($attempt/$max_attempts)"
      sleep 30
      continue
    fi

    echo "::error::Deploy failed for $app_name@$version"
    exit 1
  done

  if [ "$deployed" != "true" ]; then
    echo "::error::Could not deploy $app_name after $max_attempts attempts"
    echo ""
    echo "=== Candidate agents for node_size='${node_size:-any}' ==="
    curl -sf "$CP_URL/api/v1/agents" 2>/dev/null | jq -r --arg ns "$node_size" \
      '[.agents[] | select(if $ns != "" then .node_size == $ns else true end)
        | {agent_id, node_size, status, health_status, verified, hostname, has_mrtd: (.mrtd != null), has_rtmrs: (.rtmrs != null)}]'
    exit 1
  fi

  # Wait for healthy deployed agent
  echo "Waiting for $app_name to become healthy..."
  local healthy_agents=0
  for i in {1..60}; do
    local agents_json
    agents_json=$(curl -sf "$CP_URL/api/v1/agents" 2>/dev/null || echo '{"agents":[]}')
    healthy_agents="$(echo "$agents_json" | jq -r --arg app "$app_name" '
      [.agents[]
        | select((.deployed_app // "") == $app)
        | select((.health_status // "" | ascii_downcase) == "healthy")
      ] | length
    ')"
    if [ "${healthy_agents:-0}" -gt 0 ]; then
      echo "$app_name is healthy!"
      return 0
    fi
    echo "  Waiting... ($i/60)"
    sleep 5
  done
  echo "::error::$app_name not healthy after 5 minutes"
  echo ""
  echo "=== Debug: deployments (most recent 5 for app=$app_name) ==="
  curl -sf "$CP_URL/api/v1/deployments" 2>/dev/null | jq -r --arg app "$app_name" '
    (.deployments // [])
    | map(select(.app_name == $app))
    | sort_by(.created_at)
    | reverse
    | .[0:5]
  ' || true
  echo ""
  echo "=== Debug: agents summary ==="
  curl -sf "$CP_URL/api/v1/agents" 2>/dev/null | jq -r '
    [.agents[] | {agent_id, status, health_status, verified, node_size, datacenter, hostname, deployed_app, current_deployment_id}]
  ' || true
  echo ""
  echo "=== Debug: agent VM serial logs (last 120 lines each) ==="
  for log in /var/tmp/tdvirsh/console.*.log; do
    [ -f "$log" ] || continue
    echo ""
    echo "--- $log ---"
    tail -120 "$log" || true
  done
  exit 1
}

# Compose generators (read image from stdin)
make_compose() {
  local app_name="$1"
  local image
  read -r image
  printf 'services:\n  %s:\n    image: %s\n    ports:\n      - "8080:8080"\n' "$app_name" "$image"
}

# ===================================================================
# 0. Agent trust material is still required (trusted MRTDs) for agent verification.
# App version measurement is handled directly by the control plane.

# ===================================================================
# 1. Deploy control plane
# ===================================================================
echo "==> Deploying control plane..."
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
# Public URL reachability can lag behind and should not block agent registration.
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
echo "==> Waiting for $TOTAL_AGENTS agents to register and be verified..."
for i in $(seq 1 "$AGENT_VERIFY_WAIT_ATTEMPTS"); do
  AGENTS=$(curl -sf "$CP_URL/api/v1/agents" 2>/dev/null || echo '{"agents":[]}')
  VERIFIED=$(echo "$AGENTS" | jq '[.agents[] | select(.verified == true)] | length')
  TOTAL_SEEN=$(echo "$AGENTS" | jq '[.agents[]] | length')
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
      [.agents[] | {
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

VERIFIED=$(curl -sf "$CP_URL/api/v1/agents" 2>/dev/null | jq '[.agents[] | select(.verified == true)] | length')
if [ "$VERIFIED" -lt "$TOTAL_AGENTS" ]; then
  waited_seconds=$((AGENT_VERIFY_WAIT_ATTEMPTS * AGENT_VERIFY_WAIT_SECONDS))
  echo "::error::Not all agents verified after ${waited_seconds}s ($VERIFIED/$TOTAL_AGENTS)"
  echo "::error::Dumping unverified agents (to surface root cause without VM logs)..."
  curl -sf "$CP_URL/api/v1/agents" 2>/dev/null \
    | jq -r '
      .agents[]
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
