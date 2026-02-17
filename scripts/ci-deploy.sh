#!/usr/bin/env bash
# Deploy control plane, launch agents, and bootstrap apps.
#
# Required env vars:
#   TRUSTED_AGENT_MRTDS  - from ci-reproducibility-check.sh
#   TRUSTED_AGENT_RTMRS  - from ci-reproducibility-check.sh
#   TRUSTED_AGENT_MRTDS_BY_SIZE - from ci-reproducibility-check.sh
#   TRUSTED_AGENT_RTMRS_BY_SIZE - from ci-reproducibility-check.sh
#   ITA_API_KEY          - Intel Trust Authority key (used by the control plane for CP-mint)
#   MEASURER_IMAGE       - ghcr.io image ref for measuring enclave
#
# Optional env vars:
#   CP_URL      - control plane URL (default: https://app.easyenclave.com)
#   NUM_TINY_AGENTS    - number of additional tiny agents to launch (default: 1)
#   NUM_STANDARD_AGENTS - number of additional standard agents to launch (default: 0)
#   NUM_LLM_AGENTS     - number of additional LLM-sized agents to launch (default: 0)
#   CP_BOOTSTRAP_SIZES - comma-separated bootstrap measurer sizes for control-plane new (default: tiny)
#   ADMIN_PASSWORD - admin password (auto-detected from CP logs if not set)
#   AGENT_DATACENTER - explicit datacenter label override (e.g. baremetal:github-runner-a)
#   AGENT_CLOUD_PROVIDER - provider label if AGENT_DATACENTER is unset (default: baremetal)
#   AGENT_DATACENTER_AZ - availability zone/datacenter shard label (default: github-runner)
#   AGENT_DATACENTER_REGION - optional region label for placement metadata
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
ALLOW_AGENT_REFERENCE_BOOTSTRAP="${ALLOW_AGENT_REFERENCE_BOOTSTRAP:-false}"
CP_BOOTSTRAP_SIZES="${CP_BOOTSTRAP_SIZES:-tiny}"

# ===================================================================
# Helpers
# ===================================================================

admin_login() {
  local resp token
  echo "Logging in to admin panel..." >&2
  resp=$(curl -sf -w "\nHTTP_CODE:%{http_code}" "$CP_URL/admin/login" \
    -H "Content-Type: application/json" \
    -d "{\"password\": \"$ADMIN_PASSWORD\"}")
  token=$(echo "$resp" | grep -v "HTTP_CODE:" | jq -r '.token')
  if [ -z "$token" ] || [ "$token" = "null" ]; then
    echo "Admin login failed" >&2
    echo "$resp" >&2
    exit 1
  fi
  echo "Admin login successful" >&2
  echo "$token"
}

find_reference_agent_measurement() {
  local node_size="$1"
  local attempts="${2:-30}"
  local delay_seconds="${3:-10}"
  local agents_json candidate

  for attempt in $(seq 1 "$attempts"); do
    agents_json=$(curl -sf "$CP_URL/api/v1/agents" 2>/dev/null || echo '{"agents":[]}')
    candidate=$(echo "$agents_json" | jq -c --arg ns "$node_size" '
      [.agents[] | select(.verified == true
        and (if $ns != "" then .node_size == $ns else true end))
      ] | first')

    if [ -n "$candidate" ] && [ "$candidate" != "null" ]; then
      echo "$candidate"
      return 0
    fi

    echo "Waiting for measurement reference (node_size=${node_size:-any})... ($attempt/$attempts)"
    sleep "$delay_seconds"
  done

  return 1
}

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
  local require_mrtd="${4:-false}"
  local qs=""
  local version_json actual_node_size actual_status attested_node_size measured_mrtd

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

  if [ "$require_mrtd" = "true" ]; then
    measured_mrtd=$(echo "$version_json" | jq -r '.mrtd // ""')
    if [ -z "$measured_mrtd" ] || [ "$measured_mrtd" = "null" ]; then
      echo "::error::Missing MRTD for $app_name@$version (node_size='$node_size')"
      return 1
    fi
  fi

  return 0
}

# deploy_app APP_NAME DESCRIPTION IMAGE TAGS SERVICE_CONFIG [NODE_SIZE]
#   Registers app, publishes version, attests, deploys, waits healthy.
#   NODE_SIZE (optional): filter agents by node_size (e.g. "llm").
deploy_app() {
  local app_name="$1" description="$2" image="$3" tags="$4" service_config="$5"
  local node_size="${6:-}"
  local compose_b64 version publish_resp version_id
  local deployed=false http_code detail selected_agent
  local manual_attest_body="" reference_agent reference_agent_id reference_mrtd reference_rtmrs
  local measured_profile_mrtd="" measured_profile_rtmrs="null"
  local attestation_detail
  local reference_measurement measured_at attest_qs="" max_attempts require_mrtd

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

  # Manual attest (bootstrap) with node-size-specific measurement metadata when available.
  if [ -n "$node_size" ]; then
    local mrtds_by_size_json rtmrs_by_size_json
    mrtds_by_size_json="$(load_json_map TRUSTED_AGENT_MRTDS_BY_SIZE mrtds_by_size)"
    rtmrs_by_size_json="$(load_json_map TRUSTED_AGENT_RTMRS_BY_SIZE rtmrs_by_size)"

    if ! measured_profile_mrtd="$(echo "$mrtds_by_size_json" | jq -r --arg ns "$node_size" '.[$ns] // ""' 2>/dev/null)"; then
      echo "::warning::Failed to read MRTD profile for node_size='$node_size'; ignoring CI measured profile map"
      measured_profile_mrtd=""
    fi
    if ! measured_profile_rtmrs="$(echo "$rtmrs_by_size_json" | jq -c --arg ns "$node_size" '.[$ns] // null' 2>/dev/null)"; then
      echo "::warning::Failed to read RTMR profile for node_size='$node_size'; ignoring CI measured profile map"
      measured_profile_rtmrs="null"
    fi

    if [ -n "$measured_profile_mrtd" ]; then
      measured_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
      reference_measurement=$(jq -cn \
        --arg ns "$node_size" \
        --arg mrtd "$measured_profile_mrtd" \
        --arg measured_at "$measured_at" \
        --argjson rtmrs "$measured_profile_rtmrs" \
        '{bootstrap: true, measurement_type: "ci_measured_profile", node_size: $ns, mrtd: $mrtd, rtmrs: $rtmrs, measured_at: $measured_at}')
      manual_attest_body=$(jq -cn \
        --arg mrtd "$measured_profile_mrtd" \
        --argjson attestation "$reference_measurement" \
        '{mrtd: $mrtd, attestation: $attestation}')
      echo "Using CI measured profile for $node_size bootstrap measurement"
    else
      if [ "$ALLOW_AGENT_REFERENCE_BOOTSTRAP" != "true" ]; then
        echo "::error::Missing CI-measured baseline for node_size='$node_size' (needed to bootstrap $app_name)."
        echo "::error::Fix: ensure ./scripts/ci-build-measure.sh ran with MEASURE_SIZES including '$node_size' and that TRUSTED_AGENT_MRTDS_BY_SIZE/TRUSTED_AGENT_RTMRS_BY_SIZE are passed into this job."
        echo "::error::If you intentionally want to bootstrap from a live agent's attestation (less deterministic), set ALLOW_AGENT_REFERENCE_BOOTSTRAP=true."
        exit 1
      fi

      echo "::warning::CI measured profile missing for '$node_size'; bootstrapping from a verified agent reference (ALLOW_AGENT_REFERENCE_BOOTSTRAP=true)"
      reference_agent=$(find_reference_agent_measurement "$node_size" 30 10) || {
        echo "::error::Could not find verified '$node_size' agent with MRTD/RTMRs for $app_name"
        exit 1
      }
      reference_agent_id=$(echo "$reference_agent" | jq -r '.agent_id')
      reference_mrtd=$(echo "$reference_agent" | jq -r '.mrtd')
      reference_rtmrs=$(echo "$reference_agent" | jq -c '.rtmrs')

      if [ -z "$reference_mrtd" ] || [ "$reference_mrtd" = "null" ] || [ "$reference_rtmrs" = "null" ]; then
        attestation_detail=$(curl -sf "$CP_URL/api/v1/agents/$reference_agent_id/attestation" 2>/dev/null || echo '{}')
        if [ -z "$reference_mrtd" ] || [ "$reference_mrtd" = "null" ]; then
          reference_mrtd=$(echo "$attestation_detail" | jq -r '.mrtd // ""')
        fi
        if [ "$reference_rtmrs" = "null" ]; then
          reference_rtmrs=$(echo "$attestation_detail" | jq -c '.rtmrs // null')
        fi
      fi

      if [ -z "$reference_mrtd" ] || [ "$reference_mrtd" = "null" ]; then
        echo "::error::Reference agent $reference_agent_id has no MRTD for node_size='$node_size'"
        exit 1
      fi

      measured_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
      reference_measurement=$(jq -cn \
        --arg ns "$node_size" \
        --arg aid "$reference_agent_id" \
        --arg mrtd "$reference_mrtd" \
        --arg measured_at "$measured_at" \
        --argjson rtmrs "${reference_rtmrs:-null}" \
        '{bootstrap: true, measurement_type: "agent_reference", node_size: $ns, agent_id: $aid, mrtd: $mrtd, rtmrs: $rtmrs, measured_at: $measured_at}')
      manual_attest_body=$(jq -cn \
        --arg mrtd "$reference_mrtd" \
        --argjson attestation "$reference_measurement" \
        '{mrtd: $mrtd, attestation: $attestation}')
      echo "Using reference agent $reference_agent_id for $node_size bootstrap measurement"
    fi
    attest_qs="?node_size=$node_size"
  fi

  echo "Manually attesting $app_name version $version (node_size=$node_size)..."
  if [ -n "$manual_attest_body" ]; then
    curl -sf -X POST "$CP_URL/api/v1/apps/$app_name/versions/$version/attest${attest_qs}" \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d "$manual_attest_body"
  else
    curl -sf -X POST "$CP_URL/api/v1/apps/$app_name/versions/$version/attest${attest_qs}" \
      -H "Authorization: Bearer $ADMIN_TOKEN"
  fi
  echo "Attested $app_name@$version"

  require_mrtd=false
  if [ -n "$node_size" ]; then
    require_mrtd=true
  fi
  verify_app_version_variant "$app_name" "$version" "$node_size" "$require_mrtd"
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

  # Wait for healthy
  echo "Waiting for $app_name to become healthy..."
  local healthy=0
  for i in {1..60}; do
    local svc
    svc=$(curl -sf "$CP_URL/api/v1/services?name=$app_name" 2>/dev/null || echo '{"services":[]}')
    healthy=$(echo "$svc" | jq '[.services[] | select(.health_status == "healthy")] | length')
    if [ "$healthy" -gt 0 ]; then
      echo "$app_name is healthy!"
      return 0
    fi
    echo "  Waiting... ($i/60)"
    sleep 5
  done
  echo "::error::$app_name not healthy after 5 minutes"
  echo ""
  echo "=== Debug: services?name=$app_name ==="
  curl -sf "$CP_URL/api/v1/services?name=$app_name" 2>/dev/null | jq . || true
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
  case "$app_name" in
    measuring-enclave*)
      printf 'services:\n  measuring-enclave:\n    image: %s\n    ports:\n      - "8080:8080"\n' "$image"
      ;;
    *)
      printf 'services:\n  %s:\n    image: %s\n    ports:\n      - "8080:8080"\n' "$app_name" "$image"
      ;;
  esac
}

# ===================================================================
# 0. Validate required size-aware trust material to avoid slow retry loops
# ===================================================================
require_ci_measured_profile "tiny"
if [ "$NUM_STANDARD_AGENTS" -gt 0 ]; then
  require_ci_measured_profile "standard"
fi
if [ "$NUM_LLM_AGENTS" -gt 0 ]; then
  require_ci_measured_profile "llm"
fi

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

CP_URL="$CP_INTERNAL_URL"
export CP_URL

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
      CP_URL="$CP_URL_CANDIDATE"
      export CP_URL
      break
    fi
    sleep 2
  done
fi

# Get admin password (from env or auto-generated by control plane)
if [ -z "${ADMIN_PASSWORD:-}" ]; then
  ADMIN_PASSWORD=$(curl -sf "$CP_URL/auth/methods" | jq -r '.generated_password // empty')
fi
if [ -z "${ADMIN_PASSWORD:-}" ]; then
  echo "::error::Could not determine admin password"
  exit 1
fi

# Admin token is used for capacity dispatch + manual attest.
ADMIN_TOKEN="$(admin_login)"

# Create a short-lived launcher account to claim capacity launch orders for CP-mint bootstrap tokens.
# This keeps Intel keys off the agent VMs while still requiring explicit authorization to register.
LAUNCHER_ACCOUNT_NAME="ci-launcher-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$(date +%s)"
LAUNCHER_JSON="$(
  curl -sf -X POST "$CP_URL/api/v1/accounts" \
    -H "Content-Type: application/json" \
    -d "$(jq -cn \
      --arg name "$LAUNCHER_ACCOUNT_NAME" \
      --arg desc "CI launcher account (ephemeral) for bootstrap token claims" \
      '{name:$name, description:$desc, account_type:"launcher"}')"
)"
LAUNCHER_API_KEY="$(echo "$LAUNCHER_JSON" | jq -r '.api_key // empty')"
LAUNCHER_ACCOUNT_ID="$(echo "$LAUNCHER_JSON" | jq -r '.account_id // empty')"
if [ -z "${LAUNCHER_API_KEY:-}" ] || [ -z "${LAUNCHER_ACCOUNT_ID:-}" ]; then
  echo "::error::Failed to create launcher account for capacity claims"
  echo "$LAUNCHER_JSON" | head -c 2000 || true
  exit 1
fi

resolve_target_datacenter() {
  if [ -n "${AGENT_DATACENTER:-}" ]; then
    printf '%s' "${AGENT_DATACENTER}"
    return 0
  fi
  # Mirror launcher resolve_datacenter_label(): baremetal:<availability_zone>.
  local provider="${AGENT_CLOUD_PROVIDER:-baremetal}"
  local az="${AGENT_DATACENTER_AZ:-github-runner}"
  provider="$(echo "$provider" | tr '[:upper:]' '[:lower:]')"
  az="$(echo "$az" | tr '[:upper:]' '[:lower:]')"
  if [ -z "$az" ]; then
    az="github-runner"
  fi
  if [ "$provider" = "google" ] || [ "$provider" = "gcp" ]; then
    provider="gcp"
  elif [ "$provider" = "azure" ] || [ "$provider" = "az" ]; then
    provider="azure"
  elif [ "$provider" = "bare-metal" ] || [ "$provider" = "onprem" ] || [ "$provider" = "on-prem" ] || [ "$provider" = "self-hosted" ]; then
    provider="baremetal"
  fi
  printf '%s:%s' "$provider" "$az"
}

TARGET_DATACENTER="$(resolve_target_datacenter)"

dispatch_bootstrap_orders() {
  local node_size="$1" count="$2"
  if [ "${count:-0}" -le 0 ]; then
    return 0
  fi
  curl -sf -X POST "$CP_URL/api/v1/admin/agents/capacity/reconcile" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$(jq -cn \
      --arg dc "$TARGET_DATACENTER" \
      --arg ns "$node_size" \
      --arg reason "ci-agent-bootstrap-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}" \
      --argjson count "$count" \
      --arg aid "$LAUNCHER_ACCOUNT_ID" \
      '{targets:[{datacenter:$dc,node_size:$ns,min_count:$count}], dispatch:true, reason:$reason, account_id:$aid}')" \
    >/dev/null
}

claim_bootstrap_token() {
  local node_size="$1"
  local resp order_id token
  resp="$(
    curl -sf -X POST "$CP_URL/api/v1/launchers/capacity/orders/claim" \
      -H "Authorization: Bearer $LAUNCHER_API_KEY" \
      -H "Content-Type: application/json" \
      -d "$(jq -cn --arg dc "$TARGET_DATACENTER" --arg ns "$node_size" '{datacenter:$dc,node_size:$ns}')"
  )"
  order_id="$(echo "$resp" | jq -r '.order.order_id // empty')"
  token="$(echo "$resp" | jq -r '.bootstrap_token // empty')"
  if [ -z "${order_id:-}" ] || [ -z "${token:-}" ]; then
    echo "::error::Failed to claim bootstrap token for node_size=$node_size datacenter=$TARGET_DATACENTER"
    echo "$resp" | head -c 2000 || true
    return 1
  fi
  printf '%s\t%s' "$order_id" "$token"
}

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
echo "Bootstrap agents already launched by control-plane new: $BOOTSTRAP_AGENT_COUNT"
echo "==> Launching $TOTAL_ADDITIONAL_AGENTS additional agents ($NUM_TINY_AGENTS tiny, $NUM_STANDARD_AGENTS standard, $NUM_LLM_AGENTS LLM)..."

# Queue capacity launch orders so the control plane can mint ITA tokens for quote-only agent registrations.
dispatch_bootstrap_orders "tiny" "$NUM_TINY_AGENTS"
dispatch_bootstrap_orders "standard" "$NUM_STANDARD_AGENTS"
dispatch_bootstrap_orders "llm" "$NUM_LLM_AGENTS"

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
    read -r order_id token < <(claim_bootstrap_token "tiny")
    python3 infra/tdx_cli.py vm new --size tiny \
      "${AGENT_LOCATION_ARGS[@]}" \
      --easyenclave-url "$CP_URL" \
      --bootstrap-order-id "$order_id" \
      --bootstrap-token "$token" \
      --wait &
  done
  for _i in $(seq 1 "$NUM_STANDARD_AGENTS"); do
    read -r order_id token < <(claim_bootstrap_token "standard")
    python3 infra/tdx_cli.py vm new --size standard \
      "${AGENT_LOCATION_ARGS[@]}" \
      --easyenclave-url "$CP_URL" \
      --bootstrap-order-id "$order_id" \
      --bootstrap-token "$token" \
      --wait &
  done
  for _i in $(seq 1 "$NUM_LLM_AGENTS"); do
    read -r order_id token < <(claim_bootstrap_token "llm")
    python3 infra/tdx_cli.py vm new --size llm \
      "${AGENT_LOCATION_ARGS[@]}" \
      --easyenclave-url "$CP_URL" \
      --bootstrap-order-id "$order_id" \
      --bootstrap-token "$token" \
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
for i in {1..30}; do
  AGENTS=$(curl -sf "$CP_URL/api/v1/agents" 2>/dev/null || echo '{"agents":[]}')
  VERIFIED=$(echo "$AGENTS" | jq '[.agents[] | select(.verified == true)] | length')
  if [ "$VERIFIED" -ge "$TOTAL_AGENTS" ]; then
    echo "All $TOTAL_AGENTS agents verified"
    break
  elif [ "$VERIFIED" -ge $((TOTAL_AGENTS - 1)) ]; then
    echo "Warning: only $VERIFIED/$TOTAL_AGENTS agents verified"
  fi
  echo "$VERIFIED/$TOTAL_AGENTS agents verified, waiting... ($i/30)"
  sleep 10
done

VERIFIED=$(curl -sf "$CP_URL/api/v1/agents" 2>/dev/null | jq '[.agents[] | select(.verified == true)] | length')
if [ "$VERIFIED" -lt "$TOTAL_AGENTS" ]; then
  echo "::error::Not all agents verified after 5 minutes ($VERIFIED/$TOTAL_AGENTS)"
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

# ===================================================================
# 6. Bootstrap apps
# ===================================================================

deploy_app "measuring-enclave-tiny" \
  "Measuring enclave for tiny node attestation" \
  "$MEASURER_IMAGE" \
  "" \
  '{"service_name": "measuring-enclave-tiny"}' \
  tiny

if [ "$NUM_STANDARD_AGENTS" -gt 0 ]; then
  deploy_app "measuring-enclave-standard" \
    "Measuring enclave for standard node attestation" \
    "$MEASURER_IMAGE" \
    "" \
    '{"service_name": "measuring-enclave-standard"}' \
    standard
else
  echo "Skipping standard measuring-enclave bootstrap (NUM_STANDARD_AGENTS=0)"
fi

if [ "$NUM_LLM_AGENTS" -gt 0 ]; then
  deploy_app "measuring-enclave-llm" \
    "Measuring enclave for llm node attestation" \
    "$MEASURER_IMAGE" \
    "" \
    '{"service_name": "measuring-enclave-llm"}' \
    llm
else
  echo "Skipping llm measuring-enclave bootstrap (NUM_LLM_AGENTS=0)"
fi

echo "==> Deploy complete!"
