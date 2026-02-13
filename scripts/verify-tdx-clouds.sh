#!/usr/bin/env bash
# Verify pure-TDX agent readiness across cloud datacenters.
#
# This script validates:
#  1) At least one verified/healthy agent exists per target cloud datacenter.
#  2) Deploy preflight with allowed_datacenters selects the correct cloud.
#  3) Deploy preflight with denied_datacenters blocks that cloud.
#
# Notes:
#  - AWS is skipped by default in pure-TDX mode (no AWS TDX path in this stack yet).
#  - This script does not provision cloud VMs; it verifies already-registered agents.
set -euo pipefail

CP_URL="${CP_URL:-https://app.easyenclave.com}"
CLOUDS="${CLOUDS:-baremetal,gcp,azure}"
NODE_SIZE="${NODE_SIZE:-standard}"
VERIFY_APP_NAME="${VERIFY_APP_NAME:-}"
VERIFY_APP_VERSION="${VERIFY_APP_VERSION:-}"
CP_ADMIN_TOKEN="${CP_ADMIN_TOKEN:-}"
ALLOW_MEASURER_FALLBACK="${ALLOW_MEASURER_FALLBACK:-false}"
SKIP_MISSING_DATACENTER="${SKIP_MISSING_DATACENTER:-false}"
FAIL_ON_UNSUPPORTED_CLOUDS="${FAIL_ON_UNSUPPORTED_CLOUDS:-false}"

DC_BAREMETAL="${DC_BAREMETAL:-baremetal:github-runner}"
DC_GCP="${DC_GCP:-}"
DC_AZURE="${DC_AZURE:-}"
DC_AWS="${DC_AWS:-}"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

CP_CURL_ARGS=(
  -H "Accept: application/json"
  -H "User-Agent: easyenclave-cloud-verify/1.0"
)
if [ -n "$CP_ADMIN_TOKEN" ]; then
  CP_CURL_ARGS+=(-H "Authorization: Bearer $CP_ADMIN_TOKEN")
fi

require_tools() {
  local missing=0
  for cmd in curl jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "::error::Missing required tool: $cmd"
      missing=1
    fi
  done
  if [ "$missing" -ne 0 ]; then
    exit 1
  fi
}

trim() {
  local value="$1"
  # shellcheck disable=SC2001
  echo "$(echo "$value" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
}

datacenter_for_cloud() {
  local cloud="$1"
  case "$cloud" in
    baremetal) echo "$DC_BAREMETAL" ;;
    gcp|google) echo "$DC_GCP" ;;
    azure) echo "$DC_AZURE" ;;
    aws) echo "$DC_AWS" ;;
    *) echo "" ;;
  esac
}

is_unsupported_cloud() {
  local cloud="$1"
  case "$cloud" in
    aws) return 0 ;;
    *) return 1 ;;
  esac
}

agents_json() {
  local tmp code body
  tmp="$(mktemp)"
  code="$(curl -sS "${CP_CURL_ARGS[@]}" -o "$tmp" -w "%{http_code}" "$CP_URL/api/v1/agents")" || {
    rm -f "$tmp"
    return 1
  }
  if [ "$code" -ge 400 ]; then
    body="$(tr '\n' ' ' < "$tmp" | sed 's/[[:space:]]\+/ /g' | cut -c1-240)"
    rm -f "$tmp"
    echo "::error::Control plane agents endpoint returned HTTP $code (${body:-no body})" >&2
    if [ "$code" = "401" ] || [ "$code" = "403" ]; then
      echo "::error::Set CP_ADMIN_TOKEN for authenticated agent checks" >&2
    fi
    return 1
  fi
  cat "$tmp"
  rm -f "$tmp"
}

cloud_header() {
  local cloud="$1"
  echo ""
  echo "=== Verifying cloud: $cloud ==="
}

verify_cloud_agents() {
  local cloud="$1"
  local dc="$2"
  local agents="$3"
  local count ids

  count="$(echo "$agents" | jq -r --arg dc_lc "$(echo "$dc" | tr '[:upper:]' '[:lower:]')" --arg ns "$NODE_SIZE" '
    [.agents[]
      | select(.verified == true)
      | select(.health_status == "healthy")
      | select(.hostname != null and .hostname != "")
      | select((.status == "undeployed") or (.status == "deployed") or (.status == "deploying"))
      | select(((.datacenter // "") | ascii_downcase) == $dc_lc)
      | select(if $ns != "" then ((.node_size // "") == $ns) else true end)
    ] | length
  ')"

  ids="$(echo "$agents" | jq -r --arg dc_lc "$(echo "$dc" | tr '[:upper:]' '[:lower:]')" --arg ns "$NODE_SIZE" '
    [.agents[]
      | select(.verified == true)
      | select(.health_status == "healthy")
      | select(.hostname != null and .hostname != "")
      | select((.status == "undeployed") or (.status == "deployed") or (.status == "deploying"))
      | select(((.datacenter // "") | ascii_downcase) == $dc_lc)
      | select(if $ns != "" then ((.node_size // "") == $ns) else true end)
      | .agent_id
    ] | join(",")
  ')"

  if [ "$count" -lt 1 ]; then
    echo "::error::No eligible verified agents found for cloud=$cloud datacenter=$dc node_size=${NODE_SIZE:-any}"
    return 1
  fi

  echo "Found $count eligible agents for $cloud ($dc), node_size=${NODE_SIZE:-any}"
  echo "Agents: $ids"
  return 0
}

verify_cloud_preflight() {
  local cloud="$1"
  local dc="$2"
  local allow_body deny_body allow_code deny_code
  local allow_resp deny_resp eligible selected_dc

  if [ -z "$VERIFY_APP_NAME" ] || [ -z "$VERIFY_APP_VERSION" ]; then
    echo "::warning::Skipping preflight checks for $cloud (set VERIFY_APP_NAME and VERIFY_APP_VERSION)"
    return 0
  fi

  allow_body="$(jq -cn \
    --arg ns "$NODE_SIZE" \
    --arg dc "$dc" \
    --arg allow_fallback "$ALLOW_MEASURER_FALLBACK" \
    '{
      dry_run: true,
      node_size: $ns,
      allowed_datacenters: [$dc],
      allow_measuring_enclave_fallback: ($allow_fallback == "true")
    }')"
  allow_code="$(curl -s -o /tmp/tdx_cloud_preflight_allow.json -w "%{http_code}" \
    "${CP_CURL_ARGS[@]}" \
    -X POST "$CP_URL/api/v1/apps/$VERIFY_APP_NAME/versions/$VERIFY_APP_VERSION/deploy/preflight" \
    -H "Content-Type: application/json" \
    -d "$allow_body")"
  allow_resp="$(cat /tmp/tdx_cloud_preflight_allow.json)"

  if [ "$allow_code" -ge 400 ]; then
    echo "::error::Allowed-datacenter preflight failed for $cloud (HTTP $allow_code): $allow_resp"
    return 1
  fi

  eligible="$(echo "$allow_resp" | jq -r '.eligible // false')"
  selected_dc="$(echo "$allow_resp" | jq -r '.selected_datacenter // ""' | tr '[:upper:]' '[:lower:]')"
  if [ "$eligible" != "true" ]; then
    echo "::error::Allowed-datacenter preflight not eligible for $cloud: $allow_resp"
    return 1
  fi
  if [ "$selected_dc" != "$(echo "$dc" | tr '[:upper:]' '[:lower:]')" ]; then
    echo "::error::Preflight selected unexpected datacenter for $cloud (expected $dc, got $selected_dc)"
    return 1
  fi

  deny_body="$(jq -cn \
    --arg ns "$NODE_SIZE" \
    --arg dc "$dc" \
    --arg allow_fallback "$ALLOW_MEASURER_FALLBACK" \
    '{
      dry_run: true,
      node_size: $ns,
      denied_datacenters: [$dc],
      allow_measuring_enclave_fallback: ($allow_fallback == "true")
    }')"
  deny_code="$(curl -s -o /tmp/tdx_cloud_preflight_deny.json -w "%{http_code}" \
    "${CP_CURL_ARGS[@]}" \
    -X POST "$CP_URL/api/v1/apps/$VERIFY_APP_NAME/versions/$VERIFY_APP_VERSION/deploy/preflight" \
    -H "Content-Type: application/json" \
    -d "$deny_body")"
  deny_resp="$(cat /tmp/tdx_cloud_preflight_deny.json)"

  if [ "$deny_code" -ge 400 ]; then
    echo "::error::Denied-datacenter preflight failed for $cloud (HTTP $deny_code): $deny_resp"
    return 1
  fi

  eligible="$(echo "$deny_resp" | jq -r '.eligible // true')"
  if [ "$eligible" = "true" ]; then
    echo "::error::Denied-datacenter preflight should be ineligible for $cloud, got: $deny_resp"
    return 1
  fi

  echo "Preflight policy checks passed for $cloud ($dc)"
  return 0
}

verify_one_cloud() {
  local cloud="$1"
  local dc agents

  cloud="$(trim "$cloud")"
  if [ -z "$cloud" ]; then
    return 0
  fi
  cloud_header "$cloud"

  if is_unsupported_cloud "$cloud"; then
    local msg="Cloud '$cloud' is not supported in pure-TDX mode yet"
    if [ "$FAIL_ON_UNSUPPORTED_CLOUDS" = "true" ]; then
      echo "::error::$msg"
      FAIL_COUNT=$((FAIL_COUNT + 1))
      return
    fi
    echo "::warning::$msg (skipping)"
    SKIP_COUNT=$((SKIP_COUNT + 1))
    return
  fi

  dc="$(datacenter_for_cloud "$cloud")"
  if [ -z "$dc" ]; then
    local msg2="No datacenter label configured for cloud '$cloud'"
    if [ "$SKIP_MISSING_DATACENTER" = "true" ]; then
      echo "::warning::$msg2 (skipping)"
      SKIP_COUNT=$((SKIP_COUNT + 1))
      return
    fi
    echo "::error::$msg2"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    return
  fi

  if ! agents="$(agents_json)"; then
    echo "::error::Failed to fetch agents from control plane: $CP_URL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    return
  fi

  if ! verify_cloud_agents "$cloud" "$dc" "$agents"; then
    FAIL_COUNT=$((FAIL_COUNT + 1))
    return
  fi

  if ! verify_cloud_preflight "$cloud" "$dc"; then
    FAIL_COUNT=$((FAIL_COUNT + 1))
    return
  fi

  PASS_COUNT=$((PASS_COUNT + 1))
}

main() {
  require_tools
  echo "Pure-TDX cloud verification"
  echo "CP_URL=$CP_URL"
  if [ -n "$CP_ADMIN_TOKEN" ]; then
    echo "CP_ADMIN_TOKEN=<set>"
  else
    echo "CP_ADMIN_TOKEN=<unset>"
  fi
  echo "CLOUDS=$CLOUDS"
  echo "NODE_SIZE=${NODE_SIZE:-any}"
  echo "VERIFY_APP_NAME=${VERIFY_APP_NAME:-<none>}"
  echo "VERIFY_APP_VERSION=${VERIFY_APP_VERSION:-<none>}"

  IFS=',' read -r -a targets <<< "$CLOUDS"
  for target in "${targets[@]}"; do
    verify_one_cloud "$target"
  done

  echo ""
  echo "=== Summary ==="
  echo "Passed: $PASS_COUNT"
  echo "Skipped: $SKIP_COUNT"
  echo "Failed: $FAIL_COUNT"

  if [ "$FAIL_COUNT" -ne 0 ]; then
    exit 1
  fi
}

main "$@"
