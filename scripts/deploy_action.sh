#!/usr/bin/env bash
set -euo pipefail

require_vars() {
  for var in "$@"; do
    if [ -z "${!var:-}" ]; then
      echo "::error::Missing required env var: $var"
      exit 1
    fi
  done
}

node_size_qs() {
  if [ -n "${NODE_SIZE:-}" ]; then
    printf '?node_size=%s' "$NODE_SIZE"
  fi
}

fetch_version_json() {
  local qs
  qs="$(node_size_qs)"
  curl -sf "${CONTROL_PLANE_URL}/api/v1/apps/${APP_NAME}/versions/${VERSION}${qs}" 2>/dev/null || echo '{}'
}

wait_attested() {
  require_vars CONTROL_PLANE_URL APP_NAME VERSION

  local version_status
  version_status="${INITIAL_STATUS:-unknown}"

  if [ "$version_status" = "attested" ]; then
    echo "Version already attested"
  else
    echo "Version status: $version_status - waiting for measurement..."
    for i in {1..60}; do
      local version_json
      version_json="$(fetch_version_json)"
      version_status="$(echo "$version_json" | jq -r '.status // "unknown"')"

      if [ "$version_status" = "attested" ]; then
        echo "Version attested!"
        break
      elif [ "$version_status" = "failed" ] || [ "$version_status" = "rejected" ]; then
        local reason
        reason="$(echo "$version_json" | jq -r '.rejection_reason // "Unknown"')"
        echo "::error::Measurement failed: $reason"
        exit 1
      fi

      echo "  Status: $version_status ($i/60)"
      sleep 5
    done

    if [ "$version_status" != "attested" ]; then
      echo "::error::Timed out waiting for measurement (status: $version_status)"
      exit 1
    fi
  fi

  local version_json
  version_json="$(fetch_version_json)"
  version_status="$(echo "$version_json" | jq -r '.status // "unknown"')"
  if [ "$version_status" != "attested" ]; then
    echo "::error::Expected attested version but got status='$version_status'"
    exit 1
  fi

  local actual_node_size
  actual_node_size="$(echo "$version_json" | jq -r '.node_size // ""')"
  if [ -n "${NODE_SIZE:-}" ] && [ "$actual_node_size" != "$NODE_SIZE" ]; then
    echo "::error::Version node_size mismatch: expected '$NODE_SIZE', got '$actual_node_size'"
    exit 1
  fi

  echo "Version ${VERSION} is attested"
}

try_deploy() {
  local config_json
  config_json="$(jq -n \
    --arg service_name "${SERVICE_NAME}" \
    --arg health_endpoint "${HEALTH_ENDPOINT}" \
    --arg admin_password "${AGENT_ADMIN_PASSWORD:-}" \
    '{
      service_name: $service_name,
      health_endpoint: $health_endpoint
    } + (if $admin_password != "" then {agent_admin_password: $admin_password} else {} end)')"

  local body
  body="$(jq -n \
    --arg github_owner "${GITHUB_OWNER:-}" \
    --arg node_size "${NODE_SIZE:-}" \
    --arg allow_fallback "${ALLOW_MEASURER_FALLBACK:-false}" \
    --argjson config "$config_json" \
    '{
      config: $config,
      allow_measuring_enclave_fallback: ($allow_fallback == "true")
    } + (if $github_owner != "" then {github_owner: $github_owner} else {} end)
      + (if $node_size != "" then {node_size: $node_size} else {} end)')"

  curl -s -o /tmp/deploy_response.json -w "%{http_code}" \
    -X POST "${CONTROL_PLANE_URL}/api/v1/apps/${APP_NAME}/versions/${VERSION}/deploy" \
    -H "Content-Type: application/json" \
    -d "$body"
}

find_and_deploy() {
  require_vars CONTROL_PLANE_URL APP_NAME VERSION SERVICE_NAME HEALTH_ENDPOINT

  echo "Requesting control-plane placement and deploy for version $VERSION..."
  for attempt in {1..12}; do
    local http_code response detail deployment_id agent_id
    http_code="$(try_deploy)"
    response="$(cat /tmp/deploy_response.json)"
    detail="$(echo "$response" | jq -r '.detail // empty')"

    if [ "$http_code" -lt 400 ]; then
      deployment_id="$(echo "$response" | jq -r '.deployment_id // empty')"
      agent_id="$(echo "$response" | jq -r '.agent_id // empty')"
      if [ -z "$agent_id" ] && [ -n "$deployment_id" ]; then
        agent_id="$(curl -sf "${CONTROL_PLANE_URL}/api/v1/deployments/${deployment_id}" 2>/dev/null | jq -r '.agent_id // empty')"
      fi

      if [ -z "$deployment_id" ] || [ -z "$agent_id" ]; then
        echo "::error::Deploy response missing deployment_id/agent_id: $response"
        exit 1
      fi

      echo "Deployed to agent $agent_id (deployment $deployment_id)"
      echo "agent_id=$agent_id" >> "$GITHUB_OUTPUT"
      echo "deployment_id=$deployment_id" >> "$GITHUB_OUTPUT"
      return 0
    fi

    echo "  HTTP $http_code: $detail"
    if [ "$http_code" = "503" ] || echo "$detail" | grep -qi "No eligible agents"; then
      echo "No eligible agents yet, waiting 30s... ($attempt/12)"
      sleep 30
      continue
    fi

    echo "::error::Deploy request failed"
    exit 1
  done

  echo "::error::No eligible agents after 12 attempts"
  exit 1
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    wait-attested)
      wait_attested
      ;;
    find-and-deploy)
      find_and_deploy
      ;;
    *)
      echo "Usage: $0 {wait-attested|find-and-deploy}" >&2
      exit 2
      ;;
  esac
}

main "$@"
