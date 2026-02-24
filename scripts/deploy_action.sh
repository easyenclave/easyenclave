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

csv_to_json_array() {
  local csv="${1:-}"
  jq -cn --arg csv "$csv" '
    $csv
    | split(",")
    | map(gsub("^\\s+|\\s+$"; ""))
    | map(select(length > 0))
  '
}

node_size_qs() {
  if [ -n "${NODE_SIZE:-}" ]; then
    printf '?node_size=%s' "$NODE_SIZE"
  fi
}

fetch_version_json() {
  # Populates LAST_HTTP_CODE/LAST_URL for diagnostics.
  local qs url tmp code
  qs="$(node_size_qs)"
  url="${CONTROL_PLANE_URL}/api/v1/apps/${APP_NAME}/versions/${VERSION}${qs}"
  tmp="/tmp/easyenclave_version_response.json"

  LAST_URL="$url"
  code="$(curl -sS -H 'Accept: application/json' \
    --connect-timeout 5 --max-time 20 --retry 3 --retry-delay 1 \
    -o "$tmp" -w "%{http_code}" \
    "$url" || echo "000")"
  LAST_HTTP_CODE="$code"
  cat "$tmp" 2>/dev/null || true
}

is_json() {
  jq -e . >/dev/null 2>&1
}

json_get_or() {
  local raw="${1:-}"
  local filter="${2:-.}"
  local fallback="${3:-}"
  if echo "$raw" | is_json; then
    echo "$raw" | jq -r "$filter" 2>/dev/null || echo "$fallback"
  else
    echo "$fallback"
  fi
}

response_snippet() {
  local raw="${1:-}"
  local one_line
  one_line="$(echo "$raw" | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')"
  echo "${one_line:0:200}"
}

measurer_service_name() {
  # Legacy (measuring-enclave) name kept for backward compatibility.
  # The control plane now measures versions directly.
  if [ -n "${NODE_SIZE:-}" ]; then
    echo "measuring-enclave-${NODE_SIZE}"
  else
    echo "measuring-enclave"
  fi
}

print_cp_logs() {
  echo ""
  echo "=== Control Plane Logs (last 80 lines) ==="
  curl -sS -H 'Accept: application/json' --connect-timeout 5 --max-time 20 \
    "${CONTROL_PLANE_URL}/api/v1/logs/control-plane?limit=80" \
    | jq -r '.logs[]? | .message' \
    | tail -n 80 || true
  echo "=== End Control Plane Logs ==="
  echo ""
}

build_deploy_body() {
  local dry_run="${1:-false}"
  local config_json allowed_datacenters denied_datacenters allowed_clouds denied_clouds
  config_json="$(jq -n \
    --arg service_name "${SERVICE_NAME}" \
    --arg health_endpoint "${HEALTH_ENDPOINT}" \
    --arg admin_password "${AGENT_ADMIN_PASSWORD:-}" \
    '{
      service_name: $service_name,
      health_endpoint: $health_endpoint
    } + (if $admin_password != "" then {agent_admin_password: $admin_password} else {} end)')"
  allowed_datacenters="$(csv_to_json_array "${ALLOWED_DATACENTERS:-}")"
  denied_datacenters="$(csv_to_json_array "${DENIED_DATACENTERS:-}")"
  allowed_clouds="$(csv_to_json_array "${ALLOWED_CLOUDS:-}")"
  denied_clouds="$(csv_to_json_array "${DENIED_CLOUDS:-}")"

  jq -n \
    --arg github_owner "${GITHUB_OWNER:-}" \
    --arg node_size "${NODE_SIZE:-}" \
    --arg allow_fallback "${ALLOW_MEASURER_FALLBACK:-false}" \
    --arg dry_run "$dry_run" \
    --argjson config "$config_json" \
    --argjson allowed_datacenters "$allowed_datacenters" \
    --argjson denied_datacenters "$denied_datacenters" \
    --argjson allowed_clouds "$allowed_clouds" \
    --argjson denied_clouds "$denied_clouds" \
    '{
      config: $config,
      dry_run: ($dry_run == "true"),
      allow_measuring_enclave_fallback: ($allow_fallback == "true")
    }
    + (if $github_owner != "" then {github_owner: $github_owner} else {} end)
    + (if $node_size != "" then {node_size: $node_size} else {} end)
    + (if ($allowed_datacenters | length) > 0 then {allowed_datacenters: $allowed_datacenters} else {} end)
    + (if ($denied_datacenters | length) > 0 then {denied_datacenters: $denied_datacenters} else {} end)
    + (if ($allowed_clouds | length) > 0 then {allowed_clouds: $allowed_clouds} else {} end)
    + (if ($denied_clouds | length) > 0 then {denied_clouds: $denied_clouds} else {} end)'
}

wait_attested() {
  require_vars CONTROL_PLANE_URL APP_NAME VERSION

  local version_status consecutive_fetch_errors
  version_status="${INITIAL_STATUS:-unknown}"
  consecutive_fetch_errors=0

  if [ "$version_status" = "attested" ]; then
    echo "Version already attested"
  else
    echo "Version status: $version_status - waiting for measurement..."
    for i in {1..60}; do
      local version_json
      version_json="$(fetch_version_json)"
      if ! echo "$version_json" | is_json; then
        consecutive_fetch_errors=$((consecutive_fetch_errors + 1))
        echo "::warning::Control plane returned non-JSON while polling version status (HTTP ${LAST_HTTP_CODE:-unknown})."
        echo "URL: ${LAST_URL:-unknown}"
        echo "Response (first 200 bytes):"
        echo "${version_json:0:200}"
        if [ "$consecutive_fetch_errors" -ge 3 ]; then
          echo "::error::Failed to fetch version status reliably (3 consecutive non-JSON responses)."
          print_cp_logs
          exit 1
        fi
        sleep 5
        continue
      fi
      consecutive_fetch_errors=0

      version_status="$(echo "$version_json" | jq -r '.status // "unknown"')"

      if [ "$version_status" = "attested" ]; then
        echo "Version attested!"
        break
      elif [ "$version_status" = "failed" ] || [ "$version_status" = "rejected" ]; then
        local reason
        reason="$(echo "$version_json" | jq -r '.rejection_reason // "Unknown"')"
        echo "::error::Measurement failed: $reason"
        echo "Version JSON:"
        echo "$version_json" | jq .
        exit 1
      fi

      echo "  Status: $version_status ($i/60)"
      if [ "$version_status" = "pending" ] && [ "$i" -eq 12 ]; then
        echo "::warning::Version still pending after 1 minute. The control plane should measure versions locally."
        echo "Version JSON:"
        echo "$version_json" | jq . || true
        print_cp_logs
      fi

      # If we're stuck in attesting for a while, dump diagnostics once.
      if [ "$version_status" = "attesting" ] && [ "$i" -eq 24 ]; then
        echo "::warning::Version still attesting after 2 minutes; dumping diagnostics."
        print_cp_logs
        echo "Version JSON:"
        echo "$version_json" | jq .
      fi
      sleep 5
    done

    if [ "$version_status" != "attested" ]; then
      echo "::error::Timed out waiting for measurement (status: $version_status)"
      print_cp_logs
      exit 1
    fi
  fi

  local version_json
  version_json="$(fetch_version_json)"
  if ! echo "$version_json" | is_json; then
    echo "::error::Control plane returned non-JSON while fetching final version status (HTTP ${LAST_HTTP_CODE:-unknown})."
    echo "URL: ${LAST_URL:-unknown}"
    echo "Response (first 200 bytes):"
    echo "${version_json:0:200}"
    print_cp_logs
    exit 1
  fi
  version_status="$(echo "$version_json" | jq -r '.status // "unknown"')"
  if [ "$version_status" != "attested" ]; then
    echo "::error::Expected attested version but got status='$version_status'"
    echo "Version JSON:"
    echo "$version_json" | jq .
    exit 1
  fi

  local actual_node_size
  actual_node_size="$(echo "$version_json" | jq -r '.node_size // ""')"
  if [ -n "${NODE_SIZE:-}" ] && [ "$actual_node_size" != "$NODE_SIZE" ]; then
    echo "::error::Version node_size mismatch: expected '$NODE_SIZE', got '$actual_node_size'"
    echo "Version JSON:"
    echo "$version_json" | jq .
    exit 1
  fi

  echo "Version ${VERSION} is attested"
}

try_deploy() {
  local body
  body="$(build_deploy_body false)"

  curl -s -o /tmp/deploy_response.json -w "%{http_code}" \
    -X POST "${CONTROL_PLANE_URL}/api/v1/apps/${APP_NAME}/versions/${VERSION}/deploy" \
    -H "Content-Type: application/json" \
    -d "$body"
}

run_preflight() {
  local body
  body="$(build_deploy_body true)"
  curl -s -o /tmp/deploy_preflight_response.json -w "%{http_code}" \
    -X POST "${CONTROL_PLANE_URL}/api/v1/apps/${APP_NAME}/versions/${VERSION}/deploy/preflight" \
    -H "Content-Type: application/json" \
    -d "$body"
}

print_preflight_diagnostics() {
  local response="$1"
  local eligible selected_agent selected_dc selected_cloud issue_count
  eligible="$(echo "$response" | jq -r '.eligible // false')"
  selected_agent="$(echo "$response" | jq -r '.selected_agent_id // ""')"
  selected_dc="$(echo "$response" | jq -r '.selected_datacenter // ""')"
  selected_cloud="$(echo "$response" | jq -r '.selected_cloud // ""')"
  issue_count="$(echo "$response" | jq -r '.issues | length // 0')"

  echo "Preflight: eligible=$eligible selected_agent=${selected_agent:-none} datacenter=${selected_dc:-none} cloud=${selected_cloud:-none} issues=$issue_count"
  if [ "$issue_count" -gt 0 ]; then
    echo "$response" | jq -r '.issues[] | "- \(.code): \(.message)\(if .agent_id then " [agent=" + .agent_id + "]" else "" end)\(if .datacenter then " [dc=" + .datacenter + "]" else "" end)\(if .node_size then " [size=" + .node_size + "]" else "" end)"'
  fi
}

find_and_deploy() {
  require_vars CONTROL_PLANE_URL APP_NAME VERSION SERVICE_NAME HEALTH_ENDPOINT

  local preflight_code preflight_resp
  preflight_code="$(run_preflight)"
  preflight_resp="$(cat /tmp/deploy_preflight_response.json)"
  if [ "$preflight_code" -lt 400 ] && echo "$preflight_resp" | is_json; then
    print_preflight_diagnostics "$preflight_resp"
  elif [ "$preflight_code" -lt 400 ]; then
    echo "::warning::Preflight returned non-JSON body: $(response_snippet "$preflight_resp")"
  else
    echo "::warning::Preflight request failed (HTTP $preflight_code): $preflight_resp"
  fi

  echo "Requesting control-plane placement and deploy for version $VERSION..."
  for attempt in {1..12}; do
    local http_code response detail response_hint deployment_id agent_id
    http_code="$(try_deploy)"
    response="$(cat /tmp/deploy_response.json)"
    detail="$(json_get_or "$response" '.detail // empty' '')"
    response_hint="$(response_snippet "$response")"

    if [ "$http_code" -lt 400 ]; then
      if ! echo "$response" | is_json; then
        echo "::warning::Deploy returned HTTP ${http_code} with non-JSON body (attempt ${attempt}/12): ${response_hint}"
        sleep 10
        continue
      fi

      deployment_id="$(json_get_or "$response" '.deployment_id // empty' '')"
      agent_id="$(json_get_or "$response" '.agent_id // empty' '')"
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

    if [ -n "$detail" ]; then
      echo "  HTTP $http_code: $detail"
    else
      echo "  HTTP $http_code: ${response_hint:-<empty response>}"
    fi
    if [ "$http_code" = "503" ] || echo "${detail}${response_hint}" | grep -Eqi "No eligible agents|No warm capacity|pool reconcile|service unavailable|temporarily unavailable"; then
      echo "Control plane not placeable yet, waiting 30s... ($attempt/12)"
      sleep 30
      continue
    fi

    preflight_code="$(run_preflight)"
    preflight_resp="$(cat /tmp/deploy_preflight_response.json)"
    if [ "$preflight_code" -lt 400 ] && echo "$preflight_resp" | is_json; then
      print_preflight_diagnostics "$preflight_resp"
    elif [ "$preflight_code" -lt 400 ]; then
      echo "::warning::Preflight returned non-JSON body: $(response_snippet "$preflight_resp")"
    fi
    echo "::error::Deploy request failed"
    exit 1
  done

  preflight_code="$(run_preflight)"
  preflight_resp="$(cat /tmp/deploy_preflight_response.json)"
  if [ "$preflight_code" -lt 400 ] && echo "$preflight_resp" | is_json; then
    print_preflight_diagnostics "$preflight_resp"
  elif [ "$preflight_code" -lt 400 ]; then
    echo "::warning::Preflight returned non-JSON body: $(response_snippet "$preflight_resp")"
  fi
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
