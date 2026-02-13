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
  local qs
  qs="$(node_size_qs)"
  curl -sf "${CONTROL_PLANE_URL}/api/v1/apps/${APP_NAME}/versions/${VERSION}${qs}" 2>/dev/null || echo '{}'
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

list_filtered_agents() {
  local agents_json allowed_datacenters denied_datacenters allowed_clouds denied_clouds
  agents_json="$(curl -sf "${CONTROL_PLANE_URL}/api/v1/agents" 2>/dev/null || echo '{"agents":[]}')"
  allowed_datacenters="$(csv_to_json_array "${ALLOWED_DATACENTERS:-}" | jq -c 'map(ascii_downcase)')"
  denied_datacenters="$(csv_to_json_array "${DENIED_DATACENTERS:-}" | jq -c 'map(ascii_downcase)')"
  allowed_clouds="$(csv_to_json_array "${ALLOWED_CLOUDS:-}" | jq -c 'map(ascii_downcase)')"
  denied_clouds="$(csv_to_json_array "${DENIED_CLOUDS:-}" | jq -c 'map(ascii_downcase)')"

  echo "$agents_json" | jq -c \
    --arg ns "${NODE_SIZE:-}" \
    --argjson allowed_dcs "$allowed_datacenters" \
    --argjson denied_dcs "$denied_datacenters" \
    --argjson allowed_cs "$allowed_clouds" \
    --argjson denied_cs "$denied_clouds" '
    [.agents[]
      | . as $agent
      | (($agent.datacenter // "") | tostring | ascii_downcase) as $dc
      | (($dc | split(":"))[0]) as $cloud
      | select(($agent.verified // false) == true)
      | select(($agent.health_status // "") == "healthy")
      | select(($agent.hostname // "") != "")
      | select((($agent.status // "") == "undeployed") or (($agent.status // "") == "deployed"))
      | select(if $ns != "" then (($agent.node_size // "") == $ns) else true end)
      | select(if ($allowed_dcs | length) > 0 then (($allowed_dcs | index($dc)) != null) else true end)
      | select(if ($denied_dcs | length) > 0 then (($denied_dcs | index($dc)) == null) else true end)
      | select(if ($allowed_cs | length) > 0 then (($allowed_cs | index($cloud)) != null) else true end)
      | select(if ($denied_cs | length) > 0 then (($denied_cs | index($cloud)) == null) else true end)
      | {
          agent_id: ($agent.agent_id // ""),
          status: ($agent.status // ""),
          datacenter: $dc,
          cloud: $cloud,
          node_size: ($agent.node_size // "")
        }
    ]'
}

ensure_undeployed_candidate() {
  local candidates undeployed_agent deployed_agent reset_code reset_resp status

  candidates="$(list_filtered_agents)"
  undeployed_agent="$(echo "$candidates" | jq -r '[.[] | select(.status == "undeployed") | .agent_id] | first // empty')"
  if [ -n "$undeployed_agent" ]; then
    echo "Found undeployed candidate agent: $undeployed_agent"
    return 0
  fi

  deployed_agent="$(echo "$candidates" | jq -r '[.[] | select(.status == "deployed") | .agent_id] | first // empty')"
  if [ -z "$deployed_agent" ]; then
    echo "::warning::No matching healthy verified agents found for current placement filters yet"
    return 0
  fi

  echo "No undeployed candidate found; resetting deployed agent $deployed_agent to undeployed"
  reset_code="$(curl -s -o /tmp/reset_agent_response.json -w "%{http_code}" \
    -X POST "${CONTROL_PLANE_URL}/api/v1/agents/${deployed_agent}/reset")"
  reset_resp="$(cat /tmp/reset_agent_response.json)"

  if [ "$reset_code" -ge 400 ]; then
    echo "::warning::Failed to reset agent $deployed_agent (HTTP $reset_code): $reset_resp"
    return 0
  fi

  for i in {1..12}; do
    status="$(curl -sf "${CONTROL_PLANE_URL}/api/v1/agents/${deployed_agent}" 2>/dev/null | jq -r '.status // ""')"
    if [ "$status" = "undeployed" ]; then
      echo "Agent $deployed_agent is now undeployed"
      return 0
    fi
    echo "Waiting for agent $deployed_agent to transition to undeployed... ($i/12)"
    sleep 5
  done

  echo "::warning::Timed out waiting for reset agent $deployed_agent to become undeployed"
  return 0
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

  ensure_undeployed_candidate

  local preflight_code preflight_resp
  preflight_code="$(run_preflight)"
  preflight_resp="$(cat /tmp/deploy_preflight_response.json)"
  if [ "$preflight_code" -lt 400 ]; then
    print_preflight_diagnostics "$preflight_resp"
  else
    echo "::warning::Preflight request failed (HTTP $preflight_code): $preflight_resp"
  fi

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
      ensure_undeployed_candidate
      echo "No eligible agents yet, waiting 30s... ($attempt/12)"
      sleep 30
      continue
    fi

    preflight_code="$(run_preflight)"
    preflight_resp="$(cat /tmp/deploy_preflight_response.json)"
    if [ "$preflight_code" -lt 400 ]; then
      print_preflight_diagnostics "$preflight_resp"
    fi
    echo "::error::Deploy request failed"
    exit 1
  done

  preflight_code="$(run_preflight)"
  preflight_resp="$(cat /tmp/deploy_preflight_response.json)"
  if [ "$preflight_code" -lt 400 ]; then
    print_preflight_diagnostics "$preflight_resp"
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
