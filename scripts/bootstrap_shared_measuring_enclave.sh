#!/usr/bin/env bash
# Bootstrap a size-specific measuring enclave on an existing control plane.
#
# This is the "chicken-and-egg" path: we publish measuring-enclave-$NODE_SIZE,
# then manually attest it with CI-measured baseline values (MRTD/RTMRs), then deploy it.
#
# Required env:
#   CP_URL
#   ADMIN_PASSWORD  (optional control plane admin password; falls back to /auth/methods generated_password)
#   ADMIN_TOKEN     (optional control plane admin bearer token; takes precedence over ADMIN_PASSWORD)
#   NODE_SIZE       (tiny|standard|llm)
#   MEASURER_IMAGE  (ghcr.io/.../measuring-enclave:tag)
#   TRUSTED_AGENT_MRTDS_BY_SIZE (JSON map, e.g. {"llm":"...","tiny":"..."})
#   TRUSTED_AGENT_RTMRS_BY_SIZE (JSON map, e.g. {"llm":{"rtmr0":"...","rtmr1":"...","rtmr2":"...","rtmr3":"..."}})
# Optional env:
#   ALLOWED_CLOUDS (comma-separated allow-list, e.g. "baremetal")
#   ALLOWED_DATACENTERS (comma-separated allow-list, e.g. "baremetal:github-runner")
set -euo pipefail

require() {
  for v in "$@"; do
    if [ -z "${!v:-}" ]; then
      echo "::error::Missing required env var: $v"
      exit 1
    fi
  done
}

require CP_URL NODE_SIZE MEASURER_IMAGE TRUSTED_AGENT_MRTDS_BY_SIZE TRUSTED_AGENT_RTMRS_BY_SIZE

case "$NODE_SIZE" in
  tiny|standard|llm) ;;
  *)
    echo "::error::Unsupported NODE_SIZE='$NODE_SIZE' (expected tiny|standard|llm)"
    exit 1
    ;;
esac

APP_NAME="measuring-enclave-${NODE_SIZE}"
DESCRIPTION="Measuring enclave for ${NODE_SIZE} node attestation"

csv_to_json_array() {
  local csv="${1:-}"
  jq -cn --arg csv "$csv" '
    $csv
    | split(",")
    | map(gsub("^\\s+|\\s+$"; ""))
    | map(select(length > 0))
  '
}

login_with_password() {
  local candidate="$1"
  [ -n "$candidate" ] || return 1
  local body code token
  body="$(mktemp)"
  code="$(
    curl -sS -o "$body" -w "%{http_code}" "${CP_URL}/admin/login" \
      -X POST \
      -H "Content-Type: application/json" \
      -d "{\"password\": \"${candidate}\"}" || echo 000
  )"
  if [ "$code" != "200" ]; then
    rm -f "$body"
    return 1
  fi
  token="$(jq -r '.token // empty' "$body" 2>/dev/null || true)"
  rm -f "$body"
  [ -n "$token" ] && [ "$token" != "null" ] || return 1
  printf '%s' "$token"
  return 0
}

ADMIN_TOKEN="${ADMIN_TOKEN:-}"
if [ -z "$ADMIN_TOKEN" ]; then
  if [ -n "${ADMIN_PASSWORD:-}" ]; then
    ADMIN_TOKEN="$(login_with_password "${ADMIN_PASSWORD}" || true)"
  fi
fi
if [ -z "$ADMIN_TOKEN" ]; then
  generated_pw="$(curl -sSf "${CP_URL}/auth/methods" | jq -r '.generated_password // empty' || true)"
  if [ -n "$generated_pw" ]; then
    ADMIN_TOKEN="$(login_with_password "$generated_pw" || true)"
  fi
fi
if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" = "null" ]; then
  echo "::error::Admin login failed (set ADMIN_TOKEN or provide ADMIN_PASSWORD / generated_password)."
  exit 1
fi

MRTD="$(
  echo "$TRUSTED_AGENT_MRTDS_BY_SIZE" | jq -r --arg ns "$NODE_SIZE" '.[$ns] // empty'
)"
RTMRS="$(
  echo "$TRUSTED_AGENT_RTMRS_BY_SIZE" | jq -c --arg ns "$NODE_SIZE" '.[$ns] // null'
)"
if [ -z "$MRTD" ]; then
  echo "::error::Missing TRUSTED_AGENT_MRTDS_BY_SIZE['$NODE_SIZE']"
  exit 1
fi
if [ -z "$RTMRS" ] || [ "$RTMRS" = "null" ]; then
  echo "::error::Missing TRUSTED_AGENT_RTMRS_BY_SIZE['$NODE_SIZE']"
  exit 1
fi

# Register app (idempotent)
curl -sSf -X POST "${CP_URL}/api/v1/apps" \
  -H "Content-Type: application/json" \
  -d "{\"name\": \"${APP_NAME}\", \"description\": \"${DESCRIPTION}\"}" \
  >/dev/null 2>&1 || true

COMPOSE_YML="$(cat <<EOF
services:
  measuring-enclave:
    image: ${MEASURER_IMAGE}
    ports:
      - "8080:8080"
EOF
)"
COMPOSE_B64="$(printf '%s' "$COMPOSE_YML" | base64 -w 0)"

VERSION="bootstrap-$(date -u +%Y%m%d-%H%M%S)-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"

publish_resp="$(
  curl -sSf -X POST "${CP_URL}/api/v1/apps/${APP_NAME}/versions" \
    -H "Content-Type: application/json" \
    -d "$(jq -cn --arg v "$VERSION" --arg c "$COMPOSE_B64" --arg ns "$NODE_SIZE" '{version:$v, compose:$c, node_size:$ns}')"
)"
status="$(echo "$publish_resp" | jq -r '.status // empty')"
echo "Published ${APP_NAME}@${VERSION} status=${status:-unknown}"

measured_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
attest_body="$(jq -cn \
  --arg mrtd "$MRTD" \
  --arg ns "$NODE_SIZE" \
  --arg measured_at "$measured_at" \
  --argjson rtmrs "$RTMRS" \
  '{
    mrtd: $mrtd,
    attestation: {
      bootstrap: true,
      measurement_type: "ci_measured_profile",
      node_size: $ns,
      mrtd: $mrtd,
      rtmrs: $rtmrs,
      measured_at: $measured_at
    }
  }'
)"

curl -sSf -X POST "${CP_URL}/api/v1/apps/${APP_NAME}/versions/${VERSION}/attest?node_size=${NODE_SIZE}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$attest_body" \
  >/dev/null
echo "Manually attested ${APP_NAME}@${VERSION} (node_size=${NODE_SIZE})"

# Deploy measurer onto an eligible node of this size.
# If an existing measurer agent is already running for this app+size, target it
# explicitly so this acts as an upgrade and does not consume a second LLM node.
allowed_clouds_json="$(csv_to_json_array "${ALLOWED_CLOUDS:-}" | jq -c 'map(ascii_downcase)')"
allowed_datacenters_json="$(csv_to_json_array "${ALLOWED_DATACENTERS:-}" | jq -c 'map(ascii_downcase)')"
existing_agent_id="$(
  curl -sSf "${CP_URL}/api/v1/agents" \
  | jq -r \
      --arg app "$APP_NAME" \
      --arg ns "$NODE_SIZE" \
      --argjson allowed_clouds "$allowed_clouds_json" \
      --argjson allowed_dcs "$allowed_datacenters_json" '
      [.agents[]
        | . as $agent
        | (($agent.datacenter // "") | tostring | ascii_downcase) as $dc
        | (($dc | split(":"))[0]) as $cloud
        | select(($agent.node_size // "" | ascii_downcase) == ($ns | ascii_downcase))
        | select(($agent.deployed_app // "") == $app)
        | select(($agent.status // "" | ascii_downcase) == "deployed")
        | select(($agent.verified // false) == true)
        | select(($agent.health_status // "" | ascii_downcase) == "healthy")
        | select(if ($allowed_clouds | length) > 0 then (($allowed_clouds | index($cloud)) != null) else true end)
        | select(if ($allowed_dcs | length) > 0 then (($allowed_dcs | index($dc)) != null) else true end)
      ]
      | sort_by(.registered_at // "")
      | reverse
      | .[0].agent_id // empty
    ' \
  || true
)"

deploy_body="$(jq -cn \
  --arg ns "$NODE_SIZE" \
  --arg svc "$APP_NAME" \
  --arg aid "$existing_agent_id" \
  --argjson allowed_clouds "$allowed_clouds_json" \
  --argjson allowed_datacenters "$allowed_datacenters_json" \
  '{
    node_size: $ns,
    allow_measuring_enclave_fallback: true,
    config: {service_name: $svc}
  }
  + (if $aid != "" then {agent_id: $aid} else {} end)
  + (if ($allowed_clouds | length) > 0 then {allowed_clouds: $allowed_clouds} else {} end)
  + (if ($allowed_datacenters | length) > 0 then {allowed_datacenters: $allowed_datacenters} else {} end)
  ')"

if [ -n "$existing_agent_id" ]; then
  echo "Upgrading existing measurer agent: $existing_agent_id"
else
  echo "No existing measurer agent found; scheduling onto eligible ${NODE_SIZE} capacity"
fi

deploy_resp="$(
  curl -sSf -X POST "${CP_URL}/api/v1/apps/${APP_NAME}/versions/${VERSION}/deploy" \
    -H "Content-Type: application/json" \
    -d "$deploy_body"
)"
deployment_id="$(echo "$deploy_resp" | jq -r '.deployment_id // empty')"
agent_id="$(echo "$deploy_resp" | jq -r '.agent_id // empty')"
echo "Deploying measurer: deployment_id=${deployment_id:-unknown} agent_id=${agent_id:-unknown}"

echo "Waiting for service health..."
for i in {1..90}; do
  svc="$(curl -sSf "${CP_URL}/api/v1/services?name=${APP_NAME}&include_down=true" || echo '{}')"
  healthy="$(echo "$svc" | jq -r --arg n "$APP_NAME" '[.services[]? | select(.name == $n and ((.health_status // "") | ascii_downcase) == "healthy")] | length' 2>/dev/null || echo 0)"
  if [ "${healthy:-0}" -gt 0 ]; then
    echo "Service is healthy: ${APP_NAME}"
    exit 0
  fi
  echo "  not healthy yet ($i/90); waiting 5s..."
  sleep 5
done

echo "::error::Service did not become healthy: ${APP_NAME}"
curl -sS "${CP_URL}/api/v1/services?name=${APP_NAME}&include_down=true" | jq . || true
exit 1
