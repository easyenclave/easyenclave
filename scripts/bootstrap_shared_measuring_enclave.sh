#!/usr/bin/env bash
# Bootstrap a size-specific measuring enclave on an existing control plane.
#
# This is the "chicken-and-egg" path: we publish measuring-enclave-$NODE_SIZE,
# then manually attest it with CI-measured baseline values (MRTD/RTMRs), then deploy it.
#
# Required env:
#   CP_URL
#   ADMIN_PASSWORD  (control plane admin password)
#   NODE_SIZE       (tiny|standard|llm)
#   MEASURER_IMAGE  (ghcr.io/.../measuring-enclave:tag)
#   TRUSTED_AGENT_MRTDS_BY_SIZE (JSON map, e.g. {"llm":"...","tiny":"..."})
#   TRUSTED_AGENT_RTMRS_BY_SIZE (JSON map, e.g. {"llm":{"rtmr0":"...","rtmr1":"...","rtmr2":"...","rtmr3":"..."}})
set -euo pipefail

require() {
  for v in "$@"; do
    if [ -z "${!v:-}" ]; then
      echo "::error::Missing required env var: $v"
      exit 1
    fi
  done
}

require CP_URL ADMIN_PASSWORD NODE_SIZE MEASURER_IMAGE TRUSTED_AGENT_MRTDS_BY_SIZE TRUSTED_AGENT_RTMRS_BY_SIZE

case "$NODE_SIZE" in
  tiny|standard|llm) ;;
  *)
    echo "::error::Unsupported NODE_SIZE='$NODE_SIZE' (expected tiny|standard|llm)"
    exit 1
    ;;
esac

APP_NAME="measuring-enclave-${NODE_SIZE}"
DESCRIPTION="Measuring enclave for ${NODE_SIZE} node attestation"

ADMIN_TOKEN="$(
  curl -sf "${CP_URL}/admin/login" \
    -H "Content-Type: application/json" \
    -d "{\"password\": \"${ADMIN_PASSWORD}\"}" \
  | jq -r '.token'
)"
if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" = "null" ]; then
  echo "::error::Admin login failed (missing token)"
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
deploy_resp="$(
  curl -sSf -X POST "${CP_URL}/api/v1/apps/${APP_NAME}/versions/${VERSION}/deploy" \
    -H "Content-Type: application/json" \
    -d "$(jq -cn --arg ns "$NODE_SIZE" --arg svc "$APP_NAME" '{node_size:$ns, config:{service_name:$svc}}')"
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
