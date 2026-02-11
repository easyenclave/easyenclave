#!/usr/bin/env bash
# Deploy control plane, launch agents, and bootstrap apps.
#
# Required env vars:
#   TRUSTED_AGENT_MRTDS  - from ci-build-measure.sh
#   TRUSTED_AGENT_RTMRS  - from ci-build-measure.sh
#   INTEL_API_KEY        - Intel Trust Authority key
#   ITA_API_KEY          - alias (usually same as INTEL_API_KEY)
#   MEASURER_IMAGE       - ghcr.io image ref for measuring enclave
#   ORAM_IMAGE           - ghcr.io image ref for oram-contacts
#
# Optional env vars:
#   CP_URL      - control plane URL (default: https://app.easyenclave.com)
#   NUM_AGENTS  - number of agents to launch (default: 5)
#   ADMIN_PASSWORD - admin password (auto-detected from CP logs if not set)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

CP_URL="${CP_URL:-https://app.easyenclave.com}"
NUM_AGENTS="${NUM_AGENTS:-5}"

# ===================================================================
# Helpers
# ===================================================================

admin_login() {
  local resp token
  echo "Logging in to admin panel..."
  resp=$(curl -sf -w "\nHTTP_CODE:%{http_code}" "$CP_URL/admin/login" \
    -H "Content-Type: application/json" \
    -d "{\"password\": \"$ADMIN_PASSWORD\"}")
  token=$(echo "$resp" | grep -v "HTTP_CODE:" | jq -r '.token')
  if [ -z "$token" ] || [ "$token" = "null" ]; then
    echo "Admin login failed"
    echo "$resp"
    exit 1
  fi
  echo "Admin login successful"
  echo "$token"
}

# deploy_app APP_NAME DESCRIPTION IMAGE TAGS SERVICE_CONFIG
#   Registers app, publishes version, attests, deploys, waits healthy.
deploy_app() {
  local app_name="$1" description="$2" image="$3" tags="$4" service_config="$5"
  local compose_b64 version publish_resp version_id
  local deployed=false agent_ids agent_id http_code

  echo ""
  echo "===== Deploying $app_name ====="

  # Register app (idempotent)
  curl -f -X POST "$CP_URL/api/v1/apps" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"$app_name\", \"description\": \"$description\"${tags:+, \"tags\": $tags}}" \
    2>&1 || echo "App may already exist (ok)"

  # Build compose and publish version
  compose_b64=$(echo "$image" | make_compose "$app_name" | base64 -w 0)
  version="bootstrap-$(date -u +%Y%m%d-%H%M%S)"

  echo "Publishing $app_name version $version..."
  publish_resp=$(curl -sf -X POST "$CP_URL/api/v1/apps/$app_name/versions" \
    -H "Content-Type: application/json" \
    -d "{\"version\": \"$version\", \"compose\": \"$compose_b64\"}")
  version_id=$(echo "$publish_resp" | jq -r '.version_id')
  echo "Published $app_name@$version ($version_id)"

  # Manual attest (bootstrap)
  echo "Manually attesting $app_name version $version..."
  curl -sf -X POST "$CP_URL/api/v1/apps/$app_name/versions/$version/attest" \
    -H "Authorization: Bearer $ADMIN_TOKEN"
  echo "Attested $app_name@$version"

  # Find undeployed agent and deploy (retry)
  for attempt in {1..12}; do
    agent_ids=$(curl -f "$CP_URL/api/v1/agents" 2>/dev/null | \
      jq -r '[.agents[] | select(.verified == true and .hostname != null and .status == "undeployed")] | .[].agent_id')

    for agent_id in $agent_ids; do
      local agent_host
      agent_host=$(curl -f "$CP_URL/api/v1/agents/$agent_id" 2>/dev/null | jq -r '.hostname')
      echo "Trying agent $agent_id ($agent_host)..."

      # Check tunnel reachable
      if ! curl -sf "https://$agent_host/api/health" > /dev/null 2>&1; then
        echo "  Tunnel not reachable, skipping"
        continue
      fi

      http_code=$(curl -s -o /tmp/deploy_resp.json -w "%{http_code}" \
        -X POST "$CP_URL/api/v1/apps/$app_name/versions/$version/deploy" \
        -H "Content-Type: application/json" \
        -d "{\"agent_id\": \"$agent_id\", \"config\": $service_config}")

      if [ "$http_code" -lt 400 ]; then
        echo "Deployed $app_name to agent $agent_id"
        deployed=true
        break 2
      fi
      echo "  HTTP $http_code: $(jq -r '.detail // empty' /tmp/deploy_resp.json)"
    done

    echo "No available agents, waiting 30s... ($attempt/12)"
    sleep 30
  done

  if [ "$deployed" != "true" ]; then
    echo "::error::Could not deploy $app_name after 12 attempts"
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
  exit 1
}

# Compose generators (read image from stdin)
make_compose() {
  local app_name="$1"
  local image
  read -r image
  case "$app_name" in
    measuring-enclave)
      printf 'services:\n  measuring-enclave:\n    image: %s\n    ports:\n      - "8080:8080"\n' "$image"
      ;;
    oram-contacts)
      printf 'services:\n  oram-contacts:\n    image: %s\n    ports:\n      - "8080:8080"\n    volumes:\n      - oram-data:/data\n    environment:\n      - ORAM_DB_PATH=/data/contacts.db\n      - ORAM_BUCKETS=1024\n      - ORAM_STASH_SIZE=100\nvolumes:\n  oram-data:\n' "$image"
      ;;
    *)
      printf 'services:\n  %s:\n    image: %s\n    ports:\n      - "8080:8080"\n' "$app_name" "$image"
      ;;
  esac
}

# ===================================================================
# 1. Delete all existing VMs
# ===================================================================
echo "==> Deleting all existing VMs..."
python3 infra/tdx_cli.py vm delete all || true

# ===================================================================
# 2. Deploy control plane
# ===================================================================
echo "==> Deploying control plane..."
python3 infra/tdx_cli.py control-plane new --verity --wait --port 8080

# ===================================================================
# 3. Wait for Cloudflare tunnel
# ===================================================================
echo "==> Waiting for tunnel..."
for _i in {1..30}; do
  if curl -sf "$CP_URL/health" > /dev/null 2>&1; then
    echo "Tunnel is up"
    break
  fi
  sleep 10
done
if ! curl -sf "$CP_URL/health" > /dev/null 2>&1; then
  echo "::error::Tunnel not ready after 5 minutes"
  exit 1
fi

# Get admin password (from env or auto-generated by control plane)
if [ -z "${ADMIN_PASSWORD:-}" ]; then
  ADMIN_PASSWORD=$(curl -sf "$CP_URL/auth/methods" | jq -r '.generated_password // empty')
fi
if [ -z "${ADMIN_PASSWORD:-}" ]; then
  echo "::error::Could not determine admin password"
  exit 1
fi

# ===================================================================
# 4. Launch agents in parallel
# ===================================================================
echo "==> Launching $NUM_AGENTS agents..."
for _i in $(seq 1 "$NUM_AGENTS"); do
  python3 infra/tdx_cli.py vm new --verity \
    --easyenclave-url "$CP_URL" \
    --intel-api-key "$INTEL_API_KEY" \
    --memory 4 --vcpus 4 --wait &
done
wait
echo "All $NUM_AGENTS agents launched"

# ===================================================================
# 5. Wait for agents to register and verify
# ===================================================================
echo "==> Waiting for $NUM_AGENTS agents to register and be verified..."
for i in {1..30}; do
  AGENTS=$(curl -sf "$CP_URL/api/v1/agents" 2>/dev/null || echo '{"agents":[]}')
  VERIFIED=$(echo "$AGENTS" | jq '[.agents[] | select(.verified == true)] | length')
  if [ "$VERIFIED" -ge "$NUM_AGENTS" ]; then
    echo "All $NUM_AGENTS agents verified"
    break
  elif [ "$VERIFIED" -ge $((NUM_AGENTS - 1)) ]; then
    echo "Warning: only $VERIFIED/$NUM_AGENTS agents verified"
  fi
  echo "$VERIFIED/$NUM_AGENTS agents verified, waiting... ($i/30)"
  sleep 10
done

VERIFIED=$(curl -sf "$CP_URL/api/v1/agents" 2>/dev/null | jq '[.agents[] | select(.verified == true)] | length')
if [ "$VERIFIED" -lt "$NUM_AGENTS" ]; then
  echo "::error::Not all agents verified after 5 minutes ($VERIFIED/$NUM_AGENTS)"
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
ADMIN_TOKEN=$(admin_login)

deploy_app "measuring-enclave" \
  "Measuring enclave for app version attestation" \
  "$MEASURER_IMAGE" \
  "" \
  '{"service_name": "measuring-enclave"}'

deploy_app "oram-contacts" \
  "Privacy-preserving contact discovery with ORAM" \
  "$ORAM_IMAGE" \
  '["privacy", "oram", "contacts", "example"]' \
  '{"service_name": "oram-contacts", "health_endpoint": "/health"}'

echo "==> Deploy complete!"
