#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "$ROOT_DIR"

log() {
  echo "[private-llm-example] $*"
}

fatal() {
  echo "[private-llm-example] ERROR: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fatal "missing required command: $1"
}

require_cmd bash
require_cmd curl
require_cmd jq
require_cmd gcloud
require_cmd python3

: "${CP_URL:=https://app.easyenclave.com}"
: "${NODE_SIZE:=llm}"
: "${MODEL_NAME:=smollm2:135m}"
: "${REGISTER_TIMEOUT_SECONDS:=1200}"
: "${DEPLOY_TIMEOUT_SECONDS:=900}"
: "${OPENAI_TIMEOUT_SECONDS:=600}"
: "${KEEP_VM:=true}"
: "${POLL_SECONDS:=10}"
: "${TUNNEL_DOMAIN:=}"

if [ -n "${GITHUB_RUN_ID:-}" ]; then
  : "${APP_NAME:=private-llm-${GITHUB_RUN_ID}}"
else
  : "${APP_NAME:=private-llm-demo}"
fi

[ -n "${ITA_API_KEY:-}" ] || fatal "ITA_API_KEY is required"
[ -n "${GCP_PROJECT_ID:-}" ] || fatal "GCP_PROJECT_ID is required"

case "$NODE_SIZE" in
  tiny|standard|llm) ;;
  *) fatal "invalid NODE_SIZE '$NODE_SIZE' (expected tiny|standard|llm)" ;;
esac

export EASYENCLAVE_ENV="${EASYENCLAVE_ENV:-production}"
export EASYENCLAVE_NETWORK_NAME="${EASYENCLAVE_NETWORK_NAME:-production}"
export EE_GCP_IMAGE_FAMILY="${EE_GCP_IMAGE_FAMILY:-easyenclave-agent-main}"

DEPLOY_BEARER_TOKEN="${DEPLOY_BEARER_TOKEN:-${CP_DEPLOYER_API_KEY:-}}"
if [ -z "${DEPLOY_BEARER_TOKEN}" ]; then
  log "No deploy bearer token provided; creating one-time deployer account"
  account_suffix="$(date +%s)-$RANDOM"
  create_resp="$(
    jq -n \
      --arg name "gha-private-llm-${account_suffix}" \
      '{name: $name, account_type: "deployer"}' | \
    curl -fsS -X POST "${CP_URL}/api/accounts" \
      -H "Content-Type: application/json" \
      -d @-
  )"
  DEPLOY_BEARER_TOKEN="$(echo "$create_resp" | jq -r '.api_key // ""')"
  [ -n "$DEPLOY_BEARER_TOKEN" ] || fatal "failed to create deployer api key"
fi

VM_NAME=""
VM_ZONE=""
cleanup() {
  if [ "${KEEP_VM}" != "false" ]; then
    return 0
  fi
  if [ -z "$VM_NAME" ]; then
    return 0
  fi
  log "KEEP_VM=false, deleting VM ${VM_NAME}"
  bash crates/ee-ops/assets/gcp-nodectl.sh vm delete "$VM_NAME" || true
}
trap cleanup EXIT

log "Launching ${NODE_SIZE} TDX VM in project ${GCP_PROJECT_ID} for ${CP_URL}"
if [ -n "${GCP_ZONE:-}" ]; then
  AGENT_JSON="$(
    bash crates/ee-ops/assets/gcp-nodectl.sh vm new \
      --size "$NODE_SIZE" \
      --cp-url "$CP_URL" \
      --ita-api-key "$ITA_API_KEY" \
      --zone "$GCP_ZONE" \
      --wait \
      --timeout "$REGISTER_TIMEOUT_SECONDS"
  )"
else
  AGENT_JSON="$(
    bash crates/ee-ops/assets/gcp-nodectl.sh vm new \
      --size "$NODE_SIZE" \
      --cp-url "$CP_URL" \
      --ita-api-key "$ITA_API_KEY" \
      --wait \
      --timeout "$REGISTER_TIMEOUT_SECONDS"
  )"
fi

VM_NAME="$(echo "$AGENT_JSON" | jq -r '.name')"
VM_ZONE="$(echo "$AGENT_JSON" | jq -r '.zone')"
[ -n "$VM_NAME" ] || fatal "failed to parse VM name from gcp-nodectl output"
[ -n "$VM_ZONE" ] || fatal "failed to parse VM zone from gcp-nodectl output"
log "Launched VM name=${VM_NAME} zone=${VM_ZONE}"

deadline=$(( $(date +%s) + REGISTER_TIMEOUT_SECONDS ))
AGENT_ID=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  agent_row="$(curl -fsS "${CP_URL}/api/agents" | jq -c --arg vm "$VM_NAME" '[.[] | select(.vm_name == $vm)] | last // empty')"
  if [ -n "$agent_row" ] && [ "$agent_row" != "null" ]; then
    AGENT_ID="$(echo "$agent_row" | jq -r '.agent_id // ""')"
    status="$(echo "$agent_row" | jq -r '.status // ""')"
    if [ -n "$AGENT_ID" ] && [ "$status" = "undeployed" ]; then
      break
    fi
  fi
  sleep "$POLL_SECONDS"
done

[ -n "$AGENT_ID" ] || fatal "timed out waiting for agent registration in control plane"

if [ -z "$TUNNEL_DOMAIN" ]; then
  cp_host="$(echo "$CP_URL" | sed -E 's#^https?://##; s#/.*$##')"
  case "$cp_host" in
    app.*) TUNNEL_DOMAIN="${cp_host#app.}" ;;
    app-staging.*) TUNNEL_DOMAIN="${cp_host#app-staging.}" ;;
    *) TUNNEL_DOMAIN="$cp_host" ;;
  esac
fi

[ -n "$TUNNEL_DOMAIN" ] || fatal "failed to resolve tunnel domain"
HOSTNAME="${VM_NAME}.${TUNNEL_DOMAIN}"
log "Agent registered agent_id=${AGENT_ID} hostname=${HOSTNAME}"

deploy_payload="$(
  jq -n \
    --rawfile compose examples/private-llm/docker-compose.yml \
    --arg app_name "$APP_NAME" \
    --arg agent_name "$VM_NAME" \
    --arg node_size "$NODE_SIZE" \
    '{
      compose: $compose,
      app_name: $app_name,
      agent_name: $agent_name,
      node_size: $node_size
    }'
)"

log "Deploying app_name=${APP_NAME} to agent=${VM_NAME}"
deploy_response="$(
  curl -fsS -X POST "${CP_URL}/api/deploy" \
    -H "Authorization: Bearer ${DEPLOY_BEARER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$deploy_payload"
)"
DEPLOYMENT_ID="$(echo "$deploy_response" | jq -r '.deployment_id // ""')"
[ -n "$DEPLOYMENT_ID" ] || fatal "deployment request failed: $deploy_response"
log "Created deployment deployment_id=${DEPLOYMENT_ID}"

deadline=$(( $(date +%s) + DEPLOY_TIMEOUT_SECONDS ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  deploy_status="$(curl -fsS "${CP_URL}/api/deployments/${DEPLOYMENT_ID}" | jq -r '.status // ""')"
  case "$deploy_status" in
    running)
      break
      ;;
    failed|stopped)
      fatal "deployment entered terminal status=${deploy_status}"
      ;;
  esac
  sleep "$POLL_SECONDS"
done
[ "${deploy_status:-}" = "running" ] || fatal "timed out waiting for deployment to become running"
log "Deployment is running"

SERVICE_URL="https://${HOSTNAME}"
export SERVICE_URL MODEL_NAME OPENAI_TIMEOUT_SECONDS
log "Running OpenAI compatibility smoke test against ${SERVICE_URL}"
python3 - <<'PY'
import os
import time

import httpx
from openai import OpenAI

service_url = os.environ["SERVICE_URL"].rstrip("/")
model_name = os.environ["MODEL_NAME"]
timeout_seconds = int(os.environ["OPENAI_TIMEOUT_SECONDS"])
deadline = time.monotonic() + timeout_seconds

def strip_bot_headers(request: httpx.Request) -> None:
    request.headers["user-agent"] = "EasyEnclave-OpenAI-Smoke/1.0"
    for key in [k for k in request.headers if k.lower().startswith("x-stainless-")]:
        del request.headers[key]

client = OpenAI(
    base_url=f"{service_url}/v1",
    api_key="unused",
    http_client=httpx.Client(
        timeout=60.0,
        event_hooks={"request": [strip_bot_headers]},
    ),
)

while True:
    try:
        completion = client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": "Reply with exactly: easyenclave-ok"}],
            timeout=60,
        )
        content = completion.choices[0].message.content or ""
        print(f"[openai-smoke] response={content}")
        if content.strip():
            break
    except Exception as exc:
        if time.monotonic() >= deadline:
            raise SystemExit(f"openai smoke test timed out after {timeout_seconds}s: {exc}")
        print(f"[openai-smoke] model not ready yet ({exc}); retrying in 15s")
        time.sleep(15)
PY

summary_json="$(
  jq -n \
    --arg vm_name "$VM_NAME" \
    --arg vm_zone "$VM_ZONE" \
    --arg agent_id "$AGENT_ID" \
    --arg hostname "$HOSTNAME" \
    --arg deployment_id "$DEPLOYMENT_ID" \
    --arg app_name "$APP_NAME" \
    --arg model_name "$MODEL_NAME" \
    '{
      vm_name: $vm_name,
      vm_zone: $vm_zone,
      agent_id: $agent_id,
      hostname: $hostname,
      service_url: ("https://" + $hostname),
      deployment_id: $deployment_id,
      app_name: $app_name,
      model_name: $model_name
    }'
)"

log "Completed successfully"
echo "$summary_json" | jq .

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "vm_name=${VM_NAME}"
    echo "vm_zone=${VM_ZONE}"
    echo "agent_id=${AGENT_ID}"
    echo "hostname=${HOSTNAME}"
    echo "service_url=https://${HOSTNAME}"
    echo "deployment_id=${DEPLOYMENT_ID}"
    echo "app_name=${APP_NAME}"
    echo "model_name=${MODEL_NAME}"
  } >> "$GITHUB_OUTPUT"
fi
