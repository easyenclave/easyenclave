#!/usr/bin/env bash
# Add a trusted agent MRTD baseline to the control plane (admin-only).
#
# Intended for CI/bootstrap where the CP has no trusted baselines yet and newly
# launched agents would otherwise remain unverified forever.
#
# Required env:
#   CP_URL
#   NODE_SIZE                        (tiny|standard|llm) informational only
#   TRUSTED_AGENT_MRTDS_BY_SIZE      JSON map: {"tiny":"...","llm":"..."}
#
# Optional env:
#   ADMIN_TOKEN      Bearer token for /api/v1/admin/*
#   ADMIN_PASSWORD   Admin password for /admin/login (falls back to /auth/methods generated_password)
#   NOTE             Optional note string stored with the baseline (default: ci:<node_size>)
set -euo pipefail

require() {
  for v in "$@"; do
    if [ -z "${!v:-}" ]; then
      echo "::error::Missing required env var: $v"
      exit 1
    fi
  done
}

require CP_URL NODE_SIZE TRUSTED_AGENT_MRTDS_BY_SIZE

case "${NODE_SIZE}" in
  tiny|standard|llm) ;;
  *)
    echo "::error::Unsupported NODE_SIZE='${NODE_SIZE}' (expected tiny|standard|llm)"
    exit 1
    ;;
esac

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

mrtd="$(
  echo "${TRUSTED_AGENT_MRTDS_BY_SIZE}" | jq -r --arg ns "${NODE_SIZE}" '.[$ns] // empty' 2>/dev/null || true
)"
if [ -z "${mrtd:-}" ]; then
  echo "::error::TRUSTED_AGENT_MRTDS_BY_SIZE is missing key '${NODE_SIZE}'"
  exit 1
fi
if ! echo "$mrtd" | grep -Eq '^[0-9a-fA-F]{96}$'; then
  echo "::error::Invalid MRTD format for node_size=${NODE_SIZE}: '$mrtd'"
  exit 1
fi
mrtd="$(echo "$mrtd" | tr '[:upper:]' '[:lower:]')"

trusted_count="$(
  curl -sS -H 'Accept: application/json' "${CP_URL}/api/v1/trusted-mrtds" \
    | jq -r --arg m "$mrtd" '[.trusted_mrtds[] | select(.mrtd == $m)] | length' 2>/dev/null || echo 0
)"
if [ "${trusted_count:-0}" -gt 0 ]; then
  echo "Agent MRTD already trusted for node_size=${NODE_SIZE}: ${mrtd:0:16}..."
  exit 0
fi

admin_token="${ADMIN_TOKEN:-}"
if [ -z "$admin_token" ] && [ -n "${ADMIN_PASSWORD:-}" ]; then
  admin_token="$(login_with_password "${ADMIN_PASSWORD}" || true)"
fi
if [ -z "$admin_token" ]; then
  generated_pw="$(curl -sSf "${CP_URL}/auth/methods" | jq -r '.generated_password // empty' || true)"
  if [ -n "$generated_pw" ]; then
    admin_token="$(login_with_password "$generated_pw" || true)"
  fi
fi
if [ -z "$admin_token" ]; then
  echo "::error::Unable to obtain admin token (set ADMIN_TOKEN or provide ADMIN_PASSWORD / generated_password)."
  exit 1
fi
echo "::add-mask::${admin_token}"

note="${NOTE:-ci:${NODE_SIZE}}"
payload="$(jq -cn --arg m "$mrtd" --arg note "$note" '{mrtd: $m, type: "agent", note: $note}')"

resp=""
http_code="000"
for attempt in $(seq 1 10); do
  tmp="$(mktemp)"
  http_code="$(
    curl -sS -o "$tmp" -w "%{http_code}" \
      -X POST "${CP_URL}/api/v1/admin/trusted-mrtds" \
      -H "Authorization: Bearer ${admin_token}" \
      -H "Content-Type: application/json" \
      -d "$payload" || echo 000
  )"
  resp="$(cat "$tmp")"
  rm -f "$tmp"
  if [ "$http_code" = "530" ] || [ "$http_code" = "000" ] || [ "$http_code" -ge 500 ]; then
    echo "::warning::Trusted MRTD add failed (HTTP ${http_code}); retrying ($attempt/10)..."
    sleep 3
    continue
  fi
  break
done

if [ "$http_code" -ge 400 ]; then
  detail="$(echo "$resp" | jq -r '.detail // empty' 2>/dev/null || true)"
  echo "::error::Failed to add trusted agent MRTD (HTTP $http_code): ${detail:-$resp}"
  exit 1
fi

echo "Added trusted agent MRTD baseline for node_size=${NODE_SIZE}: ${mrtd:0:16}..."
