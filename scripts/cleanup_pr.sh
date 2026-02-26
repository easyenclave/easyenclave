#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

require_cmd gcloud
require_cmd curl
require_cmd jq

require_var PR_NUMBER
require_var GCP_PROJECT_ID
require_var GCP_SERVICE_ACCOUNT_KEY
require_var CLOUDFLARE_ACCOUNT_ID
require_var CLOUDFLARE_API_TOKEN
require_var CLOUDFLARE_ZONE_ID

PR_PREFIX="ee-pr-${PR_NUMBER}"
GCP_ZONE="${GCP_ZONE:-us-central1-a}"

echo "[cleanup] authenticating to GCP"
gcloud_auth_with_key_json GCP_SERVICE_ACCOUNT_KEY GCP_PROJECT_ID

echo "[cleanup] deleting GCP instances with prefix ${PR_PREFIX}"
mapfile -t INSTANCES < <(gcloud compute instances list \
  --filter="name~'^${PR_PREFIX}'" \
  --format='value(name,zone)' || true)

for entry in "${INSTANCES[@]:-}"; do
  [ -z "$entry" ] && continue
  name="${entry%% *}"
  zone="${entry##* }"
  [ -z "$zone" ] && zone="$GCP_ZONE"
  gcloud compute instances delete "$name" --zone "$zone" --quiet || true
done

echo "[cleanup] deleting GCP images with prefix ${PR_PREFIX}"
mapfile -t IMAGES < <(gcloud compute images list \
  --filter="name~'^${PR_PREFIX}'" \
  --format='value(name)' || true)
for name in "${IMAGES[@]:-}"; do
  [ -z "$name" ] && continue
  gcloud compute images delete "$name" --quiet || true
done

echo "[cleanup] deleting Cloudflare tunnels with prefix ${PR_PREFIX}"
TUNNELS_JSON="$(curl -fsS \
  -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
  "https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel?is_deleted=false")"

mapfile -t TUNNEL_IDS < <(printf '%s' "$TUNNELS_JSON" | jq -r --arg p "$PR_PREFIX" '.result[] | select(.name | startswith($p)) | .id')
for tunnel_id in "${TUNNEL_IDS[@]:-}"; do
  [ -z "$tunnel_id" ] && continue
  curl -fsS -X DELETE \
    -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
    "https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel/${tunnel_id}" >/dev/null || true
done

echo "[cleanup] deleting Cloudflare CNAME records with prefix ${PR_PREFIX}"
DNS_JSON="$(curl -fsS \
  -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
  "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records?type=CNAME&per_page=500")"

mapfile -t DNS_IDS < <(printf '%s' "$DNS_JSON" | jq -r --arg p "$PR_PREFIX" '.result[] | select(.name | startswith($p)) | .id')
for dns_id in "${DNS_IDS[@]:-}"; do
  [ -z "$dns_id" ] && continue
  curl -fsS -X DELETE \
    -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
    "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records/${dns_id}" >/dev/null || true
done

echo "[cleanup] completed for ${PR_PREFIX}"
