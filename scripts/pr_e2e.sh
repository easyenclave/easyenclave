#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

require_cmd cargo
require_cmd docker
require_cmd gcloud
require_cmd curl
require_cmd jq

require_var PR_NUMBER
require_var GCP_PROJECT_ID
require_var GCP_SERVICE_ACCOUNT_KEY
require_var CLOUDFLARE_ACCOUNT_ID
require_var CLOUDFLARE_API_TOKEN
require_var CLOUDFLARE_ZONE_ID
require_var ITA_API_KEY

GCP_ZONE="${GCP_ZONE:-us-central1-a}"
PR_PREFIX="ee-pr-${PR_NUMBER}"

echo "[pr-e2e] validating Rust workspace"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
CP_ALLOW_INSECURE_TEST_OIDC=true cargo test --workspace

echo "[pr-e2e] building VM image"
image/build.sh

echo "[pr-e2e] authenticating to GCP"
gcloud_auth_with_key_json GCP_SERVICE_ACCOUNT_KEY GCP_PROJECT_ID

echo "[pr-e2e] checking TDX-capable machine type in ${GCP_ZONE}"
gcloud compute machine-types describe c3-standard-4 --zone "$GCP_ZONE" --format='value(name,guestCpus,memoryMb)'

echo "[pr-e2e] checking Cloudflare API connectivity"
curl -fsS \
  -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
  "https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/cfd_tunnel?is_deleted=false&per_page=1" \
  | jq -e '.success == true' >/dev/null

echo "[pr-e2e] checking Cloudflare DNS zone access"
curl -fsS \
  -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
  "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}" \
  | jq -e '.success == true' >/dev/null

echo "[pr-e2e] completed preflight and local e2e checks for ${PR_PREFIX}"
