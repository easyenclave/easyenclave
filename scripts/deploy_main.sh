#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

require_cmd cargo
require_cmd docker
require_cmd gcloud

require_var PRODUCTION_GCP_PROJECT_ID
require_var PRODUCTION_GCP_SERVICE_ACCOUNT_KEY

GCP_ZONE="${PRODUCTION_GCP_ZONE:-us-central1-a}"

echo "[deploy] building release binaries"
cargo build --release --workspace

echo "[deploy] building VM image"
image/build.sh

echo "[deploy] authenticating to production GCP"
gcloud_auth_with_key_json PRODUCTION_GCP_SERVICE_ACCOUNT_KEY PRODUCTION_GCP_PROJECT_ID

echo "[deploy] validating machine type availability in ${GCP_ZONE}"
gcloud compute machine-types describe c3-standard-4 --zone "$GCP_ZONE" --format='value(name,guestCpus,memoryMb)'

echo "[deploy] build and production preflight completed"
