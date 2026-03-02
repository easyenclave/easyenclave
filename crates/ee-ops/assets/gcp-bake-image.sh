#!/usr/bin/env bash
# Build an EasyEnclave GCP image with Packer.
set -euo pipefail

log() {
  echo "[gcp_bake_image] $*"
}

fail() {
  echo "::error::$*"
  exit 1
}

require_cmd() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    fail "Missing required command: ${name}"
  fi
}

require_var() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    fail "Missing required value: ${name}"
  fi
}

trim() {
  local value="$1"
  echo "$value" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//'
}

sanitize_label_value() {
  local value
  value="$(echo "${1:-}" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9_-]+/-/g; s/^[-_]+//; s/[-_]+$//; s/[-_]{2,}/-/g')"
  if [ -z "$value" ]; then
    value="na"
  fi
  echo "${value:0:63}"
}

sanitize_label_key() {
  local key
  key="$(echo "${1:-}" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9_-]+/-/g; s/^-+//; s/-+$//; s/-{2,}/-/g')"
  if [ -z "$key" ]; then
    key="x"
  fi
  if ! [[ "$key" =~ ^[a-z] ]]; then
    key="x-${key}"
  fi
  echo "${key:0:63}"
}

write_bake_metadata() {
  local reused_flag="$1"
  [ -n "${BAKE_METADATA_PATH}" ] || return 0

  mkdir -p "$(dirname "${BAKE_METADATA_PATH}")"
  jq -cn \
    --arg target_project "${GCP_PROJECT_ID}" \
    --arg target_image_name "${TARGET_IMAGE_NAME}" \
    --arg target_image_family "${TARGET_IMAGE_FAMILY}" \
    --arg source_image_project "${SOURCE_IMAGE_PROJECT}" \
    --arg source_selector "${source_selector}" \
    --arg source_value "${source_value}" \
    --arg source_image_name_resolved "${resolved_source_name}" \
    --arg source_image_family_resolved "${resolved_source_family}" \
    --arg source_image_self_link "${resolved_source_self_link}" \
    --arg source_sha "${SOURCE_SHA}" \
    --arg build_tool "packer" \
    --argjson reused "${reused_flag}" \
    '{
      target_project: $target_project,
      target_image_name: $target_image_name,
      target_image_family: $target_image_family,
      source_image_project: $source_image_project,
      source_selector: $source_selector,
      source_value: $source_value,
      source_image_name_resolved: $source_image_name_resolved,
      source_image_family_resolved: $source_image_family_resolved,
      source_image_self_link: $source_image_self_link,
      source_sha: $source_sha,
      build_tool: $build_tool,
      reused: $reused
    }' > "${BAKE_METADATA_PATH}"
}

require_cmd gcloud
require_cmd jq
require_cmd packer

require_var GCP_PROJECT_ID
require_var SOURCE_IMAGE_PROJECT
require_var TARGET_IMAGE_NAME

if [ -z "${SOURCE_IMAGE_NAME:-}" ] && [ -z "${SOURCE_IMAGE_FAMILY:-}" ]; then
  fail "Set SOURCE_IMAGE_NAME or SOURCE_IMAGE_FAMILY."
fi

if [ -n "${BUILD_MACHINE_TYPE:-}" ] && [[ "${BUILD_MACHINE_TYPE}" == *,* ]]; then
  fail "BUILD_MACHINE_TYPE must be a single machine type; got '${BUILD_MACHINE_TYPE}'."
fi

BUILD_ZONE="$(trim "${BUILD_ZONE:-us-central1-a}")"
BUILD_MACHINE_TYPE="$(trim "${BUILD_MACHINE_TYPE:-e2-standard-4}")"
BUILD_BOOT_DISK_GB="$(trim "${BUILD_BOOT_DISK_GB:-200}")"
TARGET_IMAGE_FAMILY="$(trim "${TARGET_IMAGE_FAMILY:-}")"
TARGET_IMAGE_DESCRIPTION="$(trim "${TARGET_IMAGE_DESCRIPTION:-EasyEnclave image bake}")"
TARGET_IMAGE_LABELS="$(trim "${TARGET_IMAGE_LABELS:-}")"
SOURCE_SHA="$(trim "${SOURCE_SHA:-}")"
BAKE_METADATA_PATH="$(trim "${BAKE_METADATA_PATH:-}")"
EE_AGENT_BINARY_PATH="$(trim "${EE_AGENT_BINARY_PATH:-}")"
PACKER_TEMPLATE_PATH="$(trim "${PACKER_TEMPLATE_PATH:-crates/ee-ops/assets/packer/gcp-agent-image.pkr.hcl}")"

if ! [[ "${BUILD_BOOT_DISK_GB}" =~ ^[0-9]+$ ]]; then
  fail "BUILD_BOOT_DISK_GB must be an integer; got '${BUILD_BOOT_DISK_GB}'."
fi

if [ ! -f "${PACKER_TEMPLATE_PATH}" ]; then
  fail "Missing packer template: ${PACKER_TEMPLATE_PATH}"
fi

AGENT_BINARY_PATH=""
if [ -n "${EE_AGENT_BINARY_PATH}" ]; then
  if [ ! -f "${EE_AGENT_BINARY_PATH}" ]; then
    fail "Configured EE_AGENT_BINARY_PATH does not exist: ${EE_AGENT_BINARY_PATH}"
  fi
  chmod 0755 "${EE_AGENT_BINARY_PATH}" || fail "Could not make EE_AGENT_BINARY_PATH executable: ${EE_AGENT_BINARY_PATH}"
  AGENT_BINARY_PATH="${EE_AGENT_BINARY_PATH}"
  log "Using prebuilt ee-agent binary: ${AGENT_BINARY_PATH}"
else
  if [ ! -f "crates/ee-agent/src/main.rs" ]; then
    fail "Missing required file: crates/ee-agent/src/main.rs"
  fi
  require_cmd cargo
  log "Building ee-agent (release)..."
  cargo build -p ee-agent --release
  if [ ! -x "target/release/ee-agent" ]; then
    fail "ee-agent binary not found after build: target/release/ee-agent"
  fi
  AGENT_BINARY_PATH="target/release/ee-agent"
fi

source_selector=""
source_value=""
resolved_source_name=""
resolved_source_family=""
resolved_source_self_link=""
packer_source_image_name=""
packer_source_image_family=""

if [ -n "${SOURCE_IMAGE_NAME:-}" ]; then
  if ! gcloud compute images describe "${SOURCE_IMAGE_NAME}" --project "${SOURCE_IMAGE_PROJECT}" >/dev/null 2>&1; then
    fail "Configured source image '${SOURCE_IMAGE_NAME}' not found in project '${SOURCE_IMAGE_PROJECT}'."
  fi
  source_selector="name"
  source_value="${SOURCE_IMAGE_NAME}"
  packer_source_image_name="${SOURCE_IMAGE_NAME}"
  resolved_source_name="$(gcloud compute images describe "${SOURCE_IMAGE_NAME}" --project "${SOURCE_IMAGE_PROJECT}" --format='value(name)')"
  resolved_source_family="$(gcloud compute images describe "${SOURCE_IMAGE_NAME}" --project "${SOURCE_IMAGE_PROJECT}" --format='value(family)')"
  resolved_source_self_link="$(gcloud compute images describe "${SOURCE_IMAGE_NAME}" --project "${SOURCE_IMAGE_PROJECT}" --format='value(selfLink)')"
fi

if [ -z "${source_selector}" ] && [ -n "${SOURCE_IMAGE_FAMILY:-}" ]; then
  if ! gcloud compute images describe-from-family "${SOURCE_IMAGE_FAMILY}" --project "${SOURCE_IMAGE_PROJECT}" >/dev/null 2>&1; then
    fail "Configured source image family '${SOURCE_IMAGE_FAMILY}' not found in project '${SOURCE_IMAGE_PROJECT}'."
  fi
  source_selector="family"
  source_value="${SOURCE_IMAGE_FAMILY}"
  packer_source_image_family="${SOURCE_IMAGE_FAMILY}"
  resolved_source_name="$(gcloud compute images describe-from-family "${SOURCE_IMAGE_FAMILY}" --project "${SOURCE_IMAGE_PROJECT}" --format='value(name)')"
  resolved_source_family="$(gcloud compute images describe-from-family "${SOURCE_IMAGE_FAMILY}" --project "${SOURCE_IMAGE_PROJECT}" --format='value(family)')"
  resolved_source_self_link="$(gcloud compute images describe-from-family "${SOURCE_IMAGE_FAMILY}" --project "${SOURCE_IMAGE_PROJECT}" --format='value(selfLink)')"
fi

if [ -z "${source_selector}" ] || [ -z "${source_value}" ] || [ -z "${resolved_source_name}" ]; then
  fail "No usable source image selector resolved."
fi

if gcloud compute images describe "${TARGET_IMAGE_NAME}" --project "${GCP_PROJECT_ID}" >/dev/null 2>&1; then
  log "Image already exists: ${GCP_PROJECT_ID}/${TARGET_IMAGE_NAME}"
  write_bake_metadata true
  exit 0
fi

labels_json="$(jq -cn \
  --arg source_image "$(sanitize_label_value "${resolved_source_name}")" \
  --arg source_project "$(sanitize_label_value "${SOURCE_IMAGE_PROJECT}")" \
  '{
    easyenclave: "managed",
    ee_image_bake: "true",
    ee_source_image: $source_image,
    ee_source_project: $source_project
  }')"

if [ -n "${SOURCE_SHA}" ]; then
  labels_json="$(echo "${labels_json}" | jq --arg sha "$(sanitize_label_value "${SOURCE_SHA:0:12}")" '. + {ee_git_sha: $sha}')"
fi

if [ -n "${TARGET_IMAGE_LABELS}" ]; then
  IFS=',' read -r -a extra_labels <<< "${TARGET_IMAGE_LABELS}"
  for item in "${extra_labels[@]}"; do
    item="$(trim "${item}")"
    [ -n "${item}" ] || continue
    if [[ "${item}" != *=* ]]; then
      fail "Invalid TARGET_IMAGE_LABELS entry '${item}' (expected key=value)."
    fi

    key="${item%%=*}"
    value="${item#*=}"
    key="$(sanitize_label_key "$(trim "${key}")")"
    value="$(sanitize_label_value "$(trim "${value}")")"

    labels_json="$(echo "${labels_json}" | jq --arg k "${key}" --arg v "${value}" '. + {($k): $v}')"
  done
fi
labels_json="$(echo "${labels_json}" | jq -c '.')"

log "Running Packer build for ${GCP_PROJECT_ID}/${TARGET_IMAGE_NAME}"
packer init "${PACKER_TEMPLATE_PATH}"
packer build \
  -color=false \
  -var "project_id=${GCP_PROJECT_ID}" \
  -var "build_zone=${BUILD_ZONE}" \
  -var "build_machine_type=${BUILD_MACHINE_TYPE}" \
  -var "build_boot_disk_gb=${BUILD_BOOT_DISK_GB}" \
  -var "target_image_name=${TARGET_IMAGE_NAME}" \
  -var "target_image_family=${TARGET_IMAGE_FAMILY}" \
  -var "target_image_description=${TARGET_IMAGE_DESCRIPTION}" \
  -var "source_image_project=${SOURCE_IMAGE_PROJECT}" \
  -var "source_image_name=${packer_source_image_name}" \
  -var "source_image_family=${packer_source_image_family}" \
  -var "image_labels_json=${labels_json}" \
  -var "agent_binary_path=${AGENT_BINARY_PATH}" \
  "${PACKER_TEMPLATE_PATH}"

if ! gcloud compute images describe "${TARGET_IMAGE_NAME}" --project "${GCP_PROJECT_ID}" >/dev/null 2>&1; then
  fail "Packer completed but target image was not found: ${GCP_PROJECT_ID}/${TARGET_IMAGE_NAME}"
fi

write_bake_metadata false
log "Image bake completed: ${GCP_PROJECT_ID}/${TARGET_IMAGE_NAME}"
