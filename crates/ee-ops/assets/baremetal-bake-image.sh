#!/usr/bin/env bash
# Build a bare-metal-ready Ubuntu image with EasyEnclave services via Packer QEMU.
set -euo pipefail

log() {
  echo "[baremetal_bake_image] $*"
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

escape_sed_replacement() {
  echo "$1" | sed -e 's/[\/&]/\\&/g'
}

render_template() {
  local src="$1"
  local dst="$2"
  local vm_name_value="$3"
  local ssh_username_value="$4"
  local ssh_pub_key_value="$5"

  [ -f "${src}" ] || fail "Missing template file: ${src}"
  sed \
    -e "s/__VM_NAME__/$(escape_sed_replacement "${vm_name_value}")/g" \
    -e "s/__SSH_USERNAME__/$(escape_sed_replacement "${ssh_username_value}")/g" \
    -e "s/__SSH_PUB_KEY__/$(escape_sed_replacement "${ssh_pub_key_value}")/g" \
    "${src}" > "${dst}"
}

trim() {
  local value="$1"
  echo "$value" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//'
}

sanitize_name() {
  local input="$1"
  local cleaned
  cleaned="$(echo "$input" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9-]+/-/g; s/^-+//; s/-+$//; s/-{2,}/-/g')"
  [ -n "$cleaned" ] || cleaned="easyenclave"
  echo "${cleaned:0:63}"
}

require_cmd packer
require_cmd jq
require_cmd ssh-keygen

TARGET_IMAGE_NAME="$(trim "${TARGET_IMAGE_NAME:-easyenclave-baremetal-$(date +%Y%m%d%H%M%S)}")"
SOURCE_SHA="$(trim "${SOURCE_SHA:-}")"
PACKER_TEMPLATE_PATH="$(trim "${PACKER_TEMPLATE_PATH:-crates/ee-ops/assets/packer/baremetal-agent-image.pkr.hcl}")"
BAREMETAL_BASE_IMAGE_URL="$(trim "${BAREMETAL_BASE_IMAGE_URL:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img}")"
BAREMETAL_BASE_IMAGE_CHECKSUM="$(trim "${BAREMETAL_BASE_IMAGE_CHECKSUM:-none}")"
BAREMETAL_OUTPUT_ROOT="$(trim "${BAREMETAL_OUTPUT_ROOT:-artifacts/baremetal-images}")"
BAREMETAL_ACCELERATOR="$(trim "${BAREMETAL_ACCELERATOR:-kvm}")"
BAREMETAL_DISK_SIZE="$(trim "${BAREMETAL_DISK_SIZE:-80G}")"
BAREMETAL_CPUS="$(trim "${BAREMETAL_CPUS:-4}")"
BAREMETAL_MEMORY_MB="$(trim "${BAREMETAL_MEMORY_MB:-8192}")"
BAREMETAL_SSH_USERNAME="$(trim "${BAREMETAL_SSH_USERNAME:-eebuilder}")"
BAREMETAL_SSH_TIMEOUT="$(trim "${BAREMETAL_SSH_TIMEOUT:-20m}")"
BAREMETAL_EXPORT_RAW="$(trim "${BAREMETAL_EXPORT_RAW:-true}")"
EE_AGENT_BINARY_PATH="$(trim "${EE_AGENT_BINARY_PATH:-}")"
USER_DATA_TEMPLATE_PATH="$(trim "${USER_DATA_TEMPLATE_PATH:-crates/ee-ops/assets/packer/templates/baremetal-user-data.tmpl}")"
META_DATA_TEMPLATE_PATH="$(trim "${META_DATA_TEMPLATE_PATH:-crates/ee-ops/assets/packer/templates/baremetal-meta-data.tmpl}")"

if [ ! -f "${PACKER_TEMPLATE_PATH}" ]; then
  fail "Missing packer template: ${PACKER_TEMPLATE_PATH}"
fi
if [ ! -f "${USER_DATA_TEMPLATE_PATH}" ]; then
  fail "Missing user-data template: ${USER_DATA_TEMPLATE_PATH}"
fi
if [ ! -f "${META_DATA_TEMPLATE_PATH}" ]; then
  fail "Missing meta-data template: ${META_DATA_TEMPLATE_PATH}"
fi
if ! [[ "${BAREMETAL_CPUS}" =~ ^[0-9]+$ ]]; then
  fail "BAREMETAL_CPUS must be an integer; got '${BAREMETAL_CPUS}'"
fi
if ! [[ "${BAREMETAL_MEMORY_MB}" =~ ^[0-9]+$ ]]; then
  fail "BAREMETAL_MEMORY_MB must be an integer; got '${BAREMETAL_MEMORY_MB}'"
fi

AGENT_BINARY_PATH=""
if [ -n "${EE_AGENT_BINARY_PATH}" ]; then
  [ -f "${EE_AGENT_BINARY_PATH}" ] || fail "Configured EE_AGENT_BINARY_PATH not found: ${EE_AGENT_BINARY_PATH}"
  chmod 0755 "${EE_AGENT_BINARY_PATH}" || fail "Failed to make EE_AGENT_BINARY_PATH executable"
  AGENT_BINARY_PATH="${EE_AGENT_BINARY_PATH}"
  log "Using prebuilt ee-agent binary: ${AGENT_BINARY_PATH}"
else
  require_cmd cargo
  log "Building ee-agent (release)..."
  cargo build -p ee-agent --release
  [ -x "target/release/ee-agent" ] || fail "ee-agent binary not found: target/release/ee-agent"
  AGENT_BINARY_PATH="target/release/ee-agent"
fi

vm_name="$(sanitize_name "${TARGET_IMAGE_NAME}")"
output_dir="${BAREMETAL_OUTPUT_ROOT}/${TARGET_IMAGE_NAME}"
mkdir -p "${BAREMETAL_OUTPUT_ROOT}"
if [ -e "${output_dir}" ]; then
  fail "Output directory already exists: ${output_dir}"
fi

tmp_dir="$(mktemp -d -t ee-baremetal-packer-XXXXXX)"
cloud_user_data="${tmp_dir}/user-data"
cloud_meta_data="${tmp_dir}/meta-data"
ssh_key_path="${tmp_dir}/builder_ed25519"
ssh_pub_key_path="${ssh_key_path}.pub"
trap 'rm -rf "${tmp_dir}"' EXIT

ssh-keygen -q -t ed25519 -N '' -f "${ssh_key_path}" >/dev/null
builder_pub_key="$(cat "${ssh_pub_key_path}")"

render_template "${USER_DATA_TEMPLATE_PATH}" "${cloud_user_data}" "${vm_name}" "${BAREMETAL_SSH_USERNAME}" "${builder_pub_key}"
render_template "${META_DATA_TEMPLATE_PATH}" "${cloud_meta_data}" "${vm_name}" "${BAREMETAL_SSH_USERNAME}" "${builder_pub_key}"

log "Running Packer build: ${TARGET_IMAGE_NAME}"
packer init "${PACKER_TEMPLATE_PATH}"
packer build \
  -color=false \
  -var "base_image_url=${BAREMETAL_BASE_IMAGE_URL}" \
  -var "base_image_checksum=${BAREMETAL_BASE_IMAGE_CHECKSUM}" \
  -var "output_directory=${output_dir}" \
  -var "vm_name=${vm_name}" \
  -var "accelerator=${BAREMETAL_ACCELERATOR}" \
  -var "disk_size=${BAREMETAL_DISK_SIZE}" \
  -var "cpus=${BAREMETAL_CPUS}" \
  -var "memory_mb=${BAREMETAL_MEMORY_MB}" \
  -var "ssh_username=${BAREMETAL_SSH_USERNAME}" \
  -var "ssh_private_key_file=${ssh_key_path}" \
  -var "ssh_timeout=${BAREMETAL_SSH_TIMEOUT}" \
  -var "cloud_init_user_data_path=${cloud_user_data}" \
  -var "cloud_init_meta_data_path=${cloud_meta_data}" \
  -var "agent_binary_path=${AGENT_BINARY_PATH}" \
  "${PACKER_TEMPLATE_PATH}"

qcow2_path="$(find "${output_dir}" -maxdepth 2 -type f -name '*.qcow2' | head -n1 || true)"
if [ -z "${qcow2_path}" ]; then
  candidate="$(find "${output_dir}" -maxdepth 2 -type f | head -n1 || true)"
  if [ -n "${candidate}" ]; then
    qcow2_path="${candidate}"
  else
    fail "Could not find built image artifact under ${output_dir}"
  fi
fi

raw_path=""
if [ "${BAREMETAL_EXPORT_RAW}" = "true" ]; then
  require_cmd qemu-img
  raw_path="${output_dir}/${vm_name}.raw"
  log "Converting to raw: ${raw_path}"
  qemu-img convert -f qcow2 -O raw "${qcow2_path}" "${raw_path}"
fi

metadata_path="${output_dir}/build-metadata.json"
jq -cn \
  --arg target_image_name "${TARGET_IMAGE_NAME}" \
  --arg source_sha "${SOURCE_SHA}" \
  --arg base_image_url "${BAREMETAL_BASE_IMAGE_URL}" \
  --arg qcow2_path "${qcow2_path}" \
  --arg raw_path "${raw_path}" \
  --arg vm_name "${vm_name}" \
  --arg accelerator "${BAREMETAL_ACCELERATOR}" \
  --arg disk_size "${BAREMETAL_DISK_SIZE}" \
  --argjson cpus "${BAREMETAL_CPUS}" \
  --argjson memory_mb "${BAREMETAL_MEMORY_MB}" \
  '{
    build_tool: "packer-qemu",
    target_image_name: $target_image_name,
    source_sha: $source_sha,
    base_image_url: $base_image_url,
    vm_name: $vm_name,
    accelerator: $accelerator,
    disk_size: $disk_size,
    cpus: $cpus,
    memory_mb: $memory_mb,
    qcow2_path: $qcow2_path,
    raw_path: $raw_path
  }' > "${metadata_path}"

log "Bare-metal image build complete."
log "qcow2: ${qcow2_path}"
if [ -n "${raw_path}" ]; then
  log "raw:   ${raw_path}"
fi
log "metadata: ${metadata_path}"
