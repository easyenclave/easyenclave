#!/usr/bin/env bash
# Build an EasyEnclave GCP image by launching a temporary builder VM from a
# configured base image, provisioning it, then snapshotting the boot disk.
set -euo pipefail

log() {
  echo "[gcp_bake_image] $*"
}

fail() {
  echo "::error::$*"
  exit 1
}

require_var() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    fail "Missing required value: ${name}"
  fi
}

sanitize_label_value() {
  local value
  value="$(echo "${1:-}" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9_-]+/-/g; s/^[-_]+//; s/[-_]+$//; s/[-_]{2,}/-/g')"
  if [ -z "$value" ]; then
    value="na"
  fi
  echo "${value:0:63}"
}

trim() {
  local value="$1"
  echo "$value" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//'
}

require_var GCP_PROJECT_ID
require_var SOURCE_IMAGE_PROJECT
require_var TARGET_IMAGE_NAME

if [ -z "${SOURCE_IMAGE_NAME:-}" ] && [ -z "${SOURCE_IMAGE_FAMILY:-}" ]; then
  fail "Set SOURCE_IMAGE_NAME or SOURCE_IMAGE_FAMILY."
fi

if [ -n "${BUILD_ZONE:-}" ] && [[ "${BUILD_ZONE}" == *,* ]]; then
  fail "BUILD_ZONE must be a single zone; got '${BUILD_ZONE}'."
fi

if [ -n "${BUILD_MACHINE_TYPE:-}" ] && [[ "${BUILD_MACHINE_TYPE}" == *,* ]]; then
  fail "BUILD_MACHINE_TYPE must be a single machine type; got '${BUILD_MACHINE_TYPE}'."
fi

BUILD_ZONE="$(trim "${BUILD_ZONE:-us-central1-a}")"
BUILD_MACHINE_TYPE="$(trim "${BUILD_MACHINE_TYPE:-e2-standard-4}")"
BUILD_BOOT_DISK_GB="$(trim "${BUILD_BOOT_DISK_GB:-200}")"
BUILD_TIMEOUT_SECONDS="$(trim "${BUILD_TIMEOUT_SECONDS:-900}")"
TARGET_IMAGE_FAMILY="$(trim "${TARGET_IMAGE_FAMILY:-}")"
TARGET_IMAGE_DESCRIPTION="$(trim "${TARGET_IMAGE_DESCRIPTION:-EasyEnclave image bake}")"
TARGET_IMAGE_LABELS="$(trim "${TARGET_IMAGE_LABELS:-}")"
SOURCE_SHA="$(trim "${SOURCE_SHA:-}")"
BAKE_METADATA_PATH="$(trim "${BAKE_METADATA_PATH:-}")"
INSTANCE_CREATE_CALL_TIMEOUT_SECONDS="$(trim "${INSTANCE_CREATE_CALL_TIMEOUT_SECONDS:-300}")"

if [ ! -f "infra/launcher/launcher.py" ]; then
  fail "Missing required file: infra/launcher/launcher.py"
fi

source_selector=""
source_value=""
resolved_source_name=""
resolved_source_family=""
resolved_source_self_link=""

if [ -n "${SOURCE_IMAGE_NAME:-}" ]; then
  if ! gcloud compute images describe "${SOURCE_IMAGE_NAME}" --project "${SOURCE_IMAGE_PROJECT}" >/dev/null 2>&1; then
    fail "Configured source image '${SOURCE_IMAGE_NAME}' not found in project '${SOURCE_IMAGE_PROJECT}'."
  fi
  source_selector="name"
  source_value="${SOURCE_IMAGE_NAME}"
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
  resolved_source_name="$(gcloud compute images describe-from-family "${SOURCE_IMAGE_FAMILY}" --project "${SOURCE_IMAGE_PROJECT}" --format='value(name)')"
  resolved_source_family="$(gcloud compute images describe-from-family "${SOURCE_IMAGE_FAMILY}" --project "${SOURCE_IMAGE_PROJECT}" --format='value(family)')"
  resolved_source_self_link="$(gcloud compute images describe-from-family "${SOURCE_IMAGE_FAMILY}" --project "${SOURCE_IMAGE_PROJECT}" --format='value(selfLink)')"
fi

if [ -z "${source_selector}" ] || [ -z "${source_value}" ] || [ -z "${resolved_source_name}" ]; then
  fail "No usable source image selector resolved."
fi

if gcloud compute images describe "${TARGET_IMAGE_NAME}" --project "${GCP_PROJECT_ID}" >/dev/null 2>&1; then
  log "Image already exists: ${GCP_PROJECT_ID}/${TARGET_IMAGE_NAME}"
  if [ -n "${BAKE_METADATA_PATH}" ]; then
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
        reused: true
      }' > "${BAKE_METADATA_PATH}"
  fi
  exit 0
fi

target_name_slug="$(sanitize_label_value "${TARGET_IMAGE_NAME}")"
builder_name="ee-bake-${target_name_slug:0:32}-$(date +%s)"
startup_script_file="$(mktemp -t ee-gcp-bake-startup-XXXXXX.sh)"
cleanup_instance="false"

cleanup() {
  set +e
  rm -f "${startup_script_file}"
  if [ "${cleanup_instance}" = "true" ]; then
    gcloud compute instances delete "${builder_name}" \
      --project "${GCP_PROJECT_ID}" \
      --zone "${BUILD_ZONE}" \
      --quiet >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

launcher_b64="$(base64 -w0 infra/launcher/launcher.py)"
admin_b64=""
if [ -f "infra/launcher/admin.html" ]; then
  admin_b64="$(base64 -w0 infra/launcher/admin.html)"
fi

cat > "${startup_script_file}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec > >(tee -a /var/log/easyenclave-image-bake.log /dev/ttyS0) 2>&1
trap 'rc=\$?; echo "__EE_BAKE_FAIL__:\$rc"; shutdown -h now || true; exit \$rc' ERR

echo "__EE_BAKE_START__ target=${TARGET_IMAGE_NAME} source=${SOURCE_SHA:-unknown}"
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  gnupg \
  lsb-release \
  jq \
  python3 \
  python3-requests \
  python3-psutil \
  docker.io \
  docker-compose-plugin

install -d -m 0755 /opt/launcher /home/tdx /etc/easyenclave /etc/apt/keyrings

cat <<'LAUNCHER_B64' | base64 -d > /opt/launcher/launcher.py
${launcher_b64}
LAUNCHER_B64
chmod +x /opt/launcher/launcher.py

cat <<'ADMIN_B64' | base64 -d > /opt/launcher/admin.html
${admin_b64}
ADMIN_B64

cat > /etc/systemd/system/tdx-launcher.service <<'SERVICEUNIT'
[Unit]
Description=TDX VM Launcher Service
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/launcher
ExecStart=/usr/bin/python3 /opt/launcher/launcher.py
Restart=on-failure
RestartSec=5
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
SERVICEUNIT

cloudflare_codename="\$(. /etc/os-release && echo "\${VERSION_CODENAME:-}")"
if [ -z "\${cloudflare_codename}" ]; then
  echo "__EE_BAKE_FAIL__:missing VERSION_CODENAME for cloudflared repo setup"
  exit 1
fi
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | gpg --dearmor -o /etc/apt/keyrings/cloudflare-main.gpg
chmod 0644 /etc/apt/keyrings/cloudflare-main.gpg
cat > /etc/apt/sources.list.d/cloudflared.list <<APTREPO
deb [signed-by=/etc/apt/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared \${cloudflare_codename} main
APTREPO
apt-get update
apt-get install -y --no-install-recommends cloudflared

systemctl daemon-reload
systemctl enable docker
systemctl enable tdx-launcher.service

apt-get clean
rm -rf /var/lib/apt/lists/*

echo "__EE_BAKE_SUCCESS__"
shutdown -h now
EOF
chmod +x "${startup_script_file}"

log "Creating builder VM: ${builder_name} (${BUILD_ZONE}, ${BUILD_MACHINE_TYPE})"

source_args=(--image-project "${SOURCE_IMAGE_PROJECT}")
if [ "${source_selector}" = "name" ]; then
  source_args+=(--image "${source_value}")
else
  source_args+=(--image-family "${source_value}")
fi

set +e
create_output="$(
  timeout "${INSTANCE_CREATE_CALL_TIMEOUT_SECONDS}" \
    gcloud compute instances create "${builder_name}" \
    --project "${GCP_PROJECT_ID}" \
    --zone "${BUILD_ZONE}" \
    --machine-type "${BUILD_MACHINE_TYPE}" \
    --boot-disk-size "${BUILD_BOOT_DISK_GB}" \
    --metadata "serial-port-enable=1" \
    --metadata-from-file "startup-script=${startup_script_file}" \
    "${source_args[@]}" 2>&1
)"
create_rc=$?
set -e

if [ "${create_rc}" -eq 0 ]; then
  [ -n "${create_output}" ] && echo "${create_output}"
else
  if [ "${create_rc}" -eq 124 ]; then
    create_output="${create_output}
instance create timed out after ${INSTANCE_CREATE_CALL_TIMEOUT_SECONDS}s"
  fi
  [ -n "${create_output}" ] && echo "${create_output}" >&2
  if gcloud compute instances describe "${builder_name}" --project "${GCP_PROJECT_ID}" --zone "${BUILD_ZONE}" >/dev/null 2>&1; then
    log "Create call returned non-zero but builder VM exists; continuing."
  else
    fail "Builder VM creation failed (single attempt)."
  fi
fi

cleanup_instance="true"

deadline=$(( $(date +%s) + BUILD_TIMEOUT_SECONDS ))
saw_success="false"

while :; do
  serial="$(gcloud compute instances get-serial-port-output "${builder_name}" --project "${GCP_PROJECT_ID}" --zone "${BUILD_ZONE}" --port 1 2>/dev/null || true)"
  if echo "${serial}" | grep -q "__EE_BAKE_SUCCESS__"; then
    saw_success="true"
    break
  fi
  if echo "${serial}" | grep -q "__EE_BAKE_FAIL__"; then
    echo "::error::Image bake script failed inside builder VM."
    echo "${serial}" | tail -n 160
    exit 1
  fi

  now="$(date +%s)"
  if [ "${now}" -ge "${deadline}" ]; then
    echo "::error::Timed out waiting for builder VM startup script completion."
    echo "${serial}" | tail -n 160
    exit 1
  fi

  status="$(gcloud compute instances describe "${builder_name}" --project "${GCP_PROJECT_ID}" --zone "${BUILD_ZONE}" --format='value(status)' 2>/dev/null || true)"
  if [ "${status}" = "TERMINATED" ]; then
    echo "::error::Builder VM terminated before success marker."
    echo "${serial}" | tail -n 160
    exit 1
  fi
  sleep 15
done

if [ "${saw_success}" != "true" ]; then
  fail "Builder VM did not emit success marker."
fi

term_deadline=$(( $(date +%s) + 300 ))
while :; do
  status="$(gcloud compute instances describe "${builder_name}" --project "${GCP_PROJECT_ID}" --zone "${BUILD_ZONE}" --format='value(status)')"
  if [ "${status}" = "TERMINATED" ]; then
    break
  fi
  now="$(date +%s)"
  if [ "${now}" -ge "${term_deadline}" ]; then
    fail "Builder VM did not stop after successful bake."
  fi
  sleep 5
done

disk_name="$(gcloud compute instances describe "${builder_name}" --project "${GCP_PROJECT_ID}" --zone "${BUILD_ZONE}" --format='value(disks[0].source.basename())')"
if [ -z "${disk_name}" ]; then
  fail "Could not resolve builder VM boot disk name."
fi

label_parts=()
label_parts+=("easyenclave=managed")
label_parts+=("ee_image_bake=true")
label_parts+=("ee_source_image=$(sanitize_label_value "${resolved_source_name}")")
label_parts+=("ee_source_project=$(sanitize_label_value "${SOURCE_IMAGE_PROJECT}")")
if [ -n "${SOURCE_SHA}" ]; then
  label_parts+=("ee_git_sha=$(sanitize_label_value "${SOURCE_SHA:0:12}")")
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
    key="$(trim "${key}")"
    value="$(trim "${value}")"
    if [ -z "${key}" ]; then
      fail "Invalid TARGET_IMAGE_LABELS entry '${item}' (empty key)."
    fi
    label_parts+=("${key}=$(sanitize_label_value "${value}")")
  done
fi

labels_csv="$(IFS=','; echo "${label_parts[*]}")"

create_args=(
  --project "${GCP_PROJECT_ID}"
  --source-disk "${disk_name}"
  --source-disk-zone "${BUILD_ZONE}"
  --description "${TARGET_IMAGE_DESCRIPTION}"
  --labels "${labels_csv}"
)
if [ -n "${TARGET_IMAGE_FAMILY}" ]; then
  create_args+=(--family "${TARGET_IMAGE_FAMILY}")
fi

log "Creating image ${GCP_PROJECT_ID}/${TARGET_IMAGE_NAME} from disk ${disk_name}"
gcloud compute images create "${TARGET_IMAGE_NAME}" "${create_args[@]}"
log "Image bake completed: ${GCP_PROJECT_ID}/${TARGET_IMAGE_NAME}"

if [ -n "${BAKE_METADATA_PATH}" ]; then
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
    --arg builder_zone "${BUILD_ZONE}" \
    --arg builder_machine_type "${BUILD_MACHINE_TYPE}" \
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
      builder_zone: $builder_zone,
      builder_machine_type: $builder_machine_type,
      reused: false
    }' > "${BAKE_METADATA_PATH}"
fi
