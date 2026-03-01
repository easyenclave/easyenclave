#!/usr/bin/env bash
# Minimal GCP VM control utility used by ee-ops deploy/measure scripts.
# Commands:
#   control-plane new [--port N] [--wait] [--timeout SECONDS]
#   vm new --cp-url URL --ita-api-key KEY [--size tiny|standard|llm] [--zone Z] [--region R] [--datacenter D] [--wait] [--timeout SECONDS]
#   vm measure [--size tiny|standard|llm] [--timeout SECONDS] [--json]
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fatal() {
  echo "Error: $*" >&2
  exit 1
}

warn() {
  echo "Warning: $*" >&2
}

require_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || fatal "Required command not found: $cmd"
}

require_cmd gcloud
require_cmd jq
require_cmd curl

env_first() {
  local key value
  for key in "$@"; do
    value="${!key:-}"
    if [ -n "${value// }" ]; then
      printf '%s' "$value"
      return 0
    fi
  done
  printf ''
}

normalize_name() {
  local input="$1" max_len="${2:-63}" cleaned
  cleaned="$(printf '%s' "$input" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9-]+/-/g; s/-+/-/g; s/^-+//; s/-+$//')"
  if [ -z "$cleaned" ]; then
    cleaned="easyenclave"
  fi
  cleaned="${cleaned:0:${max_len}}"
  cleaned="$(printf '%s' "$cleaned" | sed -E 's/-+$//')"
  if [ -z "$cleaned" ]; then
    cleaned="easyenclave"
  fi
  printf '%s' "$cleaned"
}

project_id="$(env_first GCP_PROJECT_ID STAGING_GCP_PROJECT_ID PRODUCTION_GCP_PROJECT_ID)"
[ -n "$project_id" ] || fatal "Missing GCP_PROJECT_ID"

ensure_project() {
  # Avoid mutating gcloud config in CI and rely on explicit --project flags.
  export CLOUDSDK_CORE_PROJECT="$project_id"
}

zone_candidates() {
  local preferred="$1" fallback zone
  declare -A seen=()
  local zones=()

  add_zone() {
    local z="$1"
    [ -n "$z" ] || return 0
    if [ -z "${seen[$z]:-}" ]; then
      seen[$z]=1
      zones+=("$z")
    fi
  }

  add_csv() {
    local csv="$1" item
    IFS=',' read -r -a items <<< "$csv"
    for item in "${items[@]}"; do
      item="$(printf '%s' "$item" | xargs)"
      [ -n "$item" ] && add_zone "$item"
    done
  }

  add_zone "$preferred"
  fallback="$(env_first GCP_FALLBACK_ZONES EE_GCP_FALLBACK_ZONES)"
  [ -n "$fallback" ] && add_csv "$fallback"

  if [[ "$preferred" == us-central1-* ]]; then
    add_csv "us-central1-a,us-central1-b,us-central1-c,us-central1-f"
  fi

  for zone in "${zones[@]}"; do
    echo "$zone"
  done
}

machine_type_for_size() {
  case "$1" in
    tiny) echo "c3-standard-4" ;;
    standard) echo "c3-standard-8" ;;
    llm) echo "c3-standard-22" ;;
    *) fatal "Unsupported size '$1' (expected tiny|standard|llm)" ;;
  esac
}

disk_gib_for_size() {
  local size="$1" per_size_key default_gib override_gib
  case "$size" in
    tiny)
      per_size_key="EE_GCP_DISK_GIB_TINY"
      default_gib="80"
      ;;
    standard)
      per_size_key="EE_GCP_DISK_GIB_STANDARD"
      default_gib="100"
      ;;
    llm)
      per_size_key="EE_GCP_DISK_GIB_LLM"
      default_gib="140"
      ;;
    *)
      fatal "Unsupported size '$size' (expected tiny|standard|llm)"
      ;;
  esac

  override_gib="$(env_first "$per_size_key" EE_GCP_DISK_GIB)"
  [ -n "$override_gib" ] || override_gib="$default_gib"
  printf '%s' "$override_gib"
}

disk_type_for_role() {
  local role="$1" override default_type
  case "$role" in
    control-plane)
      override="$(env_first EE_GCP_BOOT_DISK_TYPE_CP EE_GCP_BOOT_DISK_TYPE)"
      default_type="pd-balanced"
      ;;
    agent)
      override="$(env_first EE_GCP_BOOT_DISK_TYPE_AGENT EE_GCP_BOOT_DISK_TYPE)"
      default_type="pd-balanced"
      ;;
    measure)
      override="$(env_first EE_GCP_BOOT_DISK_TYPE_MEASURE EE_GCP_BOOT_DISK_TYPE)"
      default_type="pd-balanced"
      ;;
    *)
      fatal "Unsupported disk role '$role' (expected control-plane|agent|measure)"
      ;;
  esac
  [ -n "$override" ] || override="$default_type"
  printf '%s' "$override"
}

is_retryable_create_error() {
  local text
  text="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  [[ "$text" == *"configuration_availability"* ]] && return 0
  [[ "$text" == *"does not have enough resources"* ]] && return 0
  [[ "$text" == *"resource_pool_exhausted"* ]] && return 0
  [[ "$text" == *"not supported in the"* ]] && return 0
  [[ "$text" == *"temporarily unavailable"* ]] && return 0
  [[ "$text" == *"quota"* && "$text" == *"exceeded"* ]] && return 0
  return 1
}

image_selector_args() {
  local image_project image_name image_family
  image_project="$(env_first EE_GCP_IMAGE_PROJECT)"
  [ -n "$image_project" ] || image_project="$project_id"

  image_name="$(env_first EE_GCP_IMAGE_NAME)"
  image_family="$(env_first EE_GCP_IMAGE_FAMILY)"
  [ -n "$image_family" ] || image_family="easyenclave-agent-main"

  if [ -n "$image_name" ]; then
    printf -- '--image-project\n%s\n--image\n%s\n' "$image_project" "$image_name"
    return 0
  fi
  printf -- '--image-project\n%s\n--image-family\n%s\n' "$image_project" "$image_family"
}

create_instance_with_fallback() {
  local name="$1"
  local machine_type="$2"
  local startup_script="$3"
  local labels_csv="$4"
  local disk_gib="$5"
  local preferred_zone="$6"
  local disk_type="$7"

  local source_args=()
  mapfile -t source_args < <(image_selector_args)

  local zone output rc output_lc last_error reason
  last_error=""
  while IFS= read -r zone; do
    [ -n "$zone" ] || continue
    set +e
    output="$(gcloud compute instances create "$name" \
      --project "$project_id" \
      --zone "$zone" \
      --machine-type "$machine_type" \
      --boot-disk-size "${disk_gib}GB" \
      --boot-disk-type "$disk_type" \
      --maintenance-policy TERMINATE \
      --provisioning-model STANDARD \
      --confidential-compute-type TDX \
      --labels "$labels_csv" \
      --metadata "serial-port-enable=1" \
      --metadata-from-file "startup-script=${startup_script}" \
      --scopes "https://www.googleapis.com/auth/cloud-platform" \
      "${source_args[@]}" 2>&1)"
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
      echo "$zone"
      return 0
    fi

    output_lc="$(printf '%s' "$output" | tr '[:upper:]' '[:lower:]')"
    if is_retryable_create_error "$output_lc"; then
      reason="$(printf '%s' "$output" | head -n1 | tr -d '\r')"
      warn "Zone '$zone' create failed for machine_type=${machine_type} disk=${disk_gib}GB/${disk_type}; retrying (${reason})"
      continue
    fi

    last_error="$output"
    break
  done < <(zone_candidates "$preferred_zone")

  if [ -n "$last_error" ]; then
    echo "$last_error" >&2
    fatal "Failed creating instance '$name'"
  fi
  fatal "Unable to create instance '$name' in any candidate zone (machine_type=${machine_type}, disk=${disk_gib}GB/${disk_type})"
}

wait_instance_running() {
  local name="$1" zone="$2" timeout_seconds="$3"
  local deadline status
  deadline=$(( $(date +%s) + timeout_seconds ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    status="$(gcloud compute instances describe "$name" --project "$project_id" --zone "$zone" --format='value(status)' 2>/dev/null || true)"
    if [ "${status^^}" = "RUNNING" ]; then
      return 0
    fi
    sleep 3
  done
  fatal "Timed out waiting for VM '$name' to reach RUNNING"
}

instance_json() {
  local name="$1" zone="$2"
  gcloud compute instances describe "$name" --project "$project_id" --zone "$zone" --format=json
}

instance_internal_ip() {
  jq -r '.networkInterfaces[0].networkIP // ""'
}

instance_external_ip() {
  jq -r '.networkInterfaces[0].accessConfigs[0].natIP // ""'
}

serial_tail() {
  local name="$1" zone="$2" lines="${3:-120}"
  gcloud compute instances get-serial-port-output "$name" \
    --project "$project_id" \
    --zone "$zone" \
    --port 1 2>/dev/null | tail -n "$lines"
}

control_plane_alias_host() {
  local env_name="$1" domain="$2"
  if [ "$env_name" = "staging" ]; then
    printf 'app-staging.%s' "$domain"
  else
    printf 'app.%s' "$domain"
  fi
}

write_control_plane_startup_script() {
  local cfg_json="$1" port="$2" script_path="$3"
  cat > "$script_path" <<SCRIPT
#!/usr/bin/env bash
set -euo pipefail
exec > >(tee -a /var/log/easyenclave-control-plane-bootstrap.log /dev/ttyS0) 2>&1
mkdir -p /etc/easyenclave
cat > /etc/easyenclave/control-plane.json <<'EOF_CONFIG'
${cfg_json}
EOF_CONFIG
chmod 0600 /etc/easyenclave/control-plane.json
systemctl daemon-reload || true
systemctl disable --now easyenclave-agent.service || true
systemctl enable easyenclave-control-plane.service || true
systemctl restart easyenclave-control-plane.service || true
echo "__EE_CP_LOCAL_HEALTH_WAIT__ port=${port}"
for _ in \$(seq 1 150); do
  if curl -fsS "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
    echo "__EE_CP_LOCAL_HEALTH_OK__"
    break
  fi
  sleep 2
done
if ! curl -fsS "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
  echo "__EE_CP_LOCAL_HEALTH_TIMEOUT__"
fi
SCRIPT
  chmod +x "$script_path"
}

build_control_plane_cfg_json() {
  local cp_url_for_agents="$1" port="$2"
  local cfg
  cfg="$(jq -n --arg port "$port" '{port: ($port | tonumber)}')"

  add_cfg() {
    local json_key="$1" value="$2"
    [ -n "$value" ] || return 0
    cfg="$(echo "$cfg" | jq --arg k "$json_key" --arg v "$value" '. + {($k): $v}')"
  }

  add_cfg "control_plane_image" "$(env_first CONTROL_PLANE_IMAGE)"
  add_cfg "easyenclave_domain" "$(env_first EASYENCLAVE_DOMAIN)"
  add_cfg "easyenclave_env" "$(env_first EASYENCLAVE_ENV)"
  add_cfg "easyenclave_network_name" "$(env_first EASYENCLAVE_NETWORK_NAME)"
  add_cfg "easyenclave_boot_id" "$(env_first EASYENCLAVE_BOOT_ID)"
  add_cfg "easyenclave_git_sha" "$(env_first EASYENCLAVE_GIT_SHA)"
  add_cfg "easyenclave_release_tag" "$(env_first EASYENCLAVE_RELEASE_TAG)"
  add_cfg "easyenclave_cp_url" "$cp_url_for_agents"
  add_cfg "cloudflare_api_token" "$(env_first CLOUDFLARE_API_TOKEN)"
  add_cfg "cloudflare_account_id" "$(env_first CLOUDFLARE_ACCOUNT_ID)"
  add_cfg "cloudflare_zone_id" "$(env_first CLOUDFLARE_ZONE_ID)"
  add_cfg "admin_password" "$(env_first CP_ADMIN_PASSWORD ADMIN_PASSWORD)"
  add_cfg "admin_github_logins" "$(env_first ADMIN_GITHUB_LOGINS)"
  add_cfg "admin_password_hash" "$(env_first ADMIN_PASSWORD_HASH)"
  add_cfg "ee_agent_ita_api_key" "$(env_first EE_AGENT_ITA_API_KEY ITA_API_KEY INTEL_API_KEY)"
  add_cfg "gcp_project_id" "$(env_first GCP_PROJECT_ID)"
  add_cfg "gcp_service_account_key" "$(env_first GCP_SERVICE_ACCOUNT_KEY)"
  add_cfg "ee_gcp_image_project" "$(env_first EE_GCP_IMAGE_PROJECT)"
  add_cfg "ee_gcp_image_family" "$(env_first EE_GCP_IMAGE_FAMILY)"
  add_cfg "ee_gcp_image_name" "$(env_first EE_GCP_IMAGE_NAME)"
  add_cfg "github_oauth_client_id" "$(env_first GITHUB_OAUTH_CLIENT_ID)"
  add_cfg "github_oauth_client_secret" "$(env_first GITHUB_OAUTH_CLIENT_SECRET)"
  add_cfg "github_oauth_redirect_uri" "$(env_first GITHUB_OAUTH_REDIRECT_URI)"
  add_cfg "stripe_secret_key" "$(env_first STRIPE_SECRET_KEY)"
  add_cfg "stripe_webhook_secret" "$(env_first STRIPE_WEBHOOK_SECRET)"
  add_cfg "trusted_agent_mrtds" "$(env_first TRUSTED_AGENT_MRTDS)"
  add_cfg "trusted_proxy_mrtds" "$(env_first TRUSTED_PROXY_MRTDS)"
  add_cfg "trusted_agent_rtmrs" "$(env_first TRUSTED_AGENT_RTMRS)"
  add_cfg "trusted_proxy_rtmrs" "$(env_first TRUSTED_PROXY_RTMRS)"
  add_cfg "trusted_agent_rtmrs_by_size" "$(env_first TRUSTED_AGENT_RTMRS_BY_SIZE)"
  add_cfg "trusted_proxy_rtmrs_by_size" "$(env_first TRUSTED_PROXY_RTMRS_BY_SIZE)"
  add_cfg "tcb_enforcement_mode" "$(env_first TCB_ENFORCEMENT_MODE)"
  add_cfg "allowed_tcb_statuses" "$(env_first ALLOWED_TCB_STATUSES)"
  add_cfg "nonce_enforcement_mode" "$(env_first NONCE_ENFORCEMENT_MODE)"
  add_cfg "nonce_ttl_seconds" "$(env_first NONCE_TTL_SECONDS)"
  add_cfg "rtmr_enforcement_mode" "$(env_first RTMR_ENFORCEMENT_MODE)"
  add_cfg "signature_verification_mode" "$(env_first SIGNATURE_VERIFICATION_MODE)"
  add_cfg "cp_to_agent_attestation_mode" "$(env_first CP_TO_AGENT_ATTESTATION_MODE)"
  add_cfg "auth_require_github_oauth_in_production" "$(env_first AUTH_REQUIRE_GITHUB_OAUTH_IN_PRODUCTION)"
  add_cfg "password_login_enabled" "$(env_first PASSWORD_LOGIN_ENABLED)"
  add_cfg "auth_allow_password_login_in_production" "$(env_first AUTH_ALLOW_PASSWORD_LOGIN_IN_PRODUCTION)"
  add_cfg "billing_enabled" "$(env_first BILLING_ENABLED)"
  add_cfg "billing_capacity_request_dev_simulation" "$(env_first BILLING_CAPACITY_REQUEST_DEV_SIMULATION)"
  add_cfg "billing_platform_account_id" "$(env_first BILLING_PLATFORM_ACCOUNT_ID)"
  add_cfg "billing_contributor_pool_bps" "$(env_first BILLING_CONTRIBUTOR_POOL_BPS)"
  add_cfg "default_gcp_tiny_capacity_enabled" "$(env_first DEFAULT_GCP_TINY_CAPACITY_ENABLED)"
  add_cfg "default_gcp_tiny_capacity_count" "$(env_first DEFAULT_GCP_TINY_CAPACITY_COUNT)"
  add_cfg "default_gcp_tiny_capacity_dispatch" "$(env_first DEFAULT_GCP_TINY_CAPACITY_DISPATCH)"
  add_cfg "cp_attestation_allow_insecure" "$(env_first CP_ATTESTATION_ALLOW_INSECURE)"
  add_cfg "cp_ita_jwks_url" "$(env_first CP_ITA_JWKS_URL)"
  add_cfg "cp_ita_issuer" "$(env_first CP_ITA_ISSUER)"
  add_cfg "cp_ita_audience" "$(env_first CP_ITA_AUDIENCE)"
  add_cfg "cp_ita_jwks_ttl_seconds" "$(env_first CP_ITA_JWKS_TTL_SECONDS)"

  # Keep verifier defaults aligned with the previous launcher behavior.
  if ! echo "$cfg" | jq -e '.cp_ita_jwks_url? // empty' >/dev/null; then
    cfg="$(echo "$cfg" | jq '. + {"cp_ita_jwks_url":"https://portal.trustauthority.intel.com/certs"}')"
  fi
  if ! echo "$cfg" | jq -e '.cp_ita_issuer? // empty' >/dev/null; then
    cfg="$(echo "$cfg" | jq '. + {"cp_ita_issuer":"https://portal.trustauthority.intel.com"}')"
  fi

  echo "$cfg" | jq .
}

cmd_control_plane_new() {
  local port="8080" wait_flag="false" timeout_seconds="600"
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --port) port="$2"; shift 2 ;;
      --wait) wait_flag="true"; shift 1 ;;
      --timeout) timeout_seconds="$2"; shift 2 ;;
      *) fatal "Unknown option for control-plane new: $1" ;;
    esac
  done

  ensure_project

  local env_name cp_size network_name domain alias_host network_host cp_url_for_agents
  env_name="$(printf '%s' "$(env_first EASYENCLAVE_ENV)" | tr '[:upper:]' '[:lower:]')"
  [ -n "$env_name" ] || env_name="staging"

  cp_size="$(printf '%s' "$(env_first CONTROL_PLANE_NODE_SIZE)" | tr '[:upper:]' '[:lower:]')"
  if [ -z "$cp_size" ]; then
    if [ "$env_name" = "staging" ]; then
      cp_size="tiny"
    else
      cp_size="standard"
    fi
  fi

  network_name="$(env_first EASYENCLAVE_NETWORK_NAME)"
  domain="$(env_first EASYENCLAVE_DOMAIN)"
  [ -n "$domain" ] || domain="easyenclave.com"

  alias_host="$(control_plane_alias_host "$env_name" "$domain")"
  network_host=""
  if [ -n "$network_name" ]; then
    network_host="$(normalize_name "$network_name" 48).$domain"
  fi

  cp_url_for_agents="https://${alias_host}"
  if [ -n "$network_host" ]; then
    cp_url_for_agents="https://${network_host}"
  fi

  local seed name machine_type disk_gib disk_type zone_pref startup_script cfg_json labels
  seed="${network_name:-$(cat /proc/sys/kernel/random/uuid | tr -d '-' | cut -c1-8)}"
  name="$(normalize_name "ee-cp-${env_name}-${seed}-$(date +%s)" 63)"
  machine_type="$(machine_type_for_size "$cp_size")"
  disk_gib="$(disk_gib_for_size "$cp_size")"
  disk_type="$(disk_type_for_role control-plane)"
  zone_pref="$(env_first GCP_ZONE AGENT_DATACENTER_AZ)"
  [ -n "$zone_pref" ] || zone_pref="us-central1-a"

  cfg_json="$(build_control_plane_cfg_json "$cp_url_for_agents" "$port")"
  startup_script="$(mktemp -t ee-cp-startup.XXXXXX.sh)"
  write_control_plane_startup_script "$cfg_json" "$port" "$startup_script"

  labels="easyenclave=managed,ee_role=control-plane,ee_env=$(normalize_name "$env_name" 63),ee_network=$(normalize_name "${network_name:-default}" 63)"

  local zone inst_json internal_ip external_ip public_alias_url selected_url
  zone="$(create_instance_with_fallback "$name" "$machine_type" "$startup_script" "$labels" "$disk_gib" "$zone_pref" "$disk_type")"
  rm -f "$startup_script" || true

  wait_instance_running "$name" "$zone" 300
  inst_json="$(instance_json "$name" "$zone")"
  internal_ip="$(echo "$inst_json" | instance_internal_ip)"
  external_ip="$(echo "$inst_json" | instance_external_ip)"

  public_alias_url="https://${alias_host}"
  selected_url="$public_alias_url"

  if [ "$wait_flag" = "true" ]; then
    local deadline local_ready serial health_candidate
    deadline=$(( $(date +%s) + timeout_seconds ))
    local_ready=0
    health_candidate=""

    while [ "$(date +%s)" -lt "$deadline" ]; do
      if [ -n "$external_ip" ] && curl -fsS --max-time 3 "http://${external_ip}:8080/health" >/dev/null 2>&1; then
        health_candidate="http://${external_ip}:8080"
        break
      fi
      if [ -n "$internal_ip" ] && curl -fsS --max-time 3 "http://${internal_ip}:8080/health" >/dev/null 2>&1; then
        health_candidate="http://${internal_ip}:8080"
        break
      fi
      serial="$(serial_tail "$name" "$zone" 120 || true)"
      if echo "$serial" | grep -q "__EE_CP_LOCAL_HEALTH_OK__"; then
        local_ready=1
        break
      fi
      sleep 3
    done

    if [ -n "$health_candidate" ]; then
      selected_url="$health_candidate"
    elif [ "$local_ready" -eq 1 ]; then
      warn "Control plane reported local /health OK before external endpoints became reachable; proceeding with hostname URL."
    else
      warn "Control-plane serial-port tail follows:"
      serial_tail "$name" "$zone" 120 >&2 || true
      fatal "Control plane did not become healthy within timeout"
    fi
  fi

  jq -n \
    --arg name "$name" \
    --arg zone "$zone" \
    --arg ip "${external_ip:-$internal_ip}" \
    --arg internal_ip "$internal_ip" \
    --arg external_ip "$external_ip" \
    --arg control_plane_url "$selected_url" \
    --arg control_plane_hostname "$alias_host" \
    --arg control_plane_network_hostname "$network_host" \
    '{
      name: $name,
      zone: $zone,
      ip: ($ip // ""),
      internal_ip: ($internal_ip // ""),
      external_ip: ($external_ip // ""),
      control_plane_url: $control_plane_url,
      control_plane_hostname: $control_plane_hostname,
      control_plane_network_hostname: $control_plane_network_hostname,
      bootstrap_agents: []
    }'
}

write_agent_startup_script() {
  local cfg_json="$1" script_path="$2"
  cat > "$script_path" <<SCRIPT
#!/usr/bin/env bash
set -euo pipefail
mkdir -p /etc/easyenclave
cat > /etc/easyenclave/agent.json <<'EOF_CONFIG'
${cfg_json}
EOF_CONFIG
chmod 0600 /etc/easyenclave/agent.json
systemctl daemon-reload || true
systemctl disable --now easyenclave-control-plane.service || true
systemctl enable easyenclave-agent.service || true
systemctl restart easyenclave-agent.service || true
SCRIPT
  chmod +x "$script_path"
}

cmd_vm_new() {
  local size="standard" cp_url="" ita_api_key="" zone="" region="" datacenter=""
  local wait_flag="false" timeout_seconds="600"

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --size) size="$2"; shift 2 ;;
      --cp-url) cp_url="$2"; shift 2 ;;
      --ita-api-key) ita_api_key="$2"; shift 2 ;;
      --zone) zone="$2"; shift 2 ;;
      --region) region="$2"; shift 2 ;;
      --datacenter) datacenter="$2"; shift 2 ;;
      --wait) wait_flag="true"; shift 1 ;;
      --timeout) timeout_seconds="$2"; shift 2 ;;
      *) fatal "Unknown option for vm new: $1" ;;
    esac
  done

  [ -n "$cp_url" ] || fatal "--cp-url is required"
  [ -n "$ita_api_key" ] || fatal "--ita-api-key is required"

  ensure_project

  size="$(printf '%s' "$size" | tr '[:upper:]' '[:lower:]')"
  local machine_type disk_gib disk_type
  machine_type="$(machine_type_for_size "$size")"
  disk_gib="$(disk_gib_for_size "$size")"
  disk_type="$(disk_type_for_role agent)"

  [ -n "$zone" ] || zone="$(env_first GCP_ZONE AGENT_DATACENTER_AZ)"
  [ -n "$zone" ] || zone="us-central1-a"

  local env_name network_name vm_name resolved_zone labels datacenter_label
  env_name="$(env_first EASYENCLAVE_ENV)"
  [ -n "$env_name" ] || env_name="staging"
  network_name="$(env_first EASYENCLAVE_NETWORK_NAME)"
  vm_name="$(normalize_name "tdx-agent-$(cat /proc/sys/kernel/random/uuid | tr -d '-' | cut -c1-10)" 63)"

  datacenter_label="$datacenter"
  [ -n "$datacenter_label" ] || datacenter_label="gcp:${zone}"
  datacenter_label="$(printf '%s' "$datacenter_label" | tr '[:upper:]' '[:lower:]')"

  local cfg_json startup_script
  cfg_json="$(jq -n \
    --arg cp_url "$cp_url" \
    --arg zone "$zone" \
    --arg region "$region" \
    --arg datacenter "$datacenter_label" \
    --arg size "$size" \
    --arg ita "$ita_api_key" \
    --arg env_name "$env_name" \
    --arg network_name "$network_name" \
    '{
      control_plane_url: $cp_url,
      cloud_provider: "gcp",
      availability_zone: $zone,
      region: $region,
      datacenter: $datacenter,
      node_size: $size,
      intel_api_key: $ita,
      ita_api_key: $ita,
      easyenclave_env: $env_name,
      easyenclave_network_name: $network_name
    } | with_entries(select(.value != "" and .value != null))')"

  startup_script="$(mktemp -t ee-agent-startup.XXXXXX.sh)"
  write_agent_startup_script "$cfg_json" "$startup_script"

  labels="easyenclave=managed,ee_role=agent,ee_env=$(normalize_name "$env_name" 63),ee_network=$(normalize_name "${network_name:-default}" 63),ee_node_size=$(normalize_name "$size" 63)"
  resolved_zone="$(create_instance_with_fallback "$vm_name" "$machine_type" "$startup_script" "$labels" "$disk_gib" "$zone" "$disk_type")"
  rm -f "$startup_script" || true

  if [ "$wait_flag" = "true" ]; then
    wait_instance_running "$vm_name" "$resolved_zone" "$timeout_seconds"
  fi

  local inst_json internal_ip external_ip
  inst_json="$(instance_json "$vm_name" "$resolved_zone")"
  internal_ip="$(echo "$inst_json" | instance_internal_ip)"
  external_ip="$(echo "$inst_json" | instance_external_ip)"

  jq -n \
    --arg name "$vm_name" \
    --arg zone "$resolved_zone" \
    --arg internal_ip "$internal_ip" \
    --arg external_ip "$external_ip" \
    --arg datacenter "$datacenter_label" \
    --arg size "$size" \
    '{
      name: $name,
      zone: $zone,
      internal_ip: ($internal_ip // ""),
      external_ip: ($external_ip // ""),
      cloud_provider: "gcp",
      datacenter: $datacenter,
      node_size: $size
    }'
}

write_measure_startup_script() {
  local size="$1" script_path="$2"
  cat > "$script_path" <<SCRIPT
#!/usr/bin/env bash
set -euo pipefail
exec > >(tee -a /var/log/easyenclave-measure.log /dev/ttyS0) 2>&1
mkdir -p /etc/easyenclave
cat > /etc/easyenclave/measure.json <<'EOF_CONFIG'
{"node_size":"${size}"}
EOF_CONFIG
chmod 0600 /etc/easyenclave/measure.json
if [ ! -x /usr/local/bin/ee-agent ]; then
  echo "EASYENCLAVE_MEASURE_ERROR=missing_agent_binary"
  systemctl poweroff || true
  exit 0
fi
EE_AGENT_MODE=measure EASYENCLAVE_CONFIG=/etc/easyenclave/measure.json timeout 300 /usr/local/bin/ee-agent || true
sleep 2
systemctl poweroff || true
SCRIPT
  chmod +x "$script_path"
}

cleanup_terminated_measure_vms() {
  local filter rows row vm zone
  filter="labels.easyenclave=managed AND labels.ee_role=measure AND status=TERMINATED"

  mapfile -t rows < <(gcloud compute instances list \
    --project "$project_id" \
    --filter "$filter" \
    --format "value(name,zone.basename())" 2>/dev/null || true)

  for row in "${rows[@]}"; do
    [ -n "${row:-}" ] || continue
    vm="$(echo "$row" | awk '{print $1}')"
    zone="$(echo "$row" | awk '{print $2}')"
    [ -n "${vm:-}" ] || continue
    [ -n "${zone:-}" ] || continue
    warn "Deleting stale terminated measure VM '$vm' in zone '$zone'"
    gcloud compute instances delete "$vm" --project "$project_id" --zone "$zone" --quiet >/dev/null 2>&1 || true
  done
}

cmd_vm_measure() {
  local size="standard" timeout_seconds="600" json_flag="false"
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --size) size="$2"; shift 2 ;;
      --timeout) timeout_seconds="$2"; shift 2 ;;
      --json) json_flag="true"; shift 1 ;;
      *) fatal "Unknown option for vm measure: $1" ;;
    esac
  done

  ensure_project

  size="$(printf '%s' "$size" | tr '[:upper:]' '[:lower:]')"
  local machine_type disk_gib disk_type zone vm_name labels startup_script resolved_zone env_name
  machine_type="$(machine_type_for_size "$size")"
  disk_gib="$(disk_gib_for_size "$size")"
  disk_type="$(disk_type_for_role measure)"
  zone="$(env_first GCP_ZONE AGENT_DATACENTER_AZ)"
  [ -n "$zone" ] || zone="us-central1-a"

  vm_name="$(normalize_name "ee-measure-${size}-$(cat /proc/sys/kernel/random/uuid | tr -d '-' | cut -c1-8)" 63)"
  env_name="$(env_first EASYENCLAVE_ENV)"
  [ -n "$env_name" ] || env_name="staging"
  cleanup_terminated_measure_vms
  labels="easyenclave=managed,ee_role=measure,ee_env=$(normalize_name "$env_name" 63)"

  startup_script="$(mktemp -t ee-measure-startup.XXXXXX.sh)"
  write_measure_startup_script "$size" "$startup_script"

  resolved_zone="$(create_instance_with_fallback "$vm_name" "$machine_type" "$startup_script" "$labels" "$disk_gib" "$zone" "$disk_type")"
  rm -f "$startup_script" || true

  local measurements="" deadline serial line err
  deadline=$(( $(date +%s) + timeout_seconds ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    serial="$(serial_tail "$vm_name" "$resolved_zone" 400 || true)"
    line="$(echo "$serial" | grep 'EASYENCLAVE_MEASUREMENTS=' | tail -n1 || true)"
    if [ -n "$line" ]; then
      measurements="${line#*=}"
      break
    fi
    err="$(echo "$serial" | grep 'EASYENCLAVE_MEASURE_ERROR=' | tail -n1 || true)"
    if [ -n "$err" ]; then
      gcloud compute instances delete "$vm_name" --project "$project_id" --zone "$resolved_zone" --quiet || true
      fatal "Measure VM error: ${err#*=}"
    fi
    sleep 5
  done

  gcloud compute instances delete "$vm_name" --project "$project_id" --zone "$resolved_zone" --quiet || true

  [ -n "$measurements" ] || fatal "Timed out waiting for measurement output"

  if [ "$json_flag" = "true" ]; then
    echo "$measurements" | jq .
  else
    echo "$measurements"
  fi
}

cmd_vm_list() {
  local json_flag="false"
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --json) json_flag="true"; shift 1 ;;
      *) fatal "Unknown option for vm list: $1" ;;
    esac
  done

  ensure_project
  if [ "$json_flag" = "true" ]; then
    gcloud compute instances list \
      --project "$project_id" \
      --filter "labels.easyenclave=managed" \
      --format=json \
      | jq '[.[] | {
          name: (.name // ""),
          zone: ((.zone // "") | split("/") | last),
          status: (.status // ""),
          labels: (.labels // {})
        }]'
    return 0
  fi

  gcloud compute instances list \
    --project "$project_id" \
    --filter "labels.easyenclave=managed" \
    --format "value(name)" \
    | sort
}

cmd_vm_delete() {
  [ "$#" -eq 1 ] || fatal "Usage: vm delete <name|all>"
  ensure_project

  local name="$1"
  if [ "$name" = "all" ]; then
    mapfile -t rows < <(gcloud compute instances list \
      --project "$project_id" \
      --filter "labels.easyenclave=managed" \
      --format "value(name,zone.basename())")
    for row in "${rows[@]}"; do
      [ -n "$row" ] || continue
      local vm zone
      vm="$(echo "$row" | awk '{print $1}')"
      zone="$(echo "$row" | awk '{print $2}')"
      [ -n "$vm" ] || continue
      [ -n "$zone" ] || continue
      gcloud compute instances delete "$vm" --project "$project_id" --zone "$zone" --quiet || true
    done
    return 0
  fi

  local zone
  zone="$(gcloud compute instances list \
    --project "$project_id" \
    --filter "name=${name}" \
    --format "value(zone.basename())" \
    | head -n1)"
  [ -n "$zone" ] || zone="$(env_first GCP_ZONE AGENT_DATACENTER_AZ)"
  [ -n "$zone" ] || zone="us-central1-a"

  gcloud compute instances delete "$name" --project "$project_id" --zone "$zone" --quiet
}

usage() {
  cat <<USAGE >&2
Usage:
  gcp-nodectl.sh control-plane new [--port N] [--wait] [--timeout SECONDS]
  gcp-nodectl.sh vm new --cp-url URL --ita-api-key KEY [--size tiny|standard|llm] [--zone Z] [--region R] [--datacenter D] [--wait] [--timeout SECONDS]
  gcp-nodectl.sh vm measure [--size tiny|standard|llm] [--timeout SECONDS] [--json]
  gcp-nodectl.sh vm list [--json]
  gcp-nodectl.sh vm delete <name|all>
USAGE
}

main() {
  [ "$#" -ge 2 ] || { usage; exit 2; }
  local subject="$1" action="$2"
  shift 2

  case "${subject}:${action}" in
    control-plane:new) cmd_control_plane_new "$@" ;;
    vm:new) cmd_vm_new "$@" ;;
    vm:measure) cmd_vm_measure "$@" ;;
    vm:list) cmd_vm_list "$@" ;;
    vm:delete) cmd_vm_delete "$@" ;;
    *) usage; fatal "Unsupported command '${subject} ${action}'" ;;
  esac
}

main "$@"
