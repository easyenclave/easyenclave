#!/usr/bin/env bash
set -euo pipefail

if [ -z "${CP_URL:-}" ]; then
  echo "::error::CP_URL is required"
  exit 1
fi

TARGET_DATACENTER="${TARGET_DATACENTER:-baremetal:github-runner}"
KEEP_SPARE_COUNT="${KEEP_SPARE_COUNT:-1}"
DRY_RUN="${DRY_RUN:-false}"

login_with_password() {
  local candidate="${1:-}" body code token
  [ -n "$candidate" ] || return 1
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

ADMIN_TOKEN=""
if [ -n "${CP_ADMIN_PASSWORD:-}" ]; then
  ADMIN_TOKEN="$(login_with_password "${CP_ADMIN_PASSWORD}" || true)"
fi
if [ -z "$ADMIN_TOKEN" ]; then
  generated_pw="$(curl -sSf "${CP_URL}/auth/methods" | jq -r '.generated_password // empty' || true)"
  if [ -n "$generated_pw" ]; then
    ADMIN_TOKEN="$(login_with_password "$generated_pw" || true)"
  fi
fi
if [ -z "$ADMIN_TOKEN" ]; then
  echo "::warning::Could not obtain admin token; VM deletion will skip explicit CP agent delete"
fi

mapfile -t local_vms < <(python3 infra/tdx_cli.py vm list | sed '/^\s*$/d')
if [ "${#local_vms[@]}" -eq 0 ]; then
  echo "No local tdx VMs found."
  exit 0
fi

local_vms_json="$(printf '%s\n' "${local_vms[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
agents_file="$(mktemp)"
local_vms_file="$(mktemp)"
cleanup_tmp() {
  rm -f "$agents_file" "$local_vms_file"
}
trap cleanup_tmp EXIT

curl -sSf "${CP_URL}/api/v1/agents" > "$agents_file"
printf '%s\n' "$local_vms_json" > "$local_vms_file"

keep_vms_json="$(jq -c \
  --slurpfile local "$local_vms_file" \
  --arg dc "$TARGET_DATACENTER" \
  --argjson keep_spare "$KEEP_SPARE_COUNT" '
  def in_local($vm): (($local[0] // []) | index($vm)) != null;
  def is_llm: ((.node_size // "" | ascii_downcase) == "llm");
  def in_dc: ((.datacenter // "" | ascii_downcase) == ($dc | ascii_downcase));
  def healthy_verified: ((.health_status // "" | ascii_downcase) == "healthy") and ((.verified // false) == true);
  def sort_recent: sort_by(.registered_at // "") | reverse;

  ((.agents // []) | map(select(in_local(.vm_name // "") and is_llm and in_dc and healthy_verified))) as $rows
  | ($rows | map(select((.deployed_app // "") == "measuring-enclave-llm")) | sort_recent | .[0:1]) as $keep_measurer
  | ($rows | map(select((.deployed_app // "") == "private-llm")) | sort_recent | .[0:1]) as $keep_private
  | ($rows
      | map(select(
          (.status // "" | ascii_downcase) == "undeployed"
          and ((.deployed_app // "") | startswith("measuring-enclave") | not)
        ))
      | sort_recent
      | .[0:$keep_spare]
    ) as $keep_spare_rows
  | ($keep_measurer + $keep_private + $keep_spare_rows | map(.vm_name) | map(select(length > 0)) | unique)
' "$agents_file")"

delete_vms_json="$(jq -c \
  --slurpfile local "$local_vms_file" \
  --argjson keep "$keep_vms_json" '
  def in_local($vm): (($local[0] // []) | index($vm)) != null;
  (.agents // [])
  | map(select(
      in_local(.vm_name // "")
      and ((.node_size // "" | ascii_downcase) == "llm")
      and (($keep | index(.vm_name // "")) == null)
      and ((.vm_name // "") != "")
    ))
  | map(.vm_name)
  | unique
' "$agents_file")"

echo "Local VMs: $(echo "$local_vms_json" | jq -r 'length')"
echo "Keeping LLM VMs: $(echo "$keep_vms_json" | jq -r 'length')"
echo "Deleting LLM VMs: $(echo "$delete_vms_json" | jq -r 'length')"
echo "Keep list: $(echo "$keep_vms_json" | jq -r 'join(",")')"
echo "Delete list: $(echo "$delete_vms_json" | jq -r 'join(",")')"

if [ "$DRY_RUN" = "true" ]; then
  echo "Dry run enabled; skipping delete operations."
  exit 0
fi

while IFS= read -r vm; do
  [ -n "$vm" ] || continue
  echo "Deleting stale CI LLM VM: $vm"
  if [ -n "$ADMIN_TOKEN" ]; then
    python3 infra/tdx_cli.py vm delete "$vm" --easyenclave-url "${CP_URL}" --admin-token "${ADMIN_TOKEN}" || true
  else
    python3 infra/tdx_cli.py vm delete "$vm" --easyenclave-url "${CP_URL}" || true
  fi
done < <(echo "$delete_vms_json" | jq -r '.[]')
