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

agents_file="$(mktemp)"
local_entries_file="$(mktemp)"
local_vms_raw_file="$(mktemp)"
cleanup_tmp() {
  rm -f "$agents_file" "$local_entries_file" "$local_vms_raw_file"
}
trap cleanup_tmp EXIT

curl -sSf "${CP_URL}/api/v1/agents" \
  | jq '{
      agents: [
        .agents[] | {
          vm_name,
          node_size,
          datacenter,
          status,
          deployed_app,
          health_status,
          verified,
          registered_at
        }
      ]
    }' \
  > "$agents_file"

printf '%s\n' "${local_vms[@]}" > "$local_vms_raw_file"

python3 - "$local_vms_raw_file" <<'PY' > "$local_entries_file"
import base64
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
import zlib

if len(sys.argv) < 2:
    print("[]")
    sys.exit(0)

entries = []
with open(sys.argv[1], "r", encoding="utf-8") as f:
  for raw in f:
    domain = raw.strip()
    if not domain:
        continue

    vm_id = ""
    node_size = ""
    try:
        xml = subprocess.check_output(
            ["virsh", "--connect", "qemu:///system", "dumpxml", domain],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        root = ET.fromstring(xml)
        cmdline = ""
        os_node = root.find("./os")
        if os_node is not None:
            cmdline = os_node.findtext("cmdline") or ""

        payload = None
        match = re.search(r"easyenclave\.configz=([^\s]+)", cmdline)
        if match:
            payload = zlib.decompress(base64.b64decode(match.group(1)))
        else:
            match = re.search(r"easyenclave\.config=([^\s]+)", cmdline)
            if match:
                payload = base64.b64decode(match.group(1))

        if payload:
            cfg = json.loads(payload.decode())
            vm_id = str(cfg.get("vm_id", "") or "")
            node_size = str(cfg.get("node_size", "") or "")
    except Exception:
        pass

    agent_vm_name = f"tdx-agent-{vm_id[:8]}" if vm_id else ""
    entries.append(
        {
            "domain": domain,
            "vm_id": vm_id,
            "agent_vm_name": agent_vm_name,
            "node_size": node_size,
        }
    )

print(json.dumps(entries))
PY

keep_vms_json="$(jq -c \
  --slurpfile local "$local_entries_file" \
  --arg dc "$TARGET_DATACENTER" \
  --argjson keep_spare "$KEEP_SPARE_COUNT" '
  def in_dc($a): (($a.datacenter // "" | ascii_downcase) == ($dc | ascii_downcase));
  def healthy_verified($a): (($a.health_status // "" | ascii_downcase) == "healthy") and (($a.verified // false) == true);
  def sort_recent: sort_by(.registered_at // "") | reverse;

  ((.agents // [])) as $agents
  | (($local[0] // [])
      | map(
          . + {
            agent: (
              [ $agents[] | select((.vm_name // "") == (.agent_vm_name // "")) ] | first // null
            )
          }
        )
      | map(
          . + {
            registered_at: ((.agent.registered_at // "") | tostring),
            deployed_app: ((.agent.deployed_app // "") | tostring),
            status: ((.agent.status // "") | tostring),
            healthy_verified: (if .agent == null then false else healthy_verified(.agent) end),
            in_dc: (if .agent == null then false else in_dc(.agent) end)
          }
        )
      | map(select((.node_size // "" | ascii_downcase) == "llm"))
    ) as $rows
  | ($rows
      | map(select(.agent != null and .healthy_verified and .in_dc and (.deployed_app == "measuring-enclave-llm")))
      | sort_recent
      | .[0:1]
    ) as $keep_measurer
  | ($rows
      | map(select(.agent != null and .healthy_verified and .in_dc and (.deployed_app == "private-llm")))
      | sort_recent
      | .[0:1]
    ) as $keep_private
  | ($rows
      | map(select(
          .agent != null
          and .healthy_verified
          and .in_dc
          and (.status | ascii_downcase) == "undeployed"
          and ((.deployed_app) | startswith("measuring-enclave") | not)
        ))
      | sort_recent
      | .[0:$keep_spare]
    ) as $keep_spare_rows
  | ($keep_measurer + $keep_private + $keep_spare_rows | map(.domain) | map(select(length > 0)) | unique)
' "$agents_file")"

delete_vms_json="$(jq -cn \
  --slurpfile local "$local_entries_file" \
  --argjson keep "$keep_vms_json" '
  (($local[0] // [])
  | map(select(
      (.domain // "") as $d
      | ((.node_size // "" | ascii_downcase) == "llm")
      and ($d != "")
      and (($keep | index($d)) == null)
    ))
  | map(.domain)
  | unique
 )'
)"

echo "Local VMs: $(echo "${#local_vms[@]}")"
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
