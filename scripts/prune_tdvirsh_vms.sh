#!/usr/bin/env bash
set -euo pipefail

if ! command -v virsh >/dev/null 2>&1; then
  echo "virsh not found; skipping local VM prune."
  exit 0
fi

network_raw="${EASYENCLAVE_NETWORK_NAME:-${EASYENCLAVE_ENV:-network}}"
network_slug="$(echo "${network_raw}" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9-]+/-/g; s/^-+//; s/-+$//; s/-{2,}/-/g')"
if [ -z "${network_slug}" ]; then
  echo "No network slug resolved; skipping local VM prune."
  exit 0
fi

echo "Pruning stale tdvirsh domains for current network='${network_slug}'"
count_current=0
count_orphan=0
mapfile -t all_domains < <(virsh --connect qemu:///system list --all --name | sed '/^$/d')

# 1) Always clear stale domains for the network we are about to bootstrap.
for d in "${all_domains[@]}"; do
  case "$d" in
    tdvirsh-cp-"${network_slug}"-*|tdvirsh-agent-*"${network_slug}"-*)
      echo "  deleting current-network stale domain: $d"
      virsh --connect qemu:///system destroy "$d" >/dev/null 2>&1 || true
      virsh --connect qemu:///system undefine "$d" --nvram >/dev/null 2>&1 || virsh --connect qemu:///system undefine "$d" >/dev/null 2>&1 || true
      count_current=$((count_current + 1))
      ;;
  esac
done

# 2) Cleanup orphaned legacy networks.
# Also cleanup stale same-environment networks even when their CP is still running,
# so a new staging/prod bootstrap does not stack multiple clusters on one host.
declare -A network_domains
declare -A network_has_running_cp
for d in "${all_domains[@]}"; do
  network=""
  is_cp="false"
  if [[ "$d" =~ ^tdvirsh-cp-(.+)-[0-9a-f]{8}$ ]]; then
    network="${BASH_REMATCH[1]}"
    is_cp="true"
  elif [[ "$d" =~ ^tdvirsh-agent-[^-]+-(.+)-[0-9a-f]{8}$ ]]; then
    network="${BASH_REMATCH[1]}"
  else
    continue
  fi
  network_domains["$network"]+="${d}"$'\n'
  if [ "$is_cp" = "true" ]; then
    state="$(virsh --connect qemu:///system domstate "$d" 2>/dev/null | tr -d '\r' | xargs || true)"
    if [ "$state" = "running" ]; then
      network_has_running_cp["$network"]="1"
    fi
  fi
done

env_slug="$(echo "${EASYENCLAVE_ENV:-}" | tr '[:upper:]' '[:lower:]' | xargs)"
network_is_same_environment() {
  local network="$1"
  local cp_domain=""
  local cp_ip=""
  local health=""
  local proxy_url=""
  local state=""

  [ -n "$env_slug" ] || return 1

  for d in "${all_domains[@]}"; do
    case "$d" in
      tdvirsh-cp-"${network}"-*)
        state="$(virsh --connect qemu:///system domstate "$d" 2>/dev/null | tr -d '\r' | xargs || true)"
        if [ "$state" = "running" ]; then
          cp_domain="$d"
          break
        fi
        ;;
    esac
  done
  [ -n "$cp_domain" ] || return 1

  cp_ip="$(virsh --connect qemu:///system domifaddr "$cp_domain" --source lease 2>/dev/null | awk '/ipv4/ {print $4}' | head -n1 | cut -d/ -f1)"
  [ -n "$cp_ip" ] || return 1

  health="$(curl -fsS --max-time 5 "http://${cp_ip}:8080/health" 2>/dev/null || true)"
  proxy_url="$(echo "${health}" | jq -r '.proxy_url // empty' 2>/dev/null || true)"
  [ -n "$proxy_url" ] || return 1

  case "$env_slug" in
    staging)
      [[ "$proxy_url" == *"app-staging."* ]]
      ;;
    production|prod)
      [[ "$proxy_url" == *"app."* && "$proxy_url" != *"app-staging."* ]]
      ;;
    *)
      return 1
      ;;
  esac
}

for network in "${!network_domains[@]}"; do
  if [ "$network" = "$network_slug" ]; then
    continue
  fi
  if [ "${network_has_running_cp[$network]:-0}" = "1" ]; then
    if network_is_same_environment "$network"; then
      echo "  deleting stale same-environment network domains: env=${env_slug} network=${network}"
    else
      continue
    fi
  else
    echo "  deleting orphaned network domains: network=$network"
  fi
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    echo "    deleting orphan domain: $d"
    virsh --connect qemu:///system destroy "$d" >/dev/null 2>&1 || true
    virsh --connect qemu:///system undefine "$d" --nvram >/dev/null 2>&1 || virsh --connect qemu:///system undefine "$d" >/dev/null 2>&1 || true
    count_orphan=$((count_orphan + 1))
  done <<< "${network_domains[$network]}"
done

echo "Pruned ${count_current} current-network domain(s) and ${count_orphan} orphan-network domain(s)."
