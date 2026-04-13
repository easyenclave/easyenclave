#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  smoke_test_gcp_vm.sh \
    --project <gcp-project> \
    --zone <zone> \
    --machine-type <machine-type> \
    --image <image-name> \
    --image-project <image-project> \
    --metadata-file <ee-config.json> \
    --mode <container-http|native-static> \
    [--http-port <port>] \
    [--http-path <path>]
EOF
}

PROJECT=""
ZONE=""
MACHINE_TYPE=""
IMAGE=""
IMAGE_PROJECT=""
METADATA_FILE=""
MODE=""
HTTP_PORT=""
HTTP_PATH="/"
FIREWALL_RULE="${FIREWALL_RULE:-ee-smoke-allow-http}"
FIREWALL_TAG="${FIREWALL_TAG:-ee-smoke-test}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT="$2"; shift 2 ;;
    --zone) ZONE="$2"; shift 2 ;;
    --machine-type) MACHINE_TYPE="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    --image-project) IMAGE_PROJECT="$2"; shift 2 ;;
    --metadata-file) METADATA_FILE="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --http-port) HTTP_PORT="$2"; shift 2 ;;
    --http-path) HTTP_PATH="$2"; shift 2 ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

[[ -n "$PROJECT" ]] || { echo "missing --project" >&2; usage >&2; exit 1; }
[[ -n "$ZONE" ]] || { echo "missing --zone" >&2; usage >&2; exit 1; }
[[ -n "$MACHINE_TYPE" ]] || { echo "missing --machine-type" >&2; usage >&2; exit 1; }
[[ -n "$IMAGE" ]] || { echo "missing --image" >&2; usage >&2; exit 1; }
[[ -n "$IMAGE_PROJECT" ]] || { echo "missing --image-project" >&2; usage >&2; exit 1; }
[[ -n "$METADATA_FILE" ]] || { echo "missing --metadata-file" >&2; usage >&2; exit 1; }
[[ -f "$METADATA_FILE" ]] || { echo "metadata file not found: $METADATA_FILE" >&2; exit 1; }
[[ "$MODE" == "container-http" || "$MODE" == "native-static" ]] || {
  echo "mode must be one of: container-http, native-static" >&2
  exit 1
}

VM_NAME="ee-${MODE//[^a-z]/-}-$(date +%s)"
SERIAL_OUTPUT=""

cleanup() {
  gcloud compute instances delete "$VM_NAME" \
    --project="$PROJECT" --zone="$ZONE" --quiet >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ "$MODE" == "container-http" ]]; then
  HTTP_PORT="${HTTP_PORT:-80}"
  HTTP_PATH="${HTTP_PATH:-/}"
fi

if [[ -n "$HTTP_PORT" ]]; then
  gcloud compute firewall-rules describe "$FIREWALL_RULE" \
    --project="$PROJECT" >/dev/null 2>&1 || \
  gcloud compute firewall-rules create "$FIREWALL_RULE" \
    --project="$PROJECT" \
    --allow="tcp:${HTTP_PORT}" \
    --target-tags="$FIREWALL_TAG" \
    --source-ranges=0.0.0.0/0 \
    --quiet
fi

INSTANCE_ARGS=(
  --project="$PROJECT"
  --zone="$ZONE"
  --machine-type="$MACHINE_TYPE"
  --confidential-compute-type=TDX
  --maintenance-policy=TERMINATE
  --image="$IMAGE"
  --image-project="$IMAGE_PROJECT"
  --boot-disk-size=10GB
  --metadata-from-file="ee-config=$METADATA_FILE"
)

if [[ -n "$HTTP_PORT" ]]; then
  INSTANCE_ARGS+=(--tags="$FIREWALL_TAG")
fi

gcloud compute instances create "$VM_NAME" "${INSTANCE_ARGS[@]}"

COMMON_CHECKS=(
  "kernel_boot:Run /init as init process:1"
  "root_resolved:Resolved root to /dev/:1"
  "easyenclave_pid1:easyenclave: running as PID 1:1"
  "tmpfs_mounted:mounted /var/lib/easyenclave:1"
  "cgroup_mounted:mounted /sys/fs/cgroup:1"
  "tdx_attestation:attestation backend: tdx:1"
  "network_up:Device link is up:1"
  "dhcp_lease:lease of .* obtained:1"
  "dns_configured:dns from dhcp lease:1"
  "listening:easyenclave: listening on:1"
)

if [[ "$MODE" == "container-http" ]]; then
  MODE_CHECKS=(
    "container_started:container .* started:1"
    "deployment_running:deployment .* running \\(container=:1"
  )
  FAIL_PATTERNS=(
    "FATAL"
    "Kernel panic"
    "switch_root: can"
    "Invalid ELF header"
    "deployment .* failed"
  )
else
  MODE_CHECKS=(
    "native_pull:pulling .* \\(native static\\):1"
    "native_running:deployment .* running native:1"
  )
  FAIL_PATTERNS=(
    "FATAL"
    "Kernel panic"
    "switch_root: can"
    "Invalid ELF header"
    "native mode requires a static ELF executable"
    "deployment .* failed"
  )
fi

CHECKS=("${COMMON_CHECKS[@]}" "${MODE_CHECKS[@]}")
declare -A PASSED=()
LAST_LINES=0
ALL_REQUIRED_DONE=false

for i in $(seq 1 36); do
  SERIAL_OUTPUT=$(gcloud compute instances get-serial-port-output "$VM_NAME" \
    --project="$PROJECT" --zone="$ZONE" 2>/dev/null || true)

  TOTAL_LINES=$(echo "$SERIAL_OUTPUT" | wc -l | tr -d ' ')
  if [[ "$TOTAL_LINES" -gt "$LAST_LINES" ]]; then
    echo "$SERIAL_OUTPUT" | tail -n +"$((LAST_LINES + 1))" | sed 's/^/[serial] /'
    LAST_LINES="$TOTAL_LINES"
  fi

  for pattern in "${FAIL_PATTERNS[@]}"; do
    if echo "$SERIAL_OUTPUT" | grep -qE "$pattern"; then
      echo "::error::smoke test failed due to fatal serial pattern: $pattern"
      echo "$SERIAL_OUTPUT" | tail -80
      exit 1
    fi
  done

  for check in "${CHECKS[@]}"; do
    IFS=: read -r name pattern required <<<"$check"
    [[ -n "${PASSED[$name]:-}" ]] && continue
    if echo "$SERIAL_OUTPUT" | grep -qE "$pattern"; then
      PASSED[$name]=1
      echo "  ✓ $name"
    fi
  done

  ALL_REQUIRED_DONE=true
  for check in "${CHECKS[@]}"; do
    IFS=: read -r name pattern required <<<"$check"
    [[ "$required" == "0" ]] && continue
    if [[ -z "${PASSED[$name]:-}" ]]; then
      ALL_REQUIRED_DONE=false
      break
    fi
  done

  $ALL_REQUIRED_DONE && break
  echo "  waiting... (${i}/36)"
  sleep 10
done

HTTP_OK=false
if [[ -n "$HTTP_PORT" && "$ALL_REQUIRED_DONE" == "true" ]]; then
  VM_IP=$(gcloud compute instances describe "$VM_NAME" \
    --project="$PROJECT" --zone="$ZONE" \
    --format="value(networkInterfaces[0].accessConfigs[0].natIP)")
  echo ""
  echo "Testing HTTP on ${VM_IP}:${HTTP_PORT}${HTTP_PATH}..."
  for i in $(seq 1 12); do
    code=$(curl -sS -o /dev/null -w '%{http_code}' \
      --connect-timeout 5 "http://${VM_IP}:${HTTP_PORT}${HTTP_PATH}" 2>/dev/null || echo 000)
    if [[ "$code" == "200" ]]; then
      echo "  ✓ http_probe (${VM_IP})"
      HTTP_OK=true
      break
    fi
    echo "  waiting... ${code} (${i}/12)"
    sleep 5
  done
fi

echo ""
echo "=== smoke test (${MODE}) ==="
PASS=0
TOTAL=0
for check in "${CHECKS[@]}"; do
  IFS=: read -r name pattern required <<<"$check"
  [[ "$required" == "1" ]] && TOTAL=$((TOTAL + 1))
  if [[ -n "${PASSED[$name]:-}" ]]; then
    echo "  ✓ $name"
    [[ "$required" == "1" ]] && PASS=$((PASS + 1))
  else
    echo "  ✗ $name"
  fi
done

if [[ -n "$HTTP_PORT" ]]; then
  TOTAL=$((TOTAL + 1))
  if [[ "$HTTP_OK" == "true" ]]; then
    echo "  ✓ http_probe"
    PASS=$((PASS + 1))
  else
    echo "  ✗ http_probe"
  fi
fi

echo "${PASS}/${TOTAL} passed"

if [[ "$ALL_REQUIRED_DONE" != "true" ]]; then
  echo "::error::smoke test did not reach all required serial checkpoints"
  echo "$SERIAL_OUTPUT" | tail -80
  exit 1
fi

if [[ -n "$HTTP_PORT" && "$HTTP_OK" != "true" ]]; then
  echo "::error::smoke test never served HTTP 200"
  echo "$SERIAL_OUTPUT" | tail -80
  exit 1
fi

echo "✓ Smoke test passed"
