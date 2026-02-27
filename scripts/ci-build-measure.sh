#!/usr/bin/env bash
# Build the dm-verity VM image and measure MRTD + RTMRs.
# Outputs:
#   - digest: rootfs SHA256
#   - mrtd/rtmrs: legacy tiny baseline
#   - mrtds: comma-separated trusted MRTDs across measured sizes
#   - rtmrs_by_size: JSON map {tiny|standard|llm -> {rtmr0..rtmr3}}
# (written to $GITHUB_OUTPUT when available)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# mkosi needs unprivileged user namespaces
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0

# ---------- Build ----------
echo "==> Building verity VM image (mkosi)..."
(cd infra/image && nix develop --command bash -lc 'make clean && make build')

CMDLINE="infra/image/output/easyenclave.cmdline"
ROOTFS="infra/image/output/easyenclave.root.raw"

# Verify roothash is baked in
cat "$CMDLINE"
if ! grep -q "roothash=" "$CMDLINE"; then
  echo "::error::No roothash in cmdline"
  exit 1
fi

# Rootfs digest (for build provenance attestation)
DIGEST=$(sha256sum "$ROOTFS" | cut -d' ' -f1)
echo "Rootfs digest: $DIGEST"

MEASURE_SIZES="${MEASURE_SIZES:-tiny}"
MEASURE_ATTEMPTS="${MEASURE_ATTEMPTS:-3}"
MEASURE_RETRY_SLEEP_SECONDS="${MEASURE_RETRY_SLEEP_SECONDS:-10}"

# ---------- Measure ----------
echo "==> Measuring MRTD and RTMRs from temp VMs (${MEASURE_SIZES})..."

IFS=',' read -r -a SIZES <<<"$MEASURE_SIZES"
if [ "${#SIZES[@]}" -eq 0 ]; then
  echo "::error::MEASURE_SIZES is empty"
  exit 1
fi

for s in "${SIZES[@]}"; do
  case "$s" in
    tiny|standard|llm) ;;
    *)
      echo "::error::Unsupported node_size in MEASURE_SIZES: '$s' (expected tiny,standard,llm)"
      exit 1
      ;;
  esac
done

declare -A MRTD_BY_SIZE
declare -A RTMRS_BY_SIZE

MRTDS_BY_SIZE_JSON='{}'
RTMRS_BY_SIZE_JSON='{}'

for SIZE in "${SIZES[@]}"; do
  echo "--- Measuring node_size=$SIZE ---"
  MEASURES=""
  measure_ok="false"
  for attempt in $(seq 1 "$MEASURE_ATTEMPTS"); do
    echo "Measurement attempt ${attempt}/${MEASURE_ATTEMPTS} for node_size=$SIZE"
    set +e
    MEASURES=$(python3 infra/tdx_cli.py vm measure --json --timeout 180 --size "$SIZE" 2>"/tmp/ci-build-measure-${SIZE}.err")
    measure_rc=$?
    set -e

    if [ "$measure_rc" -eq 0 ] \
      && [ -n "${MEASURES:-}" ] \
      && echo "$MEASURES" | jq -e '.mrtd and .rtmr0 and .rtmr1 and .rtmr2 and .rtmr3' >/dev/null 2>&1; then
      measure_ok="true"
      break
    fi

    echo "::warning::Measurement attempt ${attempt}/${MEASURE_ATTEMPTS} failed for node_size=$SIZE (rc=${measure_rc})."
    if [ -s "/tmp/ci-build-measure-${SIZE}.err" ]; then
      tail -n 20 "/tmp/ci-build-measure-${SIZE}.err" || true
    fi
    ./scripts/prune_tdvirsh_vms.sh || true
    if [ "$attempt" -lt "$MEASURE_ATTEMPTS" ]; then
      sleep "$MEASURE_RETRY_SLEEP_SECONDS"
    fi
  done

  if [ "$measure_ok" != "true" ]; then
    echo "::error::Failed to capture measurements for node_size=$SIZE after ${MEASURE_ATTEMPTS} attempts"
    exit 1
  fi

  MRTD_SIZE=$(echo "$MEASURES" | jq -r '.mrtd')
  RTMRS_SIZE=$(echo "$MEASURES" | jq -c '{rtmr0,rtmr1,rtmr2,rtmr3}')

  if [ -z "$MRTD_SIZE" ] || [ "$MRTD_SIZE" = "null" ]; then
    echo "::error::Failed to measure MRTD for node_size=$SIZE"
    exit 1
  fi

  MRTD_BY_SIZE["$SIZE"]="$MRTD_SIZE"
  RTMRS_BY_SIZE["$SIZE"]="$RTMRS_SIZE"

  MRTDS_BY_SIZE_JSON=$(jq -cn --arg k "$SIZE" --arg v "$MRTD_SIZE" --argjson obj "$MRTDS_BY_SIZE_JSON" '$obj + {($k): $v}')
  RTMRS_BY_SIZE_JSON=$(jq -cn --arg k "$SIZE" --argjson v "$RTMRS_SIZE" --argjson obj "$RTMRS_BY_SIZE_JSON" '$obj + {($k): $v}')

  echo "MRTD[$SIZE]: ${MRTD_SIZE:0:32}..."
  echo "RTMRs[$SIZE]: $RTMRS_SIZE"
done

# Backward-compat outputs: use tiny baseline as default when measured; otherwise first measured size.
DEFAULT_SIZE="${SIZES[0]}"
if [ -n "${MRTD_BY_SIZE[tiny]:-}" ]; then
  DEFAULT_SIZE="tiny"
fi
MRTD="${MRTD_BY_SIZE[$DEFAULT_SIZE]}"
RTMRS="${RTMRS_BY_SIZE[$DEFAULT_SIZE]}"

# New outputs: full size-aware trust material
MRTDS=$(printf '%s\n' "${MRTD_BY_SIZE[@]}" | awk 'NF' | sort -u | paste -sd, -)
if [ -z "$MRTDS" ]; then
  echo "::error::Failed to build TRUSTED_AGENT_MRTDS list"
  exit 1
fi

# ---------- Outputs ----------
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "digest=$DIGEST"
    echo "mrtd=$MRTD"
    echo "mrtds=$MRTDS"
    echo "mrtds_by_size=$MRTDS_BY_SIZE_JSON"
    echo "rtmrs=$RTMRS"
    echo "rtmrs_by_size=$RTMRS_BY_SIZE_JSON"
  } >> "$GITHUB_OUTPUT"
fi
