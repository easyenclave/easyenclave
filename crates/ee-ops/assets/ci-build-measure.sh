#!/usr/bin/env bash
# Measure trusted MRTD/RTMR values from real GCP TDX VMs.
# Outputs (to $GITHUB_OUTPUT when set):
#   - digest: SHA256 over canonical trusted-value JSON payload
#   - mrtd/rtmrs: baseline (tiny when measured, otherwise first size)
#   - mrtds: comma-separated unique MRTDs
#   - mrtds_by_size: JSON map {tiny|standard|llm -> mrtd}
#   - rtmrs_by_size: JSON map {tiny|standard|llm -> {rtmr0..rtmr3}}
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "::error::Required command not found: $cmd"
    exit 1
  fi
}

require_cmd python3
require_cmd jq
require_cmd sha256sum

MEASURE_SIZES="${MEASURE_SIZES:-tiny}"
MEASURE_ATTEMPTS="${MEASURE_ATTEMPTS:-3}"
MEASURE_RETRY_SLEEP_SECONDS="${MEASURE_RETRY_SLEEP_SECONDS:-10}"
MEASURE_TIMEOUT_SECONDS="${MEASURE_TIMEOUT_SECONDS:-240}"

echo "==> Measuring MRTD and RTMRs from GCP TDX VMs (${MEASURE_SIZES})..."

IFS=',' read -r -a SIZES <<<"$MEASURE_SIZES"
if [ "${#SIZES[@]}" -eq 0 ]; then
  echo "::error::MEASURE_SIZES is empty"
  exit 1
fi

for s in "${SIZES[@]}"; do
  case "$s" in
    tiny | standard | llm) ;;
    *)
      echo "::error::Unsupported node_size in MEASURE_SIZES: '$s' (expected tiny,standard,llm)"
      exit 1
      ;;
  esac
done

MRTDS_BY_SIZE_JSON='{}'
RTMRS_BY_SIZE_JSON='{}'

for SIZE in "${SIZES[@]}"; do
  echo "--- Measuring node_size=$SIZE ---"
  MEASURES=""
  measure_ok="false"
  for attempt in $(seq 1 "$MEASURE_ATTEMPTS"); do
    echo "Measurement attempt ${attempt}/${MEASURE_ATTEMPTS} for node_size=$SIZE"
    set +e
    MEASURES="$(
      python3 infra/tdx_cli.py vm measure \
        --json \
        --timeout "$MEASURE_TIMEOUT_SECONDS" \
        --size "$SIZE" \
        2>"/tmp/ci-build-measure-${SIZE}.err"
    )"
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
    if [ "$attempt" -lt "$MEASURE_ATTEMPTS" ]; then
      sleep "$MEASURE_RETRY_SLEEP_SECONDS"
    fi
  done

  if [ "$measure_ok" != "true" ]; then
    echo "::error::Failed to capture measurements for node_size=$SIZE after ${MEASURE_ATTEMPTS} attempts"
    exit 1
  fi

  MRTD_SIZE="$(echo "$MEASURES" | jq -r '.mrtd')"
  RTMRS_SIZE="$(echo "$MEASURES" | jq -c '{rtmr0,rtmr1,rtmr2,rtmr3}')"

  if [ -z "$MRTD_SIZE" ] || [ "$MRTD_SIZE" = "null" ]; then
    echo "::error::Failed to measure MRTD for node_size=$SIZE"
    exit 1
  fi

  MRTDS_BY_SIZE_JSON="$(
    jq -cn --arg k "$SIZE" --arg v "$MRTD_SIZE" --argjson obj "$MRTDS_BY_SIZE_JSON" '$obj + {($k): $v}'
  )"
  RTMRS_BY_SIZE_JSON="$(
    jq -cn --arg k "$SIZE" --argjson v "$RTMRS_SIZE" --argjson obj "$RTMRS_BY_SIZE_JSON" '$obj + {($k): $v}'
  )"

  echo "MRTD[$SIZE]: ${MRTD_SIZE:0:32}..."
  echo "RTMRs[$SIZE]: $RTMRS_SIZE"
done

DEFAULT_SIZE="${SIZES[0]}"
if echo "$MRTDS_BY_SIZE_JSON" | jq -e 'has("tiny")' >/dev/null; then
  DEFAULT_SIZE="tiny"
fi

MRTD="$(echo "$MRTDS_BY_SIZE_JSON" | jq -r --arg s "$DEFAULT_SIZE" '.[$s]')"
RTMRS="$(echo "$RTMRS_BY_SIZE_JSON" | jq -c --arg s "$DEFAULT_SIZE" '.[$s]')"

MRTDS="$(echo "$MRTDS_BY_SIZE_JSON" | jq -r '[.[]] | map(select(type == "string" and length > 0)) | unique | join(",")')"
if [ -z "$MRTDS" ]; then
  echo "::error::Failed to build TRUSTED_AGENT_MRTDS list"
  exit 1
fi

DIGEST_PAYLOAD="$(
  jq -cn \
    --argjson mrtds_by_size "$MRTDS_BY_SIZE_JSON" \
    --argjson rtmrs_by_size "$RTMRS_BY_SIZE_JSON" \
    '{mrtds_by_size: $mrtds_by_size, rtmrs_by_size: $rtmrs_by_size}'
)"
DIGEST="$(printf '%s' "$DIGEST_PAYLOAD" | sha256sum | awk '{print $1}')"
echo "Trusted-values digest: $DIGEST"

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
