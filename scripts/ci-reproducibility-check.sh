#!/usr/bin/env bash
# Determinism gate for trusted measurements sourced from real GCP TDX boots.
# Runs two back-to-back measurement passes and verifies trusted-value stability.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

REPORT_DIR="${REPRO_REPORT_DIR:-infra/output/reproducibility}"
MEASURE_SIZES="${MEASURE_SIZES:-tiny,standard,llm}"
TMP_DIR="$(mktemp -d /tmp/easyenclave-repro-XXXXXX)"

ARTIFACT_MATCH="unknown"
MEASUREMENT_MATCH="unknown"
FAIL_REASON=""
ROOTFS_DIGEST=""
TRUSTED_MRTD=""
TRUSTED_MRTDS=""
TRUSTED_MRTDS_BY_SIZE=""
TRUSTED_RTMRS=""
TRUSTED_RTMRS_BY_SIZE=""

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "::error::Required command not found: $cmd"
    exit 1
  fi
}

require_cmd jq
require_cmd python3

parse_output_value() {
  local file="$1"
  local key="$2"
  grep -E "^${key}=" "$file" | tail -n1 | sed -E "s/^${key}=//"
}

run_measure_pass() {
  local label="$1"
  local out_dir="$TMP_DIR/$label"
  local gh_out="$out_dir/github_output.txt"
  local start_epoch end_epoch
  local start_iso end_iso

  mkdir -p "$out_dir"
  : > "$gh_out"

  start_epoch="$(date -u +%s)"
  start_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  echo "---- [$label] measurement pass ----"
  GITHUB_OUTPUT="$gh_out" MEASURE_SIZES="$MEASURE_SIZES" ./scripts/ci-build-measure.sh

  end_epoch="$(date -u +%s)"
  end_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  local digest mrtd mrtds mrtds_by_size rtmrs rtmrs_by_size
  digest="$(parse_output_value "$gh_out" digest)"
  mrtd="$(parse_output_value "$gh_out" mrtd)"
  mrtds="$(parse_output_value "$gh_out" mrtds)"
  mrtds_by_size="$(parse_output_value "$gh_out" mrtds_by_size)"
  rtmrs="$(parse_output_value "$gh_out" rtmrs)"
  rtmrs_by_size="$(parse_output_value "$gh_out" rtmrs_by_size)"

  if [ -z "$digest" ] || [ -z "$mrtd" ] || [ -z "$mrtds" ] || [ -z "$mrtds_by_size" ] || [ -z "$rtmrs" ] || [ -z "$rtmrs_by_size" ]; then
    echo "::error::Measurement pass '$label' did not emit complete trusted values"
    exit 1
  fi

  echo "$mrtds_by_size" | jq -e 'type == "object" and length > 0' >/dev/null
  echo "$rtmrs" | jq -e 'type == "object"' >/dev/null
  echo "$rtmrs_by_size" | jq -e 'type == "object" and length > 0' >/dev/null

  jq -cn \
    --arg digest "$digest" \
    --arg mrtd "$mrtd" \
    --arg mrtds "$mrtds" \
    --argjson mrtds_by_size "$mrtds_by_size" \
    --argjson rtmrs "$rtmrs" \
    --argjson rtmrs_by_size "$rtmrs_by_size" \
    '{digest: $digest, mrtd: $mrtd, mrtds: $mrtds, mrtds_by_size: $mrtds_by_size, rtmrs: $rtmrs, rtmrs_by_size: $rtmrs_by_size}' \
    > "$out_dir/trusted_values.json"

  jq -cn \
    --arg mrtd "$mrtd" \
    --argjson rtmrs "$rtmrs" \
    '{mrtd: $mrtd, rtmr0: ($rtmrs.rtmr0 // ""), rtmr1: ($rtmrs.rtmr1 // ""), rtmr2: ($rtmrs.rtmr2 // ""), rtmr3: ($rtmrs.rtmr3 // "")}' \
    > "$out_dir/measure.json"

  printf '%s  trusted_values.json\n' "$digest" > "$out_dir/sha256.txt"
  printf 'trusted_values.json\t%s\n' "$(stat -c '%s' "$out_dir/trusted_values.json")" > "$out_dir/sizes.tsv"

  jq -n \
    --arg label "$label" \
    --arg started_utc "$start_iso" \
    --arg ended_utc "$end_iso" \
    --argjson duration_seconds "$((end_epoch - start_epoch))" \
    '{label: $label, started_utc: $started_utc, ended_utc: $ended_utc, duration_seconds: $duration_seconds}' \
    > "$out_dir/timing.json"

  if [ "$label" = "build2" ]; then
    ROOTFS_DIGEST="$digest"
    TRUSTED_MRTD="$mrtd"
    TRUSTED_MRTDS="$mrtds"
    TRUSTED_MRTDS_BY_SIZE="$mrtds_by_size"
    TRUSTED_RTMRS="$rtmrs"
    TRUSTED_RTMRS_BY_SIZE="$rtmrs_by_size"
  fi
}

echo "==> Reproducibility gate (GCP TDX): build #1 and build #2"
echo "Measure sizes: $MEASURE_SIZES"
echo "Report output: $REPORT_DIR"

rm -rf "$REPORT_DIR"
mkdir -p "$REPORT_DIR"

run_measure_pass "build1"
run_measure_pass "build2"

echo "==> Comparing trusted digest outputs..."
if diff -u "$TMP_DIR/build1/sha256.txt" "$TMP_DIR/build2/sha256.txt" > "$TMP_DIR/artifact.diff"; then
  ARTIFACT_MATCH="true"
else
  ARTIFACT_MATCH="false"
  FAIL_REASON="${FAIL_REASON:-trusted_digest_mismatch}"
  echo "::error::Reproducibility check failed: trusted digests differ"
fi

echo "==> Comparing trusted measurement payloads..."
if diff -u <(jq -S . "$TMP_DIR/build1/trusted_values.json") <(jq -S . "$TMP_DIR/build2/trusted_values.json") > "$TMP_DIR/measurement.diff"; then
  MEASUREMENT_MATCH="true"
else
  MEASUREMENT_MATCH="false"
  FAIL_REASON="${FAIL_REASON:-trusted_values_mismatch}"
  echo "::error::Reproducibility check failed: trusted values differ"
fi

cp "$TMP_DIR/build1/sha256.txt" "$REPORT_DIR/build1.sha256.txt"
cp "$TMP_DIR/build2/sha256.txt" "$REPORT_DIR/build2.sha256.txt"
cp "$TMP_DIR/build1/sizes.tsv" "$REPORT_DIR/build1.sizes.tsv"
cp "$TMP_DIR/build2/sizes.tsv" "$REPORT_DIR/build2.sizes.tsv"
cp "$TMP_DIR/build1/measure.json" "$REPORT_DIR/build1.measure.json"
cp "$TMP_DIR/build2/measure.json" "$REPORT_DIR/build2.measure.json"
cp "$TMP_DIR/build1/timing.json" "$REPORT_DIR/build1.timing.json"
cp "$TMP_DIR/build2/timing.json" "$REPORT_DIR/build2.timing.json"
cp "$TMP_DIR/artifact.diff" "$REPORT_DIR/artifact.diff"
cp "$TMP_DIR/measurement.diff" "$REPORT_DIR/measurement.diff"
cp "$TMP_DIR/build2/trusted_values.json" "$REPORT_DIR/trusted_values.json"

status="passed"
if [ "$ARTIFACT_MATCH" != "true" ] || [ "$MEASUREMENT_MATCH" != "true" ]; then
  status="failed"
fi

jq -cn \
  --arg status "$status" \
  --arg artifact_match "$ARTIFACT_MATCH" \
  --arg measurement_match "$MEASUREMENT_MATCH" \
  --arg failure_reason "$FAIL_REASON" \
  --slurpfile b1 "$TMP_DIR/build1/trusted_values.json" \
  --slurpfile b2 "$TMP_DIR/build2/trusted_values.json" \
  '{
    status: $status,
    artifact_match: ($artifact_match == "true"),
    measurement_match: ($measurement_match == "true"),
    failure_reason: ($failure_reason | select(length > 0)),
    build1: ($b1[0] // {}),
    build2: ($b2[0] // {})
  }' > "$REPORT_DIR/report.json"

{
  echo "## Determinism Report"
  echo
  echo "- Status: **$(echo "$status" | tr '[:lower:]' '[:upper:]')**"
  echo "- Artifact digest match: **$ARTIFACT_MATCH**"
  echo "- Trusted measurement payload match: **$MEASUREMENT_MATCH**"
  if [ -n "$FAIL_REASON" ]; then
    echo "- Failure reason: \`$FAIL_REASON\`"
  fi
} > "$REPORT_DIR/summary.md"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "report_json=$REPORT_DIR/report.json"
    echo "report_summary=$REPORT_DIR/summary.md"
    echo "digest=$ROOTFS_DIGEST"
    echo "mrtd=$TRUSTED_MRTD"
    echo "mrtds=$TRUSTED_MRTDS"
    echo "mrtds_by_size=$TRUSTED_MRTDS_BY_SIZE"
    echo "rtmrs=$TRUSTED_RTMRS"
    echo "rtmrs_by_size=$TRUSTED_RTMRS_BY_SIZE"
  } >> "$GITHUB_OUTPUT"
fi

if [ "$status" != "passed" ]; then
  exit 1
fi

echo "==> Reproducibility gate passed"
