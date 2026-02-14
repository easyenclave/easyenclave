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

# ---------- Measure ----------
echo "==> Measuring MRTD and RTMRs from temp VMs (tiny/standard/llm)..."

SIZES=(tiny standard llm)
declare -A MRTD_BY_SIZE
declare -A RTMRS_BY_SIZE

for SIZE in "${SIZES[@]}"; do
  echo "--- Measuring node_size=$SIZE ---"
  MEASURES=$(python3 infra/tdx_cli.py vm measure --json --timeout 180 --size "$SIZE")
  if [ -z "$MEASURES" ]; then
    echo "::error::Failed to capture measurements for node_size=$SIZE"
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

  echo "MRTD[$SIZE]: ${MRTD_SIZE:0:32}..."
  echo "RTMRs[$SIZE]: $RTMRS_SIZE"
done

# Backward-compat outputs: use tiny baseline as default
MRTD="${MRTD_BY_SIZE[tiny]}"
RTMRS="${RTMRS_BY_SIZE[tiny]}"

# New outputs: full size-aware trust material
MRTDS=$(printf '%s\n' "${MRTD_BY_SIZE[@]}" | awk 'NF' | sort -u | paste -sd, -)
if [ -z "$MRTDS" ]; then
  echo "::error::Failed to build TRUSTED_AGENT_MRTDS list"
  exit 1
fi

MRTDS_BY_SIZE_JSON=$(jq -cn \
  --arg tiny "${MRTD_BY_SIZE[tiny]}" \
  --arg standard "${MRTD_BY_SIZE[standard]}" \
  --arg llm "${MRTD_BY_SIZE[llm]}" \
  '{tiny: $tiny, standard: $standard, llm: $llm}')

RTMRS_BY_SIZE_JSON=$(jq -cn \
  --argjson tiny "${RTMRS_BY_SIZE[tiny]}" \
  --argjson standard "${RTMRS_BY_SIZE[standard]}" \
  --argjson llm "${RTMRS_BY_SIZE[llm]}" \
  '{tiny: $tiny, standard: $standard, llm: $llm}')

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
