#!/usr/bin/env bash
# Build the dm-verity VM image and measure MRTD + RTMRs.
# Outputs: digest, mrtd, rtmrs (to $GITHUB_OUTPUT if set, always to stdout).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# mkosi needs unprivileged user namespaces
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0

# ---------- Build ----------
echo "==> Building verity VM image (mkosi)..."
(cd infra/image && nix develop --command make build)

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
echo "==> Measuring MRTD and RTMRs from temp VM..."
MEASURES=$(python3 infra/tdx_cli.py vm measure --verity --json --timeout 180)
if [ -z "$MEASURES" ]; then
  echo "::error::Failed to capture measurements"
  exit 1
fi
echo "Raw measurements: $MEASURES"

MRTD=$(echo "$MEASURES" | jq -r '.mrtd')
RTMRS=$(echo "$MEASURES" | jq -c '{rtmr0,rtmr1,rtmr2,rtmr3}')

if [ -z "$MRTD" ] || [ "$MRTD" = "null" ]; then
  echo "::error::Failed to measure MRTD"
  exit 1
fi

echo "MRTD: ${MRTD:0:32}..."
echo "RTMRs: $RTMRS"

# ---------- Outputs ----------
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "digest=$DIGEST"
    echo "mrtd=$MRTD"
    echo "rtmrs=$RTMRS"
  } >> "$GITHUB_OUTPUT"
fi
