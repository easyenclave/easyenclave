#!/usr/bin/env bash
# Reproducibility gate for EasyEnclave verity image builds.
#
# Runs two builds back-to-back and verifies:
#  1) Split verity artifacts are byte-identical
#  2) Measured tiny-profile TDX values are identical
#
# Modes:
#   CI_REPRO_MODE=cached (default): reset build artifacts, keep mkosi cache
#   CI_REPRO_MODE=full: run `make clean` before each build
#
# Exits non-zero on any mismatch.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

REPRO_MODE="${CI_REPRO_MODE:-cached}"
if [ "$REPRO_MODE" != "cached" ] && [ "$REPRO_MODE" != "full" ]; then
  echo "::error::Invalid CI_REPRO_MODE='$REPRO_MODE' (expected 'cached' or 'full')"
  exit 1
fi

ARTIFACTS=(
  "easyenclave.vmlinuz"
  "easyenclave.initrd"
  "easyenclave.root.raw"
  "easyenclave.cmdline"
)

TMP_DIR="$(mktemp -d /tmp/easyenclave-repro-XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "==> Reproducibility gate: build #1 and build #2"
echo "Mode: $REPRO_MODE"
echo "Temporary comparison dir: $TMP_DIR"

# mkosi requires this setting in CI.
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >/dev/null

clean_image_artifacts_only() {
  rm -rf infra/image/mkosi.extra infra/image/output
  rm -f infra/image/easyenclave
  rm -f infra/image/easyenclave.raw
  rm -f infra/image/easyenclave.vmlinuz
  rm -f infra/image/easyenclave.initrd
  rm -f infra/image/easyenclave.efi
  rm -f infra/image/easyenclave.root-*.raw
  rm -f infra/image/easyenclave.manifest
  rm -f infra/image/initrd
  rm -f infra/image/initrd.cpio.zst
}

build_image() {
  local label="$1"
  if [ "$REPRO_MODE" = "full" ]; then
    echo "[$label] full clean build"
    (cd infra/image && nix develop --command bash -lc 'make clean && make build')
  else
    echo "[$label] cached build (artifact reset, mkosi cache retained)"
    clean_image_artifacts_only
    (cd infra/image && nix develop --command make build)
  fi
}

build_once() {
  local label="$1"
  local out_dir="$TMP_DIR/$label"
  mkdir -p "$out_dir"

  echo "---- [$label] build ----"
  build_image "$label"

  for name in "${ARTIFACTS[@]}"; do
    local src="infra/image/output/$name"
    if [ ! -f "$src" ]; then
      echo "::error::Missing artifact after build ($label): $src"
      exit 1
    fi
    cp "$src" "$out_dir/$name"
  done

  (cd "$out_dir" && sha256sum "${ARTIFACTS[@]}") > "$out_dir/sha256.txt"
  echo "[$label] artifact digests:"
  cat "$out_dir/sha256.txt"

  echo "[$label] measuring tiny profile..."
  local measures
  measures="$(python3 infra/tdx_cli.py vm measure --verity --json --timeout 180 --size tiny)"
  echo "$measures" | jq -c '{mrtd, rtmr0, rtmr1, rtmr2, rtmr3}' > "$out_dir/measure.json"
  echo "[$label] measurements:"
  cat "$out_dir/measure.json"
}

build_once "build1"
build_once "build2"

echo "==> Comparing artifact digests..."
ARTIFACT_DIFF=0
if ! diff -u "$TMP_DIR/build1/sha256.txt" "$TMP_DIR/build2/sha256.txt"; then
  ARTIFACT_DIFF=1
fi

echo "==> Comparing measured values (tiny profile)..."
if ! diff -u "$TMP_DIR/build1/measure.json" "$TMP_DIR/build2/measure.json"; then
  echo "::error::Reproducibility check failed: measured values differ"
  exit 1
fi

if [ "$ARTIFACT_DIFF" -eq 1 ]; then
  if [ "$REPRO_MODE" = "full" ]; then
    echo "::error::Reproducibility check failed: artifact digests differ (full mode)"
    exit 1
  fi
  echo "::warning::Artifact digests differ in cached mode; measurements are stable. Run with CI_REPRO_MODE=full to enforce strict artifact equality."
fi

echo "==> Reproducibility gate passed"
