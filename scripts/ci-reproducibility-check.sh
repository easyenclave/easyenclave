#!/usr/bin/env bash
# Reproducibility gate for EasyEnclave verity image builds.
#
# Runs two clean builds back-to-back and verifies:
#  1) Split verity artifacts are byte-identical
#  2) Measured tiny-profile TDX values are identical
#
# Exits non-zero on any mismatch.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

ARTIFACTS=(
  "easyenclave.vmlinuz"
  "easyenclave.initrd"
  "easyenclave.root.raw"
  "easyenclave.cmdline"
)

TMP_DIR="$(mktemp -d /tmp/easyenclave-repro-XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "==> Reproducibility gate: build #1 and build #2"
echo "Temporary comparison dir: $TMP_DIR"

# mkosi requires this setting in CI.
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >/dev/null

build_once() {
  local label="$1"
  local out_dir="$TMP_DIR/$label"
  mkdir -p "$out_dir"

  echo "---- [$label] clean build ----"
  (cd infra/image && nix develop --command make clean && nix develop --command make build)

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
if ! diff -u "$TMP_DIR/build1/sha256.txt" "$TMP_DIR/build2/sha256.txt"; then
  echo "::error::Reproducibility check failed: artifact digests differ"
  exit 1
fi

echo "==> Comparing measured values (tiny profile)..."
if ! diff -u "$TMP_DIR/build1/measure.json" "$TMP_DIR/build2/measure.json"; then
  echo "::error::Reproducibility check failed: measured values differ"
  exit 1
fi

echo "==> Reproducibility gate passed"
