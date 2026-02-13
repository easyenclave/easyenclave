#!/usr/bin/env bash
# Reproducibility gate for EasyEnclave verity image builds.
#
# Runs two builds back-to-back and verifies:
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
REPORT_DIR="${REPRO_REPORT_DIR:-infra/output/reproducibility}"

ARTIFACT_MATCH="unknown"
MEASUREMENT_MATCH="unknown"
FAIL_REASON=""
LAST_FAILED_COMMAND=""

cleanup_stale_verity_domains() {
  if ! command -v virsh >/dev/null 2>&1; then
    return 0
  fi

  local domains=()
  mapfile -t domains < <(virsh list --all --name | grep '^tdvirsh-trust_domain_verity-' || true)
  for domain in "${domains[@]}"; do
    [ -n "$domain" ] || continue
    virsh destroy "$domain" >/dev/null 2>&1 || true
    virsh undefine "$domain" --nvram >/dev/null 2>&1 || virsh undefine "$domain" >/dev/null 2>&1 || true
  done
}

emit_report() {
  local exit_code="$1"

  mkdir -p "$REPORT_DIR"

  for label in build1 build2; do
    if [ -f "$TMP_DIR/$label/sha256.txt" ]; then
      cp "$TMP_DIR/$label/sha256.txt" "$REPORT_DIR/$label.sha256.txt"
    fi
    if [ -f "$TMP_DIR/$label/sizes.tsv" ]; then
      cp "$TMP_DIR/$label/sizes.tsv" "$REPORT_DIR/$label.sizes.tsv"
    fi
    if [ -f "$TMP_DIR/$label/measure.json" ]; then
      cp "$TMP_DIR/$label/measure.json" "$REPORT_DIR/$label.measure.json"
    fi
    if [ -f "$TMP_DIR/$label/timing.json" ]; then
      cp "$TMP_DIR/$label/timing.json" "$REPORT_DIR/$label.timing.json"
    fi
  done

  if [ -f "$TMP_DIR/artifact.diff" ]; then
    cp "$TMP_DIR/artifact.diff" "$REPORT_DIR/artifact.diff"
  fi
  if [ -f "$TMP_DIR/measurement.diff" ]; then
    cp "$TMP_DIR/measurement.diff" "$REPORT_DIR/measurement.diff"
  fi

  python3 - "$TMP_DIR" "$REPORT_DIR/report.json" "$REPORT_DIR/summary.md" "$exit_code" "$FAIL_REASON" "$LAST_FAILED_COMMAND" "$ARTIFACT_MATCH" "$MEASUREMENT_MATCH" <<'PY'
import json
import os
import sys
from pathlib import Path


def load_sha_file(path: Path) -> dict:
    values = {}
    if not path.exists():
        return values
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        values[parts[-1]] = parts[0]
    return values


def load_sizes_file(path: Path) -> dict:
    values = {}
    if not path.exists():
        return values
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        name, size = parts
        try:
            values[name] = int(size)
        except ValueError:
            continue
    return values


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}


def load_text(path: Path, limit: int = 4000) -> str:
    if not path.exists():
        return ""
    text = path.read_text()
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... (truncated)"


def fmt_size(value):
    if value is None:
        return "-"
    return str(value)


(
    tmp_dir,
    report_json_path,
    report_md_path,
    exit_code,
    fail_reason,
    last_failed_command,
    artifact_match_arg,
    measurement_match_arg,
) = sys.argv[1:9]

tmp_dir = Path(tmp_dir)
report_json_path = Path(report_json_path)
report_md_path = Path(report_md_path)

exit_code = int(exit_code)

build1_sha = load_sha_file(tmp_dir / "build1" / "sha256.txt")
build2_sha = load_sha_file(tmp_dir / "build2" / "sha256.txt")
build1_sizes = load_sizes_file(tmp_dir / "build1" / "sizes.tsv")
build2_sizes = load_sizes_file(tmp_dir / "build2" / "sizes.tsv")
build1_measure = load_json(tmp_dir / "build1" / "measure.json")
build2_measure = load_json(tmp_dir / "build2" / "measure.json")
build1_timing = load_json(tmp_dir / "build1" / "timing.json")
build2_timing = load_json(tmp_dir / "build2" / "timing.json")

artifact_names = sorted(set(build1_sha.keys()) | set(build2_sha.keys()))
artifact_rows = []
for name in artifact_names:
    b1 = build1_sha.get(name)
    b2 = build2_sha.get(name)
    row = {
        "artifact": name,
        "build1_sha256": b1,
        "build2_sha256": b2,
        "build1_size_bytes": build1_sizes.get(name),
        "build2_size_bytes": build2_sizes.get(name),
        "match": bool(b1 and b2 and b1 == b2),
    }
    artifact_rows.append(row)

measure_keys = ["mrtd", "rtmr0", "rtmr1", "rtmr2"]
measurement_rows = []
for key in measure_keys:
    b1 = build1_measure.get(key)
    b2 = build2_measure.get(key)
    measurement_rows.append(
        {
            "field": key,
            "build1": b1,
            "build2": b2,
            "match": bool(b1 and b2 and b1 == b2),
        }
    )

artifact_diff = load_text(tmp_dir / "artifact.diff")
measurement_diff = load_text(tmp_dir / "measurement.diff")

if artifact_match_arg in {"true", "false"}:
    artifact_match = artifact_match_arg == "true"
else:
    artifact_match = bool(artifact_rows) and all(r["match"] for r in artifact_rows)

if measurement_match_arg in {"true", "false"}:
    measurement_match = measurement_match_arg == "true"
else:
    measurement_match = bool(measurement_rows) and all(r["match"] for r in measurement_rows)

status = "passed" if exit_code == 0 else "failed"
if status == "passed":
    failure_detail = ""
elif fail_reason:
    failure_detail = fail_reason
elif last_failed_command:
    failure_detail = f"command_failed:{last_failed_command}"
else:
    failure_detail = "unknown_failure"

report = {
    "status": status,
    "exit_code": exit_code,
    "failure_reason": failure_detail,
    "artifact_match": artifact_match,
    "measurement_match": measurement_match,
    "artifacts": artifact_rows,
    "measurements": measurement_rows,
    "build_timings": {
        "build1": build1_timing,
        "build2": build2_timing,
    },
    "artifact_diff": artifact_diff,
    "measurement_diff": measurement_diff,
}

report_json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

summary_lines = []
summary_lines.append("## Determinism Report")
summary_lines.append("")
summary_lines.append(f"- Status: **{status.upper()}**")
summary_lines.append(f"- Artifact digest match: **{artifact_match}**")
summary_lines.append(f"- Measurement match (`mrtd`, `rtmr0`, `rtmr1`, `rtmr2`): **{measurement_match}**")
if failure_detail:
    summary_lines.append(f"- Failure reason: `{failure_detail}`")

b1_duration = build1_timing.get("duration_seconds")
b2_duration = build2_timing.get("duration_seconds")
if b1_duration is not None or b2_duration is not None:
    summary_lines.append(f"- Build durations (seconds): build1={b1_duration if b1_duration is not None else '-'}, build2={b2_duration if b2_duration is not None else '-'}")

summary_lines.append("")
summary_lines.append("### Artifact SHA256 Comparison")
summary_lines.append("")
summary_lines.append("| Artifact | Build #1 SHA256 | Build #2 SHA256 | Match | Size #1 (bytes) | Size #2 (bytes) |")
summary_lines.append("|---|---|---|---|---:|---:|")
for row in artifact_rows:
    b1 = row["build1_sha256"] or "-"
    b2 = row["build2_sha256"] or "-"
    summary_lines.append(
        f"| `{row['artifact']}` | `{b1}` | `{b2}` | {'yes' if row['match'] else 'no'} | {fmt_size(row['build1_size_bytes'])} | {fmt_size(row['build2_size_bytes'])} |"
    )
if not artifact_rows:
    summary_lines.append("| _none_ | - | - | - | - | - |")

summary_lines.append("")
summary_lines.append("### Measurement Comparison")
summary_lines.append("")
summary_lines.append("| Field | Build #1 | Build #2 | Match |")
summary_lines.append("|---|---|---|---|")
for row in measurement_rows:
    b1 = row["build1"] or "-"
    b2 = row["build2"] or "-"
    summary_lines.append(
        f"| `{row['field']}` | `{b1}` | `{b2}` | {'yes' if row['match'] else 'no'} |"
    )

if artifact_diff:
    summary_lines.append("")
    summary_lines.append("### Artifact Diff")
    summary_lines.append("")
    summary_lines.append("```diff")
    summary_lines.append(artifact_diff.rstrip("\n"))
    summary_lines.append("```")

if measurement_diff:
    summary_lines.append("")
    summary_lines.append("### Measurement Diff")
    summary_lines.append("")
    summary_lines.append("```diff")
    summary_lines.append(measurement_diff.rstrip("\n"))
    summary_lines.append("```")

report_md_path.write_text("\n".join(summary_lines) + "\n")
PY

  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "report_json=$REPORT_DIR/report.json" >> "$GITHUB_OUTPUT"
    echo "report_summary=$REPORT_DIR/summary.md" >> "$GITHUB_OUTPUT"
  fi
}

cleanup() {
  local exit_code=$?
  trap - EXIT
  emit_report "$exit_code" || true
  cleanup_stale_verity_domains
  rm -rf "$TMP_DIR"
  exit "$exit_code"
}
trap cleanup EXIT

trap 'LAST_FAILED_COMMAND=$BASH_COMMAND' ERR

echo "==> Reproducibility gate: build #1 and build #2"
echo "Mode: strict (always full clean)"
echo "Temporary comparison dir: $TMP_DIR"

echo "==> Report output: $REPORT_DIR"
rm -rf "$REPORT_DIR"
mkdir -p "$REPORT_DIR"

# mkosi requires this setting in CI.
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >/dev/null
cleanup_stale_verity_domains

build_image() {
  local label="$1"
  echo "[$label] full clean build"
  (cd infra/image && nix develop --command bash -lc 'make clean && make build')
}

build_once() {
  local label="$1"
  local out_dir="$TMP_DIR/$label"
  mkdir -p "$out_dir"

  local start_epoch
  local end_epoch
  local start_iso
  local end_iso
  start_epoch="$(date -u +%s)"
  start_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  echo "---- [$label] build ----"
  build_image "$label"

  end_epoch="$(date -u +%s)"
  end_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  jq -n \
    --arg label "$label" \
    --arg started_utc "$start_iso" \
    --arg ended_utc "$end_iso" \
    --argjson duration_seconds "$((end_epoch - start_epoch))" \
    '{label: $label, started_utc: $started_utc, ended_utc: $ended_utc, duration_seconds: $duration_seconds}' \
    > "$out_dir/timing.json"

  : > "$out_dir/sha256.txt"
  : > "$out_dir/sizes.tsv"

  for name in "${ARTIFACTS[@]}"; do
    local src="infra/image/output/$name"
    if [ ! -f "$src" ]; then
      FAIL_REASON="missing_artifact:${label}:${name}"
      echo "::error::Missing artifact after build ($label): $src"
      exit 1
    fi

    local sha
    local size_bytes
    sha="$(sha256sum "$src" | awk '{print $1}')"
    size_bytes="$(stat -c '%s' "$src")"
    printf '%s  %s\n' "$sha" "$name" >> "$out_dir/sha256.txt"
    printf '%s\t%s\n' "$name" "$size_bytes" >> "$out_dir/sizes.tsv"
  done

  echo "[$label] artifact digests:"
  cat "$out_dir/sha256.txt"

  echo "[$label] measuring tiny profile..."
  local measures
  measures="$(python3 infra/tdx_cli.py vm measure --verity --json --timeout 180 --size tiny)"
  echo "$measures" | jq -c '{mrtd, rtmr0, rtmr1, rtmr2}' > "$out_dir/measure.json"
  echo "[$label] measurements:"
  cat "$out_dir/measure.json"
}

build_once "build1"
build_once "build2"

echo "==> Comparing artifact digests..."
if diff -u "$TMP_DIR/build1/sha256.txt" "$TMP_DIR/build2/sha256.txt" > "$TMP_DIR/artifact.diff"; then
  ARTIFACT_MATCH="true"
else
  ARTIFACT_MATCH="false"
  FAIL_REASON="${FAIL_REASON:-artifact_digest_mismatch}"
  echo "::error::Reproducibility check failed: artifact digests differ"
fi

echo "==> Comparing measured values (tiny profile: mrtd + rtmr0 + rtmr1 + rtmr2)..."
if diff -u "$TMP_DIR/build1/measure.json" "$TMP_DIR/build2/measure.json" > "$TMP_DIR/measurement.diff"; then
  MEASUREMENT_MATCH="true"
else
  MEASUREMENT_MATCH="false"
  FAIL_REASON="${FAIL_REASON:-measurement_mismatch}"
  echo "::error::Reproducibility check failed: measured values differ"
fi

if [ "$ARTIFACT_MATCH" != "true" ] || [ "$MEASUREMENT_MATCH" != "true" ]; then
  exit 1
fi

echo "==> Reproducibility gate passed"
