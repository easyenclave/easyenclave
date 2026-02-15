#!/usr/bin/env python3
"""Provision an ephemeral GCP *confidential* GPU VM and run an LLM coding smoke test.

This is intentionally NOT integrated with EasyEnclave attestation yet.
It is a manual, triggerable workflow helper to validate we can reliably:
  - boot a confidential GPU machine type (Intel TDX + NVIDIA Confidential Computing)
  - run an OpenAI-compatible model server (vLLM)
  - execute a simple coding prompt and validate output
  - clean up all resources

The VM runs the test in a startup-script and prints a PASS/FAIL marker to the
serial console. The GitHub Actions runner only polls serial output; no SSH or
firewall ingress needed.
"""

from __future__ import annotations

import argparse
import os
import random
import string
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass

PASS_MARKER = "EASYENCLAVE_GPU_TEST_RESULT=PASS"
FAIL_MARKER = "EASYENCLAVE_GPU_TEST_RESULT=FAIL"


def _now() -> float:
    return time.monotonic()


def _rand_suffix(n: int = 6) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _split_csv(raw: str) -> list[str]:
    return [x.strip() for x in (raw or "").split(",") if x.strip()]


def _run(
    cmd: list[str], *, capture: bool = True, check: bool = True
) -> subprocess.CompletedProcess:
    kwargs = {"text": True}
    if capture:
        kwargs["capture_output"] = True
    else:
        kwargs["stdout"] = None
        kwargs["stderr"] = None
    p = subprocess.run(cmd, **kwargs)
    if check and p.returncode != 0:
        raise RuntimeError(
            f"Command failed (rc={p.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{p.stdout}\n"
            f"stderr:\n{p.stderr}\n"
        )
    return p


def _gcloud_base_args(project: str) -> list[str]:
    return ["gcloud", "--quiet", "--project", project]


def _build_startup_script(*, model: str, max_tokens: int) -> str:
    # Note: we keep output very explicit and tee to /dev/ttyS0 to ensure it shows
    # up in get-serial-port-output.
    # Important: this is an f-string. Any literal `{` / `}` in bash snippets must
    # be doubled (`{{` / `}}`) to avoid Python formatting errors.
    return textwrap.dedent(
        f"""\
        #!/usr/bin/env bash
        set -euo pipefail

        log() {{
          echo "[$(date -Is)] $*" | tee /dev/ttyS0
        }}

        fail() {{
          log "{FAIL_MARKER} $*"
          exit 1
        }}

        log "startup: begin"
        log "model: {model}"

        STAGE_DIR="/var/lib/easyenclave"
        STAGE_FILE="${{STAGE_DIR}}/gpu_smoke_stage"
        mkdir -p "${{STAGE_DIR}}"

        # Basic packages.
        export DEBIAN_FRONTEND=noninteractive
        if command -v apt-get >/dev/null 2>&1; then
          apt-get update -y || true
          apt-get install -y jq curl ca-certificates python3 python3-venv gnupg build-essential pkg-config linux-headers-$(uname -r) || true
        fi

        # Stage 1: install drivers + configure confidential GPU mode, then reboot.
        if [ ! -f "${{STAGE_FILE}}" ]; then
          log "stage1: installing NVIDIA driver and configuring confidential GPU mode"
          if ! command -v apt-get >/dev/null 2>&1; then
            fail "apt-get not available; unsupported OS image"
          fi

          apt-get install -y ubuntu-drivers-common || true
          if apt-cache show nvidia-driver-575-open >/dev/null 2>&1; then
            log "installing nvidia-driver-575-open"
            apt-get install -y nvidia-driver-575-open || fail "failed to install nvidia-driver-575-open"
          else
            pkg="$(apt-cache search '^nvidia-driver-[0-9]+-open$' | awk '{{print $1}}' | sort -V | tail -n 1)"
            if [ -z "${{pkg:-}}" ]; then
              fail "no nvidia-driver-*-open package found (need open driver; recommended nvidia-driver-575-open)"
            fi
            log "installing ${{pkg}}"
            apt-get install -y "$pkg" || fail "failed to install $pkg"
          fi

          # Docker (needed for vLLM)
          apt-get install -y docker.io || true
          systemctl enable --now docker || true

          # NVIDIA container toolkit (required for --gpus all)
          log "installing nvidia-container-toolkit (best-effort)"
          curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg || true
          curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
            | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
            | tee /etc/apt/sources.list.d/nvidia-container-toolkit.list >/dev/null || true
          apt-get update -y || true
          apt-get install -y nvidia-container-toolkit || true
          nvidia-ctk runtime configure --runtime=docker || true
          systemctl restart docker || true

          # LKCA config for secure GPU-driver SPDM link (GCP Confidential GPU guide).
          echo "install nvidia /sbin/modprobe ecdsa_generic; /sbin/modprobe ecdh; /sbin/modprobe --ignore-install nvidia" | tee /etc/modprobe.d/nvidia-lkca.conf >/dev/null || true
          update-initramfs -u || true

          # Ensure nvidia-persistenced runs with uvm-persistence-mode.
          if [ -f /usr/lib/systemd/system/nvidia-persistenced.service ]; then
            sed -i "s/no-persistence-mode/uvm-persistence-mode/g" /usr/lib/systemd/system/nvidia-persistenced.service || true
            systemctl daemon-reload || true
          fi

          echo "2" > "${{STAGE_FILE}}"
          log "stage1: rebooting to apply driver + LKCA + persistence config"
          reboot
          exit 0
        fi

        log "stage2: verifying GPU confidential mode"
        if ! command -v nvidia-smi >/dev/null 2>&1; then
          fail "nvidia-smi not found after reboot (driver install failed?)"
        fi
        nvidia-smi | head -n 40 | tee /dev/ttyS0 || true

        # Verify persistence mode has uvm flag enabled.
        if ! ps aux | grep nvidia-persistenced | grep -v grep | grep -q -- --uvm-persistence-mode; then
          fail "nvidia-persistenced not running with --uvm-persistence-mode"
        fi

        # Verify confidential computing mode.
        if ! nvidia-smi conf-compute -f 2>/dev/null | tee /dev/ttyS0 | grep -qi 'CC status: *ON'; then
          fail "GPU CC mode not ON (nvidia-smi conf-compute -f)"
        fi

        # Ensure GPU ready state after reboot.
        nvidia-smi conf-compute -srs 1 | tee /dev/ttyS0 || true
        if ! nvidia-smi conf-compute -grs 2>/dev/null | tee /dev/ttyS0 | grep -qi 'ready'; then
          fail "GPU CC ready state not ready (nvidia-smi conf-compute -grs)"
        fi

        # Docker
        if ! command -v docker >/dev/null 2>&1; then
          if command -v apt-get >/dev/null 2>&1; then
            apt-get install -y docker.io || true
          fi
        fi
        if ! command -v docker >/dev/null 2>&1; then
          fail "docker not installed"
        fi
        systemctl enable --now docker || true

        # NVIDIA container runtime is required for --gpus all.
        if ! docker info 2>/dev/null | grep -qi 'Runtimes:.*nvidia'; then
          log "nvidia runtime not detected; attempting to install nvidia-container-toolkit"
          if command -v apt-get >/dev/null 2>&1; then
            # Official repo install; best-effort (some images already have it)
            curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg || true
            curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
              | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
              | tee /etc/apt/sources.list.d/nvidia-container-toolkit.list >/dev/null || true
            apt-get update -y || true
            apt-get install -y nvidia-container-toolkit || true
            nvidia-ctk runtime configure --runtime=docker || true
            systemctl restart docker || true
          fi
        fi

        log "pulling vllm image..."
        docker pull vllm/vllm-openai:latest | tee /dev/ttyS0

        log "starting vllm server..."
        # Run in background; vLLM will download the model from HuggingFace on first start.
        docker run -d --name vllm \
          --gpus all \
          --ipc=host \
          -p 8000:8000 \
          vllm/vllm-openai:latest \
          --model "{model}" \
          --dtype auto \
          --max-model-len 4096 \
          --served-model-name "{model}" \
          --gpu-memory-utilization 0.90 \
          --disable-log-stats || fail "failed to start vllm container"

        # Wait for readiness
        log "waiting for /health..."
        for i in $(seq 1 240); do
          if curl -sf http://127.0.0.1:8000/health >/dev/null 2>&1; then
            log "vllm /health OK"
            break
          fi
          if [ "$i" -eq 240 ]; then
            docker logs --tail 200 vllm | tee /dev/ttyS0 || true
            fail "vllm not healthy in time"
          fi
          sleep 5
        done

        log "running coding prompt..."
        if ! python3 - <<'PY'; then
          rc="$?"
          docker logs --tail 200 vllm | tee /dev/ttyS0 || true
          fail "coding prompt validation failed rc=$rc"
        fi
        import json, sys, urllib.request

        url = "http://127.0.0.1:8000/v1/chat/completions"
        body = {{
          "model": "{model}",
          "messages": [
            {{"role": "system", "content": "You are a concise coding assistant. Output only code."}},
            {{"role": "user", "content": "Write a Python function solve() that reads two integers and prints their sum."}}
          ],
          "max_tokens": {max_tokens},
          "temperature": 0.0
        }}

        req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={{"Content-Type": "application/json"}})
        with urllib.request.urlopen(req, timeout=120) as resp:
          data = json.loads(resp.read().decode())
        content = data["choices"][0]["message"]["content"]
        print("MODEL_OUTPUT_START")
        print(content)
        print("MODEL_OUTPUT_END")
        # super light validation: contains a solve() and "print("
        ok = ("def solve" in content) and ("print" in content)
        sys.exit(0 if ok else 2)
        PY

        log "{PASS_MARKER}"
        log "startup: done"
        """
    )


@dataclass
class Attempt:
    zone: str


def _create_instance(
    *,
    project: str,
    name: str,
    attempt: Attempt,
    boot_disk_size: str,
    image_project: str,
    image_family: str,
    startup_script_path: str,
) -> None:
    cmd = [
        *_gcloud_base_args(project),
        "compute",
        "instances",
        "create",
        name,
        "--provisioning-model=SPOT",
        "--confidential-compute-type=TDX",
        "--machine-type=a3-highgpu-1g",
        "--maintenance-policy=TERMINATE",
        "--zone",
        attempt.zone,
        "--boot-disk-size",
        boot_disk_size,
        "--boot-disk-type",
        "pd-ssd",
        "--image-project",
        image_project,
        "--image-family",
        image_family,
        "--metadata",
        "serial-port-enable=1",
        "--metadata-from-file",
        f"startup-script={startup_script_path}",
        # Keep public IP for package/model download simplicity.
        "--tags",
        "easyenclave-gpu-smoke",
        "--scopes",
        "https://www.googleapis.com/auth/cloud-platform",
    ]
    _run(cmd, capture=True, check=True)

def _require_tdx(*, project: str, name: str, zone: str) -> None:
    # Avoid “looks like it worked” situations: assert the instance is actually TDX.
    cmd = [
        *_gcloud_base_args(project),
        "compute",
        "instances",
        "describe",
        name,
        "--zone",
        zone,
        "--format=value(confidentialInstanceConfig.confidentialInstanceType)",
    ]
    p = _run(cmd, capture=True, check=True)
    v = (p.stdout or "").strip()
    if v != "TDX":
        raise RuntimeError(f"Instance is not TDX (confidentialInstanceType={v!r})")


def _delete_instance(*, project: str, name: str, zone: str) -> None:
    cmd = [
        *_gcloud_base_args(project),
        "compute",
        "instances",
        "delete",
        name,
        "--zone",
        zone,
        "--delete-disks",
        "all",
    ]
    _run(cmd, capture=True, check=False)


def _get_serial(*, project: str, name: str, zone: str, start: int) -> str:
    cmd = [
        *_gcloud_base_args(project),
        "compute",
        "instances",
        "get-serial-port-output",
        name,
        "--zone",
        zone,
        "--port",
        "1",
        "--start",
        str(start),
    ]
    p = _run(cmd, capture=True, check=False)
    return p.stdout or ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument(
        "--zones",
        required=True,
        help="Comma-separated zones to try (only a3-highgpu-1g supported for confidential GPU)",
    )
    ap.add_argument("--boot-disk-size", default="200GB")
    ap.add_argument("--image-project", default="ubuntu-os-cloud")
    ap.add_argument("--image-family", default="ubuntu-2404-lts")
    ap.add_argument("--model", default="Qwen/Qwen2.5-Coder-7B-Instruct")
    ap.add_argument("--max-tokens", type=int, default=256)
    ap.add_argument("--timeout-seconds", type=int, default=3600)
    ap.add_argument("--cleanup", action="store_true", default=False)
    ap.add_argument("--name-prefix", default="ee-gpu")
    ap.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", "local"))
    args = ap.parse_args()

    zones = _split_csv(args.zones)
    if not zones:
        print("zones must be non-empty", file=sys.stderr)
        return 2

    name = f"{args.name_prefix}-{args.run_id}-{_rand_suffix()}"
    startup_script = _build_startup_script(model=args.model, max_tokens=args.max_tokens)
    startup_script_path = f"/tmp/{name}-startup.sh"
    with open(startup_script_path, "w", encoding="utf-8") as f:
        f.write(startup_script)
    os.chmod(startup_script_path, 0o755)

    attempts: list[Attempt] = [Attempt(zone=z) for z in zones]

    created_zone: str | None = None
    last_err: str | None = None
    try:
        for idx, attempt in enumerate(attempts, start=1):
            print(
                f"[attempt {idx}/{len(attempts)}] creating {name} "
                f"zone={attempt.zone} machine_type=a3-highgpu-1g confidential=TDX provisioning=SPOT",
                file=sys.stderr,
            )
            try:
                _create_instance(
                    project=args.project,
                    name=name,
                    attempt=attempt,
                    boot_disk_size=args.boot_disk_size,
                    image_project=args.image_project,
                    image_family=args.image_family,
                    startup_script_path=startup_script_path,
                )
                _require_tdx(project=args.project, name=name, zone=attempt.zone)
                created_zone = attempt.zone
                break
            except Exception as e:  # noqa: BLE001 - surface the failure text
                last_err = str(e)
                print(f"  create failed: {e}", file=sys.stderr)
                continue

        if not created_zone:
            print("Failed to create GPU instance in all zones/machine types.", file=sys.stderr)
            if last_err:
                print(last_err, file=sys.stderr)
            return 1

        # Poll serial console for PASS/FAIL.
        deadline = _now() + args.timeout_seconds
        start = 0
        last_output = ""
        while _now() < deadline:
            out = _get_serial(project=args.project, name=name, zone=created_zone, start=start)
            if out:
                last_output = out
                # gcloud doesn't return the next "start" cursor; approximate by line count.
                start += max(0, len(out.splitlines()) - 1)
                if PASS_MARKER in out:
                    print(PASS_MARKER)
                    return 0
                if FAIL_MARKER in out:
                    print(FAIL_MARKER, file=sys.stderr)
                    print(out[-4000:], file=sys.stderr)
                    return 1
            time.sleep(10)

        print("Timed out waiting for PASS/FAIL marker.", file=sys.stderr)
        if last_output:
            print(last_output[-8000:], file=sys.stderr)
        return 1
    finally:
        if created_zone and args.cleanup:
            print(f"Cleaning up instance {name} (zone={created_zone})", file=sys.stderr)
            _delete_instance(project=args.project, name=name, zone=created_zone)


if __name__ == "__main__":
    raise SystemExit(main())
