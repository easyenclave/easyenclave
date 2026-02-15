#!/usr/bin/env python3
"""Provision an ephemeral GCP GPU VM and run an LLM coding smoke test.

This is intentionally NOT integrated with EasyEnclave attestation yet.
It is a manual, triggerable workflow helper to validate we can reliably:
  - boot a GPU machine type
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

        # Basic packages. DLVM images normally have python3 and GPU drivers already.
        export DEBIAN_FRONTEND=noninteractive
        if command -v apt-get >/dev/null 2>&1; then
          apt-get update -y || true
          apt-get install -y jq curl ca-certificates python3 python3-venv gnupg || true
        fi

        if ! command -v nvidia-smi >/dev/null 2>&1; then
          fail "nvidia-smi not found (GPU driver missing). Use a Deep Learning VM image family."
        fi
        log "nvidia-smi OK"
        nvidia-smi | head -n 20 | tee /dev/ttyS0 || true

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
        # DLVM usually includes it; check quickly.
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
          fail "coding prompt validation failed rc=${rc}"
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
    machine_type: str
    accelerator_type: str
    accelerator_count: int


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
        "--zone",
        attempt.zone,
        "--machine-type",
        attempt.machine_type,
        "--boot-disk-size",
        boot_disk_size,
        "--boot-disk-type",
        "pd-ssd",
        "--maintenance-policy",
        "TERMINATE",
        "--restart-on-failure",
        "--image-project",
        image_project,
        "--image-family",
        image_family,
        "--metadata",
        "serial-port-enable=1",
        "--metadata-from-file",
        f"startup-script={startup_script_path}",
        "--accelerator",
        f"type={attempt.accelerator_type},count={attempt.accelerator_count}",
        # Keep public IP for package/model download simplicity.
        "--tags",
        "easyenclave-gpu-smoke",
        "--scopes",
        "https://www.googleapis.com/auth/cloud-platform",
    ]
    _run(cmd, capture=True, check=True)


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
        help="Comma-separated zones to try (e.g. us-central1-a,us-central1-b)",
    )
    ap.add_argument(
        "--machine-types",
        required=True,
        help="Comma-separated machine types to try (e.g. g2-standard-12,a2-highgpu-1g)",
    )
    ap.add_argument("--accelerator-type", required=True, help="e.g. nvidia-l4, nvidia-tesla-a100")
    ap.add_argument("--accelerator-count", type=int, default=1)
    ap.add_argument("--boot-disk-size", default="200GB")
    ap.add_argument("--image-project", default="deeplearning-platform-release")
    ap.add_argument("--image-family", default="common-cu121")
    ap.add_argument("--model", default="Qwen/Qwen2.5-Coder-7B-Instruct")
    ap.add_argument("--max-tokens", type=int, default=256)
    ap.add_argument("--timeout-seconds", type=int, default=3600)
    ap.add_argument("--cleanup", action="store_true", default=False)
    ap.add_argument("--name-prefix", default="ee-gpu")
    ap.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", "local"))
    args = ap.parse_args()

    zones = _split_csv(args.zones)
    machine_types = _split_csv(args.machine_types)
    if not zones or not machine_types:
        print("zones and machine-types must be non-empty", file=sys.stderr)
        return 2

    name = f"{args.name_prefix}-{args.run_id}-{_rand_suffix()}"
    startup_script = _build_startup_script(model=args.model, max_tokens=args.max_tokens)
    startup_script_path = f"/tmp/{name}-startup.sh"
    with open(startup_script_path, "w", encoding="utf-8") as f:
        f.write(startup_script)
    os.chmod(startup_script_path, 0o755)

    attempts: list[Attempt] = []
    for z in zones:
        for mt in machine_types:
            attempts.append(
                Attempt(
                    zone=z,
                    machine_type=mt,
                    accelerator_type=args.accelerator_type,
                    accelerator_count=args.accelerator_count,
                )
            )

    created_zone: str | None = None
    last_err: str | None = None
    try:
        for idx, attempt in enumerate(attempts, start=1):
            print(
                f"[attempt {idx}/{len(attempts)}] creating {name} "
                f"zone={attempt.zone} machine_type={attempt.machine_type} "
                f"accel={attempt.accelerator_type}x{attempt.accelerator_count}",
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
