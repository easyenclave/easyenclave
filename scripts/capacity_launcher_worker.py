#!/usr/bin/env python3
"""Capacity launcher worker for CP-issued launch orders.

This worker consumes queued launch orders from the control plane using a
launcher API key, provisions capacity, and reports fulfillment status.

Supported providers:
- baremetal: launches local TDX VMs via infra/tdx_cli.py
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


def _split_csv(value: str) -> list[str]:
    return [item.strip().lower() for item in (value or "").split(",") if item.strip()]


def _truncate(value: str, limit: int = 4000) -> str:
    compact = " ".join((value or "").split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def _tail(value: str, limit: int = 12000) -> str:
    """Return the last `limit` characters without whitespace compaction.

    GitHub Actions log rendering can truncate very long single-line messages;
    preserving newlines keeps actionable command errors visible.
    """
    raw = value or ""
    if len(raw) <= limit:
        return raw
    return raw[-limit:]


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, check=False)


def _parse_json_output(raw: str) -> Any:
    text = (raw or "").strip()
    if not text:
        return None
    return json.loads(text)


@dataclass
class WorkerConfig:
    cp_url: str
    launcher_api_key: str
    intel_api_key: str
    poll_seconds: int
    claim_datacenter: str
    claim_node_size: str
    supported_providers: set[str]
    one_shot: bool
    max_orders: int


class ControlPlaneClient:
    def __init__(self, cp_url: str, launcher_api_key: str):
        self.cp_url = cp_url.rstrip("/")
        self.launcher_api_key = launcher_api_key

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        url = f"{self.cp_url}{path}"
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.launcher_api_key}",
            "User-Agent": "easyenclave-capacity-launcher/1.0",
        }
        data: bytes | None = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", errors="replace")
            except Exception:
                detail = ""
            msg = _truncate(detail or f"HTTP {exc.code}")
            raise RuntimeError(
                f"Control plane request failed: {method} {path} -> {exc.code}: {msg}"
            ) from exc
        except Exception as exc:
            raise RuntimeError(f"Control plane request failed: {method} {path}: {exc}") from exc

        if not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except Exception as exc:
            raise RuntimeError(f"Control plane returned non-JSON for {method} {path}: {exc}") from exc

    def claim_order(self, *, datacenter: str, node_size: str) -> dict[str, Any]:
        payload = {"datacenter": datacenter, "node_size": node_size}
        data = self._request("POST", "/api/v1/launchers/capacity/orders/claim", payload)
        if not isinstance(data, dict):
            raise RuntimeError("Invalid claim response payload")
        return data

    def update_order(
        self,
        order_id: str,
        *,
        status: str,
        vm_name: str | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"status": status}
        if vm_name is not None:
            payload["vm_name"] = vm_name
        if error is not None:
            payload["error"] = error
        data = self._request("POST", f"/api/v1/launchers/capacity/orders/{order_id}", payload)
        if not isinstance(data, dict):
            raise RuntimeError("Invalid update response payload")
        return data


def _parse_datacenter(datacenter: str) -> tuple[str, str]:
    normalized = (datacenter or "").strip().lower()
    if not normalized or ":" not in normalized:
        raise RuntimeError(f"Invalid datacenter '{datacenter}'")
    provider, location = normalized.split(":", 1)
    if not provider or not location:
        raise RuntimeError(f"Invalid datacenter '{datacenter}'")
    return provider, location


def _launch_baremetal(config: WorkerConfig, *, order: dict[str, Any], location: str) -> str:
    node_size = str(order.get("node_size") or "").strip().lower()
    if not node_size:
        raise RuntimeError("Order missing node_size")

    cmd = [
        "python3",
        "infra/tdx_cli.py",
        "vm",
        "new",
        "--size",
        node_size,
        "--cloud-provider",
        "baremetal",
        "--availability-zone",
        location,
        "--easyenclave-url",
        config.cp_url,
        "--intel-api-key",
        config.intel_api_key,
        "--wait",
    ]
    result = _run(cmd)
    if result.returncode != 0:
        stderr = _truncate(result.stderr or "")
        stdout = _truncate(result.stdout or "")
        detail = stderr or stdout or f"exit={result.returncode}"
        raise RuntimeError(f"baremetal launch failed: {detail}")

    payload = _parse_json_output(result.stdout or "")
    if not isinstance(payload, dict):
        raise RuntimeError("baremetal launch returned invalid JSON output")
    vm_name = str(payload.get("name") or "").strip()
    if not vm_name:
        raise RuntimeError("baremetal launch did not return vm name")
    return vm_name


def _launch_for_order(config: WorkerConfig, order: dict[str, Any]) -> str:
    datacenter = str(order.get("datacenter") or "").strip().lower()
    provider, location = _parse_datacenter(datacenter)

    if provider not in config.supported_providers:
        raise RuntimeError(f"Provider '{provider}' is not enabled on this launcher")

    if provider == "baremetal":
        return _launch_baremetal(config, order=order, location=location)
    if provider == "gcp":
        raise RuntimeError(
            "GCP launch orders must be fulfilled by the control plane native fulfiller"
        )
    raise RuntimeError(f"Unsupported provider '{provider}'")


def _load_config(args: argparse.Namespace) -> WorkerConfig:
    cp_url = (args.cp_url or "").strip()
    launcher_api_key = (args.launcher_api_key or "").strip()
    intel_api_key = (args.intel_api_key or "").strip()
    claim_datacenter = (args.datacenter or "").strip().lower()
    claim_node_size = (args.node_size or "").strip().lower()
    providers = set(_split_csv(args.providers))
    if not providers:
        providers = {"baremetal"}

    if not cp_url:
        raise RuntimeError("--cp-url is required")
    if not launcher_api_key:
        raise RuntimeError("--launcher-api-key is required")
    if not intel_api_key:
        raise RuntimeError("--intel-api-key is required")

    return WorkerConfig(
        cp_url=cp_url,
        launcher_api_key=launcher_api_key,
        intel_api_key=intel_api_key,
        poll_seconds=max(2, int(args.poll_seconds)),
        claim_datacenter=claim_datacenter,
        claim_node_size=claim_node_size,
        supported_providers=providers,
        one_shot=bool(args.one_shot),
        max_orders=max(0, int(args.max_orders)),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run EasyEnclave capacity launcher worker")
    parser.add_argument(
        "--cp-url",
        default=os.environ.get("CP_URL", "https://app.easyenclave.com"),
        help="Control plane URL",
    )
    parser.add_argument(
        "--launcher-api-key",
        default=os.environ.get("LAUNCHER_API_KEY", ""),
        help="Launcher account API key (ee_live_...)",
    )
    parser.add_argument(
        "--intel-api-key",
        default=os.environ.get("INTEL_API_KEY", os.environ.get("ITA_API_KEY", "")),
        help="Intel Trust Authority API key",
    )
    parser.add_argument(
        "--providers",
        default=os.environ.get("LAUNCHER_PROVIDERS", "baremetal"),
        help="Comma-separated providers enabled on this worker (baremetal)",
    )
    parser.add_argument(
        "--datacenter",
        default=os.environ.get("LAUNCHER_DATACENTER", ""),
        help="Optional claim filter (e.g., baremetal:github-runner)",
    )
    parser.add_argument(
        "--node-size",
        default=os.environ.get("LAUNCHER_NODE_SIZE", ""),
        help="Optional claim filter (tiny|standard|llm)",
    )
    parser.add_argument(
        "--poll-seconds",
        type=int,
        default=int(os.environ.get("LAUNCHER_POLL_SECONDS", "10")),
        help="Seconds between claim polls when no order is available",
    )
    parser.add_argument(
        "--one-shot",
        action="store_true",
        help="Claim/process at most one order, then exit",
    )
    parser.add_argument(
        "--max-orders",
        type=int,
        default=int(os.environ.get("LAUNCHER_MAX_ORDERS", "0")),
        help="Stop after processing this many claimed orders (0 = unlimited)",
    )
    return parser


def run_worker(config: WorkerConfig) -> int:
    cp = ControlPlaneClient(config.cp_url, config.launcher_api_key)
    processed = 0

    while True:
        claim = cp.claim_order(datacenter=config.claim_datacenter, node_size=config.claim_node_size)
        if not bool(claim.get("claimed")):
            if config.one_shot:
                return 0
            if config.max_orders > 0 and processed >= config.max_orders:
                return 0
            time.sleep(config.poll_seconds)
            continue

        order = claim.get("order")
        if not isinstance(order, dict):
            # Unexpected payload, wait and retry loop.
            if config.one_shot:
                return 1
            time.sleep(config.poll_seconds)
            continue

        order_id = str(order.get("order_id") or "").strip()
        if not order_id:
            if config.one_shot:
                return 1
            time.sleep(config.poll_seconds)
            continue

        print(
            f"[launcher] claimed order={order_id} dc={order.get('datacenter')} "
            f"size={order.get('node_size')}",
            flush=True,
        )

        cp.update_order(order_id, status="provisioning")
        try:
            vm_name = _launch_for_order(config, order)
        except Exception as exc:
            error_full = str(exc)
            error_text = _truncate(error_full, 450)
            cp.update_order(order_id, status="failed", error=error_text)
            print(f"[launcher] order={order_id} failed:", file=sys.stderr, flush=True)
            print(_tail(error_full), file=sys.stderr, flush=True)
            if config.one_shot:
                return 1
            processed += 1
            if config.max_orders > 0 and processed >= config.max_orders:
                return 0
            continue

        cp.update_order(order_id, status="fulfilled", vm_name=vm_name)
        print(f"[launcher] order={order_id} fulfilled vm={vm_name}", flush=True)
        processed += 1

        if config.one_shot:
            return 0
        if config.max_orders > 0 and processed >= config.max_orders:
            return 0


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    try:
        config = _load_config(args)
    except Exception as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    try:
        return run_worker(config)
    except KeyboardInterrupt:
        print("stopped", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"worker error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
