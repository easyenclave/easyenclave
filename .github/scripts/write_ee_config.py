#!/usr/bin/env python3

import argparse
import json
import pathlib
import sys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate and write EasyEnclave ee-config JSON."
    )
    parser.add_argument("--json", required=True, help="Raw ee-config JSON object")
    parser.add_argument("--output", required=True, help="Path to write the JSON file to")
    parser.add_argument(
        "--require-native-static",
        action="store_true",
        help="Require at least one boot workload with native=true and an image",
    )
    return parser.parse_args()


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    args = parse_args()

    try:
        payload = json.loads(args.json)
    except json.JSONDecodeError as exc:
        fail(f"invalid ee-config JSON: {exc}")

    if not isinstance(payload, dict):
        fail("ee-config must be a JSON object")

    if args.require_native_static:
        boot_workloads_raw = payload.get("EE_BOOT_WORKLOADS")
        if not isinstance(boot_workloads_raw, str) or not boot_workloads_raw.strip():
            fail(
                "release test config must define EE_BOOT_WORKLOADS as a JSON string "
                "containing at least one native workload"
            )

        try:
            boot_workloads = json.loads(boot_workloads_raw)
        except json.JSONDecodeError as exc:
            fail(f"EE_BOOT_WORKLOADS is not valid JSON: {exc}")

        if not isinstance(boot_workloads, list):
            fail("EE_BOOT_WORKLOADS must decode to a JSON array")

        native_workloads = [
            workload
            for workload in boot_workloads
            if isinstance(workload, dict)
            and workload.get("native") is True
            and isinstance(workload.get("image"), str)
            and workload["image"].strip()
        ]
        if not native_workloads:
            fail(
                "release test config must include at least one boot workload with "
                '"native": true and a non-empty "image"'
            )

    output_path = pathlib.Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
