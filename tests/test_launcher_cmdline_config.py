"""Tests for launcher kernel cmdline config parsing."""

import base64
import json
import sys
import zlib
from pathlib import Path
from unittest.mock import patch

LAUNCHER_DIR = str(Path(__file__).parent.parent / "infra" / "launcher")
if LAUNCHER_DIR not in sys.path:
    sys.path.insert(0, LAUNCHER_DIR)

import launcher  # noqa: E402


def test_parse_cmdline_config_plain_base64():
    config = {"mode": "control-plane", "port": 8080, "intel_api_key": "abc123"}
    encoded = base64.b64encode(json.dumps(config).encode()).decode()
    cmdline = f"console=ttyS0 easyenclave.config={encoded} ro"

    with patch.object(launcher.Path, "read_text", return_value=cmdline):
        parsed = launcher._parse_cmdline_config()

    assert parsed == config


def test_parse_cmdline_config_compressed_base64():
    config = {
        "mode": "control-plane",
        "trusted_agent_rtmrs_by_size": {
            "tiny": {
                "rtmr0": "a" * 96,
                "rtmr1": "b" * 96,
                "rtmr2": "c" * 96,
                "rtmr3": "d" * 96,
            },
            "standard": {
                "rtmr0": "e" * 96,
                "rtmr1": "f" * 96,
                "rtmr2": "g" * 96,
                "rtmr3": "h" * 96,
            },
            "llm": {
                "rtmr0": "i" * 96,
                "rtmr1": "j" * 96,
                "rtmr2": "k" * 96,
                "rtmr3": "l" * 96,
            },
        },
    }
    compressed = zlib.compress(json.dumps(config, separators=(",", ":")).encode(), level=9)
    encoded = base64.b64encode(compressed).decode()
    cmdline = f"console=ttyS0 easyenclave.configz={encoded} ro"

    with patch.object(launcher.Path, "read_text", return_value=cmdline):
        parsed = launcher._parse_cmdline_config()

    assert parsed == config


def test_parse_cmdline_config_prefers_compressed_when_both_present():
    compressed_cfg = {"mode": "control-plane", "port": 8080}
    compressed = zlib.compress(json.dumps(compressed_cfg).encode(), level=9)
    compressed_b64 = base64.b64encode(compressed).decode()
    # Invalid plain config should be ignored if compressed one exists.
    cmdline = (
        f"console=ttyS0 easyenclave.config=not-valid-base64 easyenclave.configz={compressed_b64} ro"
    )

    with patch.object(launcher.Path, "read_text", return_value=cmdline):
        parsed = launcher._parse_cmdline_config()

    assert parsed == compressed_cfg
