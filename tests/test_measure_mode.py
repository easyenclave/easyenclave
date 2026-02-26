"""Tests for launcher measure mode."""

import base64
import struct
import sys
from pathlib import Path
from unittest.mock import patch

LAUNCHER_DIR = str(Path(__file__).parent.parent / "infra" / "launcher")
if LAUNCHER_DIR not in sys.path:
    sys.path.insert(0, LAUNCHER_DIR)

import launcher  # noqa: E402


def _build_fake_quote(mrtd: str, rtmrs: list[str]) -> bytes:
    """Build a minimal fake TDX quote binary for testing.

    Layout: 48-byte header + TD Report (584+ bytes).
    """
    header = struct.pack("<H", 4) + b"\x00" * 46
    td_report = b"\x00" * 136  # fields before MRTD
    td_report += bytes.fromhex(mrtd)  # MRTD (48 bytes)
    td_report += b"\x00" * 144  # MRCONFIGID + MROWNER + MROWNERCONFIG
    for rtmr_hex in rtmrs:
        td_report += bytes.fromhex(rtmr_hex)  # RTMR0-3
    td_report += b"\x00" * 64  # REPORTDATA
    return header + td_report


FAKE_MRTD = "aa" * 48
FAKE_RTMRS = ["bb" * 48, "cc" * 48, "dd" * 48, "ee" * 48]


class TestMeasureMode:
    """Test the run_measure_mode function in launcher.py."""

    @patch("launcher.subprocess.run")
    def test_prints_measurements_and_powers_off(self, mock_run, capsys):
        """Measure mode prints JSON measurements to stdout and powers off."""
        fake_quote = _build_fake_quote(FAKE_MRTD, FAKE_RTMRS)
        fake_quote_b64 = base64.b64encode(fake_quote).decode()

        with patch("launcher.generate_tdx_quote", return_value=fake_quote_b64):
            launcher.run_measure_mode({})

        # Check measurements were printed to stdout
        import json

        captured = capsys.readouterr()
        assert "EASYENCLAVE_MEASUREMENTS=" in captured.out
        json_str = captured.out.split("EASYENCLAVE_MEASUREMENTS=", 1)[1].strip()
        data = json.loads(json_str)
        assert data["mrtd"] == FAKE_MRTD
        assert data["rtmr0"] == "bb" * 48
        assert data["rtmr1"] == "cc" * 48

        # Check poweroff was called
        mock_run.assert_called_once_with(["systemctl", "poweroff"], check=False)

    @patch("launcher.subprocess.run")
    def test_prints_error_on_failure(self, mock_run, capsys):
        """On TDX failure, prints error to stdout and still powers off."""
        with patch("launcher.generate_tdx_quote", side_effect=RuntimeError("TDX not available")):
            launcher.run_measure_mode({})

        # Should have printed error
        captured = capsys.readouterr()
        assert "EASYENCLAVE_MEASURE_ERROR=" in captured.out
        assert "TDX not available" in captured.out

        # Poweroff must still happen
        mock_run.assert_called_once_with(["systemctl", "poweroff"], check=False)

    @patch("launcher.subprocess.run")
    def test_powers_off_even_on_exception(self, mock_run):
        """VM powers off even if quote generation raises."""
        with patch("launcher.generate_tdx_quote", side_effect=RuntimeError("TDX not available")):
            launcher.run_measure_mode({})

        # Poweroff must still happen
        mock_run.assert_called_once_with(["systemctl", "poweroff"], check=False)

    def test_parse_tdx_quote_extracts_all_fields(self):
        """parse_tdx_quote should extract MRTD and all RTMRs."""
        fake_quote = _build_fake_quote(FAKE_MRTD, FAKE_RTMRS)
        fake_quote_b64 = base64.b64encode(fake_quote).decode()

        result = launcher.parse_tdx_quote(fake_quote_b64)
        assert result["mrtd"] == FAKE_MRTD
        assert result["rtmr0"] == "bb" * 48
        assert result["rtmr1"] == "cc" * 48
        assert result["rtmr2"] == "dd" * 48
        assert result["rtmr3"] == "ee" * 48
