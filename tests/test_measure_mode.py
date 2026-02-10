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
    @patch("launcher._write_measure_result")
    def test_writes_measurements_to_config_disk(self, mock_write, mock_run):
        """Measure mode writes JSON measurements to config disk and powers off."""
        fake_quote = _build_fake_quote(FAKE_MRTD, FAKE_RTMRS)
        fake_quote_b64 = base64.b64encode(fake_quote).decode()

        with patch("launcher.generate_tdx_quote", return_value=fake_quote_b64):
            launcher.run_measure_mode({})

        # Check measurements were written
        mock_write.assert_called_once()
        written_data = mock_write.call_args[0][2]
        assert written_data["mrtd"] == FAKE_MRTD
        assert written_data["rtmr0"] == "bb" * 48
        assert written_data["rtmr1"] == "cc" * 48
        assert written_data["rtmr2"] == "dd" * 48
        assert written_data["rtmr3"] == "ee" * 48

        # Check poweroff was called
        mock_run.assert_called_once_with(["systemctl", "poweroff"], check=False)

    @patch("launcher.subprocess.run")
    @patch("launcher._write_measure_result")
    def test_writes_error_on_failure(self, mock_write, mock_run):
        """On TDX failure, writes error to config disk and still powers off."""
        with patch("launcher.generate_tdx_quote", side_effect=RuntimeError("TDX not available")):
            launcher.run_measure_mode({})

        # Should have tried to write error
        mock_write.assert_called_once()
        written_data = mock_write.call_args[0][2]
        assert "error" in written_data
        assert "TDX not available" in written_data["error"]

        # Poweroff must still happen
        mock_run.assert_called_once_with(["systemctl", "poweroff"], check=False)

    @patch("launcher.subprocess.run")
    @patch("launcher._write_measure_result", side_effect=OSError("disk full"))
    def test_powers_off_even_if_write_fails(self, mock_write, mock_run):
        """VM powers off even if writing to config disk fails."""
        with patch("launcher.generate_tdx_quote", side_effect=RuntimeError("TDX not available")):
            launcher.run_measure_mode({})

        # Poweroff must still happen despite write failure
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
