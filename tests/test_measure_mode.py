"""Tests for launcher measure mode."""

import base64
import struct
from unittest.mock import patch


def _build_fake_quote(mrtd: str, rtmrs: list[str]) -> bytes:
    """Build a minimal fake TDX quote binary for testing.

    Layout:
    - Header: 48 bytes (zeros, version=4)
    - TD Report starting at offset 48:
      - TEE_TCB_SVN: 16 bytes (offset 0)
      - MRSEAM: 48 bytes (offset 16)
      - MRSIGNERSEAM: 48 bytes (offset 64)
      - SEAMATTRIBUTES: 8 bytes (offset 112)
      - TDATTRIBUTES: 8 bytes (offset 120)
      - XFAM: 8 bytes (offset 128)
      - MRTD: 48 bytes (offset 136)
      - MRCONFIGID: 48 bytes (offset 184)
      - MROWNER: 48 bytes (offset 232)
      - MROWNERCONFIG: 48 bytes (offset 280)
      - RTMR0-3: 48 bytes each (offset 328)
      - REPORTDATA: 64 bytes (offset 520)
    Total minimum: 48 + 584 = 632 bytes
    """
    # Header: version=4, rest zeros
    header = struct.pack("<H", 4) + b"\x00" * 46

    # TD Report fields before MRTD
    td_report = b"\x00" * 136  # TEE_TCB_SVN + MRSEAM + MRSIGNERSEAM + attrs + XFAM

    # MRTD (48 bytes)
    td_report += bytes.fromhex(mrtd)

    # MRCONFIGID + MROWNER + MROWNERCONFIG (3 * 48 = 144 bytes)
    td_report += b"\x00" * 144

    # RTMRs (4 * 48 = 192 bytes)
    for rtmr_hex in rtmrs:
        td_report += bytes.fromhex(rtmr_hex)

    # REPORTDATA (64 bytes)
    td_report += b"\x00" * 64

    return header + td_report


FAKE_MRTD = "aa" * 48  # 96 hex chars = 48 bytes
FAKE_RTMRS = ["bb" * 48, "cc" * 48, "dd" * 48, "ee" * 48]


class TestMeasureMode:
    """Test the run_measure_mode function in launcher.py."""

    def test_measure_mode_prints_measurements(self, capsys):
        """Measure mode should print all measurements and exit."""
        fake_quote = _build_fake_quote(FAKE_MRTD, FAKE_RTMRS)
        fake_quote_b64 = base64.b64encode(fake_quote).decode()

        # We need to import from the launcher module path
        import sys

        launcher_dir = str(
            __import__("pathlib").Path(__file__).parent.parent / "infra" / "launcher"
        )
        if launcher_dir not in sys.path:
            sys.path.insert(0, launcher_dir)

        # Mock the TSM report path and ConfigFS interaction
        with patch("launcher.generate_tdx_quote", return_value=fake_quote_b64):
            import launcher

            launcher.run_measure_mode({})

        captured = capsys.readouterr()
        assert f"MRTD_FULL={FAKE_MRTD}" in captured.out
        assert f"RTMR0={'bb' * 48}" in captured.out
        assert f"RTMR1={'cc' * 48}" in captured.out
        assert f"RTMR2={'dd' * 48}" in captured.out
        assert f"RTMR3={'ee' * 48}" in captured.out

    def test_measure_mode_handles_error(self, capsys):
        """Measure mode should print error and not crash."""
        import sys

        launcher_dir = str(
            __import__("pathlib").Path(__file__).parent.parent / "infra" / "launcher"
        )
        if launcher_dir not in sys.path:
            sys.path.insert(0, launcher_dir)

        with patch("launcher.generate_tdx_quote", side_effect=RuntimeError("TDX not available")):
            import launcher

            launcher.run_measure_mode({})

        captured = capsys.readouterr()
        assert "MEASURE_ERROR=" in captured.out

    def test_parse_tdx_quote_extracts_all_fields(self):
        """parse_tdx_quote should extract MRTD and all RTMRs."""
        import sys

        launcher_dir = str(
            __import__("pathlib").Path(__file__).parent.parent / "infra" / "launcher"
        )
        if launcher_dir not in sys.path:
            sys.path.insert(0, launcher_dir)

        import launcher

        fake_quote = _build_fake_quote(FAKE_MRTD, FAKE_RTMRS)
        fake_quote_b64 = base64.b64encode(fake_quote).decode()

        result = launcher.parse_tdx_quote(fake_quote_b64)
        assert result["mrtd"] == FAKE_MRTD
        assert result["rtmr0"] == "bb" * 48
        assert result["rtmr1"] == "cc" * 48
        assert result["rtmr2"] == "dd" * 48
        assert result["rtmr3"] == "ee" * 48
