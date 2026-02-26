"""Tests for launcher VM name resolution."""

import os
import re
import sys
from pathlib import Path
from unittest.mock import mock_open, patch

LAUNCHER_DIR = str(Path(__file__).parent.parent / "infra" / "launcher")
if LAUNCHER_DIR not in sys.path:
    sys.path.insert(0, LAUNCHER_DIR)

import launcher  # noqa: E402


def test_get_vm_name_prefers_environment():
    with patch.dict(os.environ, {"VM_NAME": "vm-from-env"}, clear=False):
        assert launcher.get_vm_name({}) == "vm-from-env"


def test_get_vm_name_uses_gcp_metadata_when_hostname_missing():
    with patch.dict(os.environ, {}, clear=True):
        with patch("builtins.open", mock_open(read_data="")):
            with patch.object(launcher.Path, "exists", return_value=False):
                with patch.object(launcher.Path, "mkdir", return_value=None):
                    with patch.object(launcher.Path, "write_text", return_value=0):
                        with patch.object(
                            launcher, "_gcp_metadata_get", return_value="ee-tiny-test123"
                        ):
                            vm_name = launcher.get_vm_name({"cloud_provider": "gcp"})
    assert vm_name == "ee-tiny-test123"


def test_get_vm_name_non_gcp_falls_back_to_generated_name():
    with patch.dict(os.environ, {}, clear=True):
        with patch("builtins.open", mock_open(read_data="")):
            with patch.object(launcher.Path, "exists", return_value=False):
                with patch.object(launcher.Path, "mkdir", return_value=None):
                    with patch.object(launcher.Path, "write_text", return_value=0):
                        with patch.object(
                            launcher,
                            "_gcp_metadata_get",
                            side_effect=AssertionError("should not be called for non-gcp"),
                        ):
                            vm_name = launcher.get_vm_name({"cloud_provider": "baremetal"})
    assert re.fullmatch(r"tdx-agent-[0-9a-f]{8}", vm_name)
