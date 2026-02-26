"""Tests for TCB status enforcement."""

import os
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def reset_tcb_config():
    """Reset TCB config before each test."""
    # Save original values
    orig_mode = os.environ.get("TCB_ENFORCEMENT_MODE")
    orig_statuses = os.environ.get("ALLOWED_TCB_STATUSES")

    yield

    # Restore original values
    if orig_mode is None:
        os.environ.pop("TCB_ENFORCEMENT_MODE", None)
    else:
        os.environ["TCB_ENFORCEMENT_MODE"] = orig_mode

    if orig_statuses is None:
        os.environ.pop("ALLOWED_TCB_STATUSES", None)
    else:
        os.environ["ALLOWED_TCB_STATUSES"] = orig_statuses

    # Reload module to pick up env changes
    import importlib

    import app.attestation

    importlib.reload(app.attestation)


@pytest.mark.asyncio
async def test_tcb_disabled_mode_allows_all():
    """Test that disabled mode allows all TCB statuses."""
    os.environ["TCB_ENFORCEMENT_MODE"] = "disabled"
    import importlib

    import app.attestation

    importlib.reload(app.attestation)

    attestation = {"tdx": {"intel_ta_token": "fake_token"}}

    with patch("app.attestation.verify_attestation_token") as mock_verify:
        with patch("app.attestation.get_trusted_mrtd") as mock_trusted:
            # Mock Intel TA verification
            mock_verify.return_value = {
                "verified": True,
                "details": {
                    "tdx_mrtd": "abc123" * 16,
                    "attester_tcb_status": "OutOfDate",  # Should be allowed in disabled mode
                },
            }

            # Mock MRTD trusted list
            mock_trusted.return_value = "agent"

            result = await app.attestation.verify_agent_registration(attestation)

            assert result.mrtd == "abc123" * 16
            assert result.tcb_status == "OutOfDate"


@pytest.mark.asyncio
async def test_tcb_warn_mode_logs_warning():
    """Test that warn mode logs warning but allows registration."""
    os.environ["TCB_ENFORCEMENT_MODE"] = "warn"
    os.environ["ALLOWED_TCB_STATUSES"] = "UpToDate"
    import importlib

    import app.attestation

    importlib.reload(app.attestation)

    attestation = {"tdx": {"intel_ta_token": "fake_token"}}

    with patch("app.attestation.verify_attestation_token") as mock_verify:
        with patch("app.attestation.get_trusted_mrtd") as mock_trusted:
            with patch("app.attestation.logger") as mock_logger:
                # Mock Intel TA verification
                mock_verify.return_value = {
                    "verified": True,
                    "details": {
                        "tdx_mrtd": "abc123" * 16,
                        "attester_tcb_status": "OutOfDate",
                    },
                }

                # Mock MRTD trusted list
                mock_trusted.return_value = "agent"

                result = await app.attestation.verify_agent_registration(attestation)

                # Should succeed despite OutOfDate TCB
                assert result.mrtd == "abc123" * 16
                assert result.tcb_status == "OutOfDate"

                # Should log warning
                mock_logger.warning.assert_called_once()
                warning_msg = mock_logger.warning.call_args[0][0]
                assert "TCB warning" in warning_msg
                assert "OutOfDate" in warning_msg


@pytest.mark.asyncio
async def test_tcb_strict_mode_rejects_invalid():
    """Test that strict mode rejects non-allowed TCB statuses."""
    os.environ["TCB_ENFORCEMENT_MODE"] = "strict"
    os.environ["ALLOWED_TCB_STATUSES"] = "UpToDate"
    import importlib

    import app.attestation

    importlib.reload(app.attestation)

    attestation = {"tdx": {"intel_ta_token": "fake_token"}}

    with patch("app.attestation.verify_attestation_token") as mock_verify:
        with patch("app.attestation.get_trusted_mrtd") as mock_trusted:
            # Mock Intel TA verification
            mock_verify.return_value = {
                "verified": True,
                "details": {
                    "tdx_mrtd": "abc123" * 16,
                    "attester_tcb_status": "OutOfDate",
                },
            }

            # Mock MRTD trusted list (won't be reached)
            mock_trusted.return_value = "agent"

            with pytest.raises(app.attestation.AttestationError) as exc_info:
                await app.attestation.verify_agent_registration(attestation)

            assert exc_info.value.status_code == 403
            assert "OutOfDate" in exc_info.value.detail
            assert "UpToDate" in exc_info.value.detail


@pytest.mark.asyncio
async def test_tcb_strict_mode_allows_valid():
    """Test that strict mode allows UpToDate TCB status."""
    os.environ["TCB_ENFORCEMENT_MODE"] = "strict"
    os.environ["ALLOWED_TCB_STATUSES"] = "UpToDate"
    import importlib

    import app.attestation

    importlib.reload(app.attestation)

    attestation = {"tdx": {"intel_ta_token": "fake_token"}}

    with patch("app.attestation.verify_attestation_token") as mock_verify:
        with patch("app.attestation.get_trusted_mrtd") as mock_trusted:
            # Mock Intel TA verification
            mock_verify.return_value = {
                "verified": True,
                "details": {
                    "tdx_mrtd": "abc123" * 16,
                    "attester_tcb_status": "UpToDate",
                },
            }

            # Mock MRTD trusted list
            mock_trusted.return_value = "agent"

            result = await app.attestation.verify_agent_registration(attestation)

            assert result.mrtd == "abc123" * 16
            assert result.tcb_status == "UpToDate"


@pytest.mark.asyncio
async def test_tcb_multiple_allowed_statuses():
    """Test that multiple allowed statuses can be configured."""
    os.environ["TCB_ENFORCEMENT_MODE"] = "strict"
    os.environ["ALLOWED_TCB_STATUSES"] = "UpToDate,SWHardeningNeeded"
    import importlib

    import app.attestation

    importlib.reload(app.attestation)

    attestation = {"tdx": {"intel_ta_token": "fake_token"}}

    with patch("app.attestation.verify_attestation_token") as mock_verify:
        with patch("app.attestation.get_trusted_mrtd") as mock_trusted:
            # Mock Intel TA verification with SWHardeningNeeded
            mock_verify.return_value = {
                "verified": True,
                "details": {
                    "tdx_mrtd": "abc123" * 16,
                    "attester_tcb_status": "SWHardeningNeeded",
                },
            }

            # Mock MRTD trusted list
            mock_trusted.return_value = "agent"

            result = await app.attestation.verify_agent_registration(attestation)

            assert result.mrtd == "abc123" * 16
            assert result.tcb_status == "SWHardeningNeeded"


@pytest.mark.asyncio
async def test_tcb_unknown_status_handled():
    """Test that Unknown TCB status is handled correctly."""
    os.environ["TCB_ENFORCEMENT_MODE"] = "strict"
    os.environ["ALLOWED_TCB_STATUSES"] = "UpToDate"
    import importlib

    import app.attestation

    importlib.reload(app.attestation)

    attestation = {"tdx": {"intel_ta_token": "fake_token"}}

    with patch("app.attestation.verify_attestation_token") as mock_verify:
        with patch("app.attestation.get_trusted_mrtd") as mock_trusted:
            # Mock Intel TA verification with missing TCB status
            mock_verify.return_value = {
                "verified": True,
                "details": {
                    "tdx_mrtd": "abc123" * 16,
                    # No attester_tcb_status field
                },
            }

            # Mock MRTD trusted list
            mock_trusted.return_value = "agent"

            with pytest.raises(app.attestation.AttestationError) as exc_info:
                await app.attestation.verify_agent_registration(attestation)

            # Should default to "Unknown" and reject
            assert exc_info.value.status_code == 403
            assert "Unknown" in exc_info.value.detail
