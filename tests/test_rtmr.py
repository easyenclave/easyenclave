"""Tests for RTMR extraction, drift detection, backfill, and registration verification."""

import os
from unittest.mock import patch

import pytest

from app.attestation import build_attestation_chain, extract_rtmrs, refresh_agent_attestation
from app.db_models import Agent
from app.storage import agent_store

SAMPLE_RTMRS = {
    "rtmr0": "a" * 96,
    "rtmr1": "b" * 96,
    "rtmr2": "c" * 96,
    "rtmr3": "d" * 96,
}

SAMPLE_ATTESTATION = {
    "tdx": {
        "intel_ta_token": "fake.jwt.token",
        "measurements": {
            "mrtd": "e" * 96,
            **SAMPLE_RTMRS,
        },
    }
}


class TestExtractRtmrs:
    def test_valid_attestation(self):
        result = extract_rtmrs(SAMPLE_ATTESTATION)
        assert result == SAMPLE_RTMRS

    def test_missing_tdx(self):
        assert extract_rtmrs({}) is None

    def test_missing_measurements(self):
        assert extract_rtmrs({"tdx": {}}) is None

    def test_partial_rtmrs(self):
        """If fewer than 4 RTMRs are present, return None."""
        attestation = {
            "tdx": {
                "measurements": {
                    "rtmr0": "a" * 96,
                    "rtmr1": "b" * 96,
                }
            }
        }
        assert extract_rtmrs(attestation) is None

    def test_empty_measurements(self):
        assert extract_rtmrs({"tdx": {"measurements": {}}}) is None


class TestRtmrDriftDetection:
    """Test RTMR drift detection during re-attestation."""

    def _make_agent(self, rtmrs=None):
        agent = Agent(
            vm_name="test-vm",
            attestation=SAMPLE_ATTESTATION,
            mrtd="e" * 96,
            rtmrs=rtmrs,
            verified=True,
        )
        agent_store.register(agent)
        return agent.agent_id

    @pytest.mark.asyncio
    @patch("app.attestation.verify_attestation_token")
    async def test_drift_detected(self, mock_verify):
        """Agent with stored RTMRs re-attests with different values -> verified=False."""
        mock_verify.return_value = {"verified": True, "details": {}}
        agent_id = self._make_agent(rtmrs=SAMPLE_RTMRS)

        # Build attestation with changed rtmr1 and rtmr3
        changed_rtmrs = {**SAMPLE_RTMRS, "rtmr1": "f" * 96, "rtmr3": "f" * 96}
        changed_attestation = {
            "tdx": {
                "intel_ta_token": "fake.jwt.token",
                "measurements": {"mrtd": "e" * 96, **changed_rtmrs},
            }
        }

        result = await refresh_agent_attestation(agent_id, changed_attestation)
        assert result is False

        agent = agent_store.get(agent_id)
        assert agent.verified is False
        assert "RTMR drift detected" in agent.attestation_error
        assert "rtmr1" in agent.attestation_error
        assert "rtmr3" in agent.attestation_error

    @pytest.mark.asyncio
    @patch("app.attestation.verify_attestation_token")
    async def test_no_drift(self, mock_verify):
        """Same RTMRs -> stays verified."""
        mock_verify.return_value = {"verified": True, "details": {}}
        agent_id = self._make_agent(rtmrs=SAMPLE_RTMRS)

        result = await refresh_agent_attestation(agent_id, SAMPLE_ATTESTATION)
        assert result is True

        agent = agent_store.get(agent_id)
        assert agent.verified is True

    @pytest.mark.asyncio
    @patch("app.attestation.verify_attestation_token")
    async def test_backfill(self, mock_verify):
        """Agent with rtmrs=None, re-attest -> rtmrs populated."""
        mock_verify.return_value = {"verified": True, "details": {}}
        agent_id = self._make_agent(rtmrs=None)

        result = await refresh_agent_attestation(agent_id, SAMPLE_ATTESTATION)
        assert result is True

        agent = agent_store.get(agent_id)
        assert agent.rtmrs == SAMPLE_RTMRS
        assert agent.verified is True

    @pytest.mark.asyncio
    @patch("app.attestation.verify_attestation_token")
    async def test_no_rtmrs_in_attestation(self, mock_verify):
        """Attestation without RTMRs still succeeds (no drift check possible)."""
        mock_verify.return_value = {"verified": True, "details": {}}
        agent_id = self._make_agent(rtmrs=SAMPLE_RTMRS)

        bare_attestation = {"tdx": {"intel_ta_token": "fake.jwt.token"}}
        result = await refresh_agent_attestation(agent_id, bare_attestation)
        assert result is True

        agent = agent_store.get(agent_id)
        assert agent.verified is True


class TestAttestationChainIncludesRtmrs:
    @pytest.mark.asyncio
    @patch("app.attestation.verify_attestation_token")
    async def test_chain_has_rtmrs(self, mock_verify):
        mock_verify.return_value = {"verified": False, "details": {}}
        agent = Agent(
            vm_name="test-vm",
            attestation=SAMPLE_ATTESTATION,
            mrtd="e" * 96,
            rtmrs=SAMPLE_RTMRS,
            verified=True,
        )
        agent_store.register(agent)

        chain = await build_attestation_chain(agent)
        assert chain["rtmrs"] == SAMPLE_RTMRS

    @pytest.mark.asyncio
    @patch("app.attestation.verify_attestation_token")
    async def test_chain_rtmrs_none(self, mock_verify):
        mock_verify.return_value = {"verified": False, "details": {}}
        agent = Agent(
            vm_name="test-vm",
            attestation=SAMPLE_ATTESTATION,
            mrtd="e" * 96,
            rtmrs=None,
            verified=True,
        )
        agent_store.register(agent)

        chain = await build_attestation_chain(agent)
        assert chain["rtmrs"] is None


# ── RTMR verification at registration ────────────────────────────────────

TRUSTED_RTMRS = {
    "rtmr0": "a" * 96,
    "rtmr1": "b" * 96,
    "rtmr2": "c" * 96,
    "rtmr3": "d" * 96,
}

MRTD_HEX = "e" * 96


@pytest.fixture(autouse=False)
def reset_rtmr_config():
    """Reset RTMR enforcement config around a test."""
    orig_mode = os.environ.get("RTMR_ENFORCEMENT_MODE")
    orig_rtmrs = os.environ.get("TRUSTED_AGENT_RTMRS")
    orig_rtmrs_by_size = os.environ.get("TRUSTED_AGENT_RTMRS_BY_SIZE")

    yield

    if orig_mode is None:
        os.environ.pop("RTMR_ENFORCEMENT_MODE", None)
    else:
        os.environ["RTMR_ENFORCEMENT_MODE"] = orig_mode

    if orig_rtmrs is None:
        os.environ.pop("TRUSTED_AGENT_RTMRS", None)
    else:
        os.environ["TRUSTED_AGENT_RTMRS"] = orig_rtmrs

    if orig_rtmrs_by_size is None:
        os.environ.pop("TRUSTED_AGENT_RTMRS_BY_SIZE", None)
    else:
        os.environ["TRUSTED_AGENT_RTMRS_BY_SIZE"] = orig_rtmrs_by_size

    # Reload to pick up changes
    import importlib

    import app.attestation
    import app.storage

    importlib.reload(app.storage)
    importlib.reload(app.attestation)


def _make_attestation(rtmrs=None):
    """Build attestation dict with optional RTMRs."""
    measurements = {"mrtd": MRTD_HEX}
    if rtmrs:
        measurements.update(rtmrs)
    return {"tdx": {"intel_ta_token": "fake.jwt.token", "measurements": measurements}}


class TestRtmrRegistrationVerification:
    """Test RTMR verification at agent registration time."""

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("reset_rtmr_config")
    async def test_strict_mode_rejects_mismatch(self):
        """Strict mode rejects when RTMRs don't match trusted baseline."""
        import importlib
        import json

        os.environ["RTMR_ENFORCEMENT_MODE"] = "strict"
        os.environ["TRUSTED_AGENT_RTMRS"] = json.dumps(TRUSTED_RTMRS)

        import app.attestation
        import app.storage

        importlib.reload(app.storage)
        importlib.reload(app.attestation)

        # Attestation with mismatched rtmr1
        bad_rtmrs = {**TRUSTED_RTMRS, "rtmr1": "f" * 96}
        attestation = _make_attestation(bad_rtmrs)

        with patch("app.attestation.verify_attestation_token") as mock_verify:
            with patch("app.attestation.get_trusted_mrtd") as mock_mrtd:
                mock_verify.return_value = {
                    "verified": True,
                    "details": {"tdx_mrtd": MRTD_HEX, "attester_tcb_status": "UpToDate"},
                }
                mock_mrtd.return_value = "agent"

                with pytest.raises(app.attestation.AttestationError) as exc_info:
                    await app.attestation.verify_agent_registration(attestation)

                assert exc_info.value.status_code == 403
                assert "RTMR mismatch" in exc_info.value.detail
                assert "RTMR1" in exc_info.value.detail

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("reset_rtmr_config")
    async def test_strict_mode_allows_match(self):
        """Strict mode allows when RTMRs match trusted baseline."""
        import importlib
        import json

        os.environ["RTMR_ENFORCEMENT_MODE"] = "strict"
        os.environ["TRUSTED_AGENT_RTMRS"] = json.dumps(TRUSTED_RTMRS)

        import app.attestation
        import app.storage

        importlib.reload(app.storage)
        importlib.reload(app.attestation)

        attestation = _make_attestation(TRUSTED_RTMRS)

        with patch("app.attestation.verify_attestation_token") as mock_verify:
            with patch("app.attestation.get_trusted_mrtd") as mock_mrtd:
                mock_verify.return_value = {
                    "verified": True,
                    "details": {"tdx_mrtd": MRTD_HEX, "attester_tcb_status": "UpToDate"},
                }
                mock_mrtd.return_value = "agent"

                result = await app.attestation.verify_agent_registration(attestation)
                assert result.mrtd == MRTD_HEX
                assert result.rtmrs == TRUSTED_RTMRS

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("reset_rtmr_config")
    async def test_warn_mode_logs_mismatch(self):
        """Warn mode logs warning but allows registration on mismatch."""
        import importlib
        import json

        os.environ["RTMR_ENFORCEMENT_MODE"] = "warn"
        os.environ["TRUSTED_AGENT_RTMRS"] = json.dumps(TRUSTED_RTMRS)

        import app.attestation
        import app.storage

        importlib.reload(app.storage)
        importlib.reload(app.attestation)

        bad_rtmrs = {**TRUSTED_RTMRS, "rtmr2": "f" * 96}
        attestation = _make_attestation(bad_rtmrs)

        with patch("app.attestation.verify_attestation_token") as mock_verify:
            with patch("app.attestation.get_trusted_mrtd") as mock_mrtd:
                with patch("app.attestation.logger") as mock_logger:
                    mock_verify.return_value = {
                        "verified": True,
                        "details": {"tdx_mrtd": MRTD_HEX, "attester_tcb_status": "UpToDate"},
                    }
                    mock_mrtd.return_value = "agent"

                    result = await app.attestation.verify_agent_registration(attestation)
                    assert result.mrtd == MRTD_HEX

                    # Should have logged a warning
                    warning_calls = [
                        c for c in mock_logger.warning.call_args_list if "RTMR warning" in str(c)
                    ]
                    assert len(warning_calls) >= 1

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("reset_rtmr_config")
    async def test_disabled_mode_skips_check(self):
        """Disabled mode skips RTMR check entirely."""
        import importlib
        import json

        os.environ["RTMR_ENFORCEMENT_MODE"] = "disabled"
        os.environ["TRUSTED_AGENT_RTMRS"] = json.dumps(TRUSTED_RTMRS)

        import app.attestation
        import app.storage

        importlib.reload(app.storage)
        importlib.reload(app.attestation)

        # Completely wrong RTMRs should still pass
        bad_rtmrs = {f"rtmr{i}": "f" * 96 for i in range(4)}
        attestation = _make_attestation(bad_rtmrs)

        with patch("app.attestation.verify_attestation_token") as mock_verify:
            with patch("app.attestation.get_trusted_mrtd") as mock_mrtd:
                mock_verify.return_value = {
                    "verified": True,
                    "details": {"tdx_mrtd": MRTD_HEX, "attester_tcb_status": "UpToDate"},
                }
                mock_mrtd.return_value = "agent"

                result = await app.attestation.verify_agent_registration(attestation)
                assert result.mrtd == MRTD_HEX

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("reset_rtmr_config")
    async def test_strict_mode_uses_node_size_specific_baseline(self):
        """Strict mode should use node_size-specific RTMR profiles when configured."""
        import importlib
        import json

        llm_rtmrs = {**TRUSTED_RTMRS, "rtmr0": "f" * 96}
        os.environ["RTMR_ENFORCEMENT_MODE"] = "strict"
        os.environ["TRUSTED_AGENT_RTMRS_BY_SIZE"] = json.dumps(
            {
                "tiny": TRUSTED_RTMRS,
                "llm": llm_rtmrs,
            }
        )

        import app.attestation
        import app.storage

        importlib.reload(app.storage)
        importlib.reload(app.attestation)

        with patch("app.attestation.verify_attestation_token") as mock_verify:
            with patch("app.attestation.get_trusted_mrtd") as mock_mrtd:
                mock_verify.return_value = {
                    "verified": True,
                    "details": {"tdx_mrtd": MRTD_HEX, "attester_tcb_status": "UpToDate"},
                }
                mock_mrtd.return_value = "agent"

                # Matches llm profile -> pass
                llm_attestation = _make_attestation(llm_rtmrs)
                result = await app.attestation.verify_agent_registration(
                    llm_attestation, node_size="llm"
                )
                assert result.mrtd == MRTD_HEX

                # Same attestation against tiny profile -> fail
                with pytest.raises(app.attestation.AttestationError):
                    await app.attestation.verify_agent_registration(
                        llm_attestation, node_size="tiny"
                    )

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("reset_rtmr_config")
    async def test_no_trusted_rtmrs_configured(self):
        """When no trusted RTMRs configured, verification passes."""
        import importlib

        os.environ["RTMR_ENFORCEMENT_MODE"] = "strict"
        os.environ.pop("TRUSTED_AGENT_RTMRS", None)

        import app.attestation
        import app.storage

        importlib.reload(app.storage)
        importlib.reload(app.attestation)

        attestation = _make_attestation(TRUSTED_RTMRS)

        with patch("app.attestation.verify_attestation_token") as mock_verify:
            with patch("app.attestation.get_trusted_mrtd") as mock_mrtd:
                mock_verify.return_value = {
                    "verified": True,
                    "details": {"tdx_mrtd": MRTD_HEX, "attester_tcb_status": "UpToDate"},
                }
                mock_mrtd.return_value = "agent"

                result = await app.attestation.verify_agent_registration(attestation)
                assert result.mrtd == MRTD_HEX

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("reset_rtmr_config")
    async def test_strict_rejects_missing_rtmrs_in_attestation(self):
        """Strict mode rejects when trusted RTMRs configured but agent has none."""
        import importlib
        import json

        os.environ["RTMR_ENFORCEMENT_MODE"] = "strict"
        os.environ["TRUSTED_AGENT_RTMRS"] = json.dumps(TRUSTED_RTMRS)

        import app.attestation
        import app.storage

        importlib.reload(app.storage)
        importlib.reload(app.attestation)

        # Attestation without any RTMRs
        attestation = _make_attestation(rtmrs=None)

        with patch("app.attestation.verify_attestation_token") as mock_verify:
            with patch("app.attestation.get_trusted_mrtd") as mock_mrtd:
                mock_verify.return_value = {
                    "verified": True,
                    "details": {"tdx_mrtd": MRTD_HEX, "attester_tcb_status": "UpToDate"},
                }
                mock_mrtd.return_value = "agent"

                with pytest.raises(app.attestation.AttestationError) as exc_info:
                    await app.attestation.verify_agent_registration(attestation)

                assert exc_info.value.status_code == 403
                assert "does not contain RTMRs" in exc_info.value.detail


class TestTrustedRtmrsLoading:
    """Test trusted RTMR loading from environment variables."""

    def test_load_valid_json(self):
        import importlib
        import json

        orig = os.environ.get("TRUSTED_AGENT_RTMRS")
        try:
            os.environ["TRUSTED_AGENT_RTMRS"] = json.dumps(TRUSTED_RTMRS)

            import app.storage

            importlib.reload(app.storage)

            result = app.storage.get_trusted_rtmrs("agent")
            assert result == TRUSTED_RTMRS
        finally:
            if orig is None:
                os.environ.pop("TRUSTED_AGENT_RTMRS", None)
            else:
                os.environ["TRUSTED_AGENT_RTMRS"] = orig
            importlib.reload(app.storage)

    def test_load_empty_env(self):
        import importlib

        orig = os.environ.get("TRUSTED_AGENT_RTMRS")
        try:
            os.environ.pop("TRUSTED_AGENT_RTMRS", None)

            import app.storage

            importlib.reload(app.storage)

            result = app.storage.get_trusted_rtmrs("agent")
            assert result is None
        finally:
            if orig is not None:
                os.environ["TRUSTED_AGENT_RTMRS"] = orig
            importlib.reload(app.storage)

    def test_load_invalid_json(self):
        import importlib

        orig = os.environ.get("TRUSTED_AGENT_RTMRS")
        try:
            os.environ["TRUSTED_AGENT_RTMRS"] = "not-valid-json"

            import app.storage

            importlib.reload(app.storage)

            result = app.storage.get_trusted_rtmrs("agent")
            assert result is None
        finally:
            if orig is None:
                os.environ.pop("TRUSTED_AGENT_RTMRS", None)
            else:
                os.environ["TRUSTED_AGENT_RTMRS"] = orig
            importlib.reload(app.storage)

    def test_load_missing_keys(self):
        """JSON that's missing some rtmr keys should not load."""
        import importlib
        import json

        orig = os.environ.get("TRUSTED_AGENT_RTMRS")
        try:
            os.environ["TRUSTED_AGENT_RTMRS"] = json.dumps({"rtmr0": "a" * 96})

            import app.storage

            importlib.reload(app.storage)

            result = app.storage.get_trusted_rtmrs("agent")
            assert result is None
        finally:
            if orig is None:
                os.environ.pop("TRUSTED_AGENT_RTMRS", None)
            else:
                os.environ["TRUSTED_AGENT_RTMRS"] = orig
            importlib.reload(app.storage)

    def test_load_node_size_profiles(self):
        import importlib
        import json

        orig = os.environ.get("TRUSTED_AGENT_RTMRS_BY_SIZE")
        try:
            os.environ["TRUSTED_AGENT_RTMRS_BY_SIZE"] = json.dumps(
                {
                    "tiny": TRUSTED_RTMRS,
                    "llm": {**TRUSTED_RTMRS, "rtmr0": "f" * 96},
                }
            )
            os.environ.pop("TRUSTED_AGENT_RTMRS", None)

            import app.storage

            importlib.reload(app.storage)

            assert app.storage.get_trusted_rtmrs("agent", node_size="tiny") == TRUSTED_RTMRS
            assert app.storage.get_trusted_rtmrs("agent", node_size="llm")["rtmr0"] == "f" * 96
            assert app.storage.get_trusted_rtmrs("agent", node_size="standard") is None
        finally:
            if orig is None:
                os.environ.pop("TRUSTED_AGENT_RTMRS_BY_SIZE", None)
            else:
                os.environ["TRUSTED_AGENT_RTMRS_BY_SIZE"] = orig
            importlib.reload(app.storage)
