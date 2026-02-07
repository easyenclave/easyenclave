"""Tests for RTMR extraction, drift detection, and backfill."""

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
