"""Attestation business logic for EasyEnclave.

High-level attestation workflows: agent verification, attestation refresh,
MRTD re-verification, TDX quote generation, and attestation chain building.

Low-level JWT verification is in ita.py.
"""

from __future__ import annotations

import base64
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path

from .ita import extract_intel_ta_claims, verify_attestation_token
from .models import MrtdType, TrustedMrtd
from .storage import agent_store, trusted_mrtd_store

logger = logging.getLogger(__name__)


class AttestationError(Exception):
    """Raised when attestation verification fails."""

    def __init__(self, detail: str, status_code: int = 403):
        self.detail = detail
        self.status_code = status_code
        super().__init__(detail)


@dataclass
class AgentVerificationResult:
    """Result of verifying an agent's attestation during registration."""

    mrtd: str
    intel_ta_token: str
    trusted_mrtd_info: TrustedMrtd


@dataclass
class TdxQuoteResult:
    """Result of generating a TDX quote."""

    quote_b64: str | None = None
    measurements: dict[str, str] | None = None
    error: str | None = None


def extract_intel_ta_token(attestation: dict) -> str | None:
    """Extract Intel TA token from attestation dict."""
    return attestation.get("tdx", {}).get("intel_ta_token")


def extract_mrtd_from_claims(ita_claims: dict) -> str:
    """Extract MRTD from verified Intel TA claims.

    Tries top-level 'tdx_mrtd' first, then falls back to nested 'tdx.tdx_mrtd'.
    Returns empty string if not found.
    """
    mrtd = ita_claims.get("tdx_mrtd", "")
    if not mrtd:
        tdx_claims = ita_claims.get("tdx", {})
        mrtd = tdx_claims.get("tdx_mrtd", "")
    return mrtd


async def verify_agent_registration(attestation: dict) -> AgentVerificationResult:
    """Verify agent attestation during registration.

    Steps:
    1. Extract and verify Intel TA token
    2. Extract MRTD from verified claims
    3. Check MRTD against trusted list (must be type 'agent' or 'proxy')

    Raises:
        AttestationError: If any verification step fails.
    """
    # Step 1: Extract and verify Intel TA token
    intel_ta_token = extract_intel_ta_token(attestation)
    if not intel_ta_token:
        raise AttestationError(
            detail="Registration requires Intel Trust Authority token",
            status_code=400,
        )

    try:
        ita_result = await verify_attestation_token(intel_ta_token)
        if not ita_result["verified"]:
            raise AttestationError(
                detail=f"Intel TA verification failed: {ita_result.get('error', 'unknown')}",
            )
    except AttestationError:
        raise
    except Exception as e:
        raise AttestationError(
            detail=f"Intel TA verification error: {e}",
        ) from e

    # Step 2: Extract MRTD from verified claims
    ita_claims = ita_result.get("details", {})
    mrtd = extract_mrtd_from_claims(ita_claims)

    if not mrtd:
        raise AttestationError(
            detail="Intel TA token does not contain MRTD claim",
        )

    # Step 3: Check MRTD against trusted list
    trusted_mrtd_info = trusted_mrtd_store.get(mrtd)
    if not trusted_mrtd_info or not trusted_mrtd_info.active:
        raise AttestationError(
            detail=f"MRTD from Intel TA not in trusted list: {mrtd[:32]}...",
        )

    if trusted_mrtd_info.type not in (MrtdType.AGENT, MrtdType.PROXY):
        raise AttestationError(
            detail=f"MRTD is type '{trusted_mrtd_info.type}', not 'agent' or 'proxy'",
        )

    return AgentVerificationResult(
        mrtd=mrtd,
        intel_ta_token=intel_ta_token,
        trusted_mrtd_info=trusted_mrtd_info,
    )


async def refresh_agent_attestation(agent_id: str, attestation: dict) -> bool:
    """Refresh an agent's attestation during background health checks.

    Extracts Intel TA token, verifies it, and updates the agent store.
    Returns True on success, False on failure. Never raises.
    """
    intel_ta_token = extract_intel_ta_token(attestation)
    if not intel_ta_token:
        return False

    try:
        result = await verify_attestation_token(intel_ta_token)
        if result["verified"]:
            agent_store.update_attestation(
                agent_id,
                intel_ta_token=intel_ta_token,
                verified=True,
            )
            logger.debug(f"Agent {agent_id} attestation refreshed")
            return True
        else:
            logger.warning(f"Agent {agent_id} attestation failed: {result.get('error')}")
            agent_store.update_attestation(
                agent_id,
                intel_ta_token=intel_ta_token,
                verified=False,
                error=result.get("error"),
            )
            return False
    except Exception as e:
        logger.warning(f"Failed to verify attestation for {agent_id}: {e}")
        return False


def reverify_agents_for_mrtd(mrtd: str, verified: bool, error: str | None = None) -> list[str]:
    """Update verification status for all agents matching a given MRTD.

    Returns list of agent_ids that were updated.
    """
    updated = []
    for agent in agent_store.list():
        if agent.mrtd == mrtd:
            if verified and not agent.verified:
                agent_store.set_verified(agent.agent_id, True)
                updated.append(agent.agent_id)
            elif not verified and agent.verified:
                agent_store.set_verified(agent.agent_id, False, error=error)
                updated.append(agent.agent_id)
    return updated


def generate_tdx_quote(nonce: str | None = None) -> TdxQuoteResult:
    """Generate a TDX quote via the TSM kernel interface.

    Returns a TdxQuoteResult with either quote_b64+measurements or error.
    """
    TSM_REPORT_PATH = Path("/sys/kernel/config/tsm/report")

    if not TSM_REPORT_PATH.exists():
        return TdxQuoteResult(error="TDX not available (control plane not in TEE)")

    try:
        report_id = f"quote_{os.getpid()}_{int(time.time())}"
        report_dir = TSM_REPORT_PATH / report_id

        report_dir.mkdir()
        try:
            # Prepare user data (nonce)
            if nonce:
                inblob = nonce.encode().ljust(64, b"\0")[:64]
            else:
                inblob = b"\0" * 64
            (report_dir / "inblob").write_bytes(inblob)

            # Read generated quote
            quote = (report_dir / "outblob").read_bytes()
            quote_b64 = base64.b64encode(quote).decode()

            # Parse measurements from quote
            measurements = {}
            if len(quote) >= 584:
                td_report_offset = 48
                measurements["mrtd"] = quote[td_report_offset + 136 : td_report_offset + 184].hex()
                measurements["rtmr0"] = quote[td_report_offset + 328 : td_report_offset + 376].hex()
                measurements["rtmr1"] = quote[td_report_offset + 376 : td_report_offset + 424].hex()
                measurements["rtmr2"] = quote[td_report_offset + 424 : td_report_offset + 472].hex()
                measurements["rtmr3"] = quote[td_report_offset + 472 : td_report_offset + 520].hex()

            return TdxQuoteResult(quote_b64=quote_b64, measurements=measurements)

        finally:
            if report_dir.exists():
                report_dir.rmdir()

    except Exception as e:
        logger.warning(f"TDX attestation generation failed: {e}")
        return TdxQuoteResult(error=f"TDX attestation failed: {e}")


async def build_attestation_chain(agent) -> dict:
    """Build the full attestation chain for an agent.

    Looks up trusted MRTD for GitHub source metadata, re-verifies Intel TA
    token (may be expired), and extracts claims for UI display.

    Returns a dict with the complete attestation chain.
    """
    # Get trusted MRTD info for GitHub attestation
    github_attestation = None
    trusted_mrtd = trusted_mrtd_store.get(agent.mrtd) if agent.mrtd else None
    if trusted_mrtd:
        github_attestation = {
            "source_repo": trusted_mrtd.source_repo,
            "source_commit": trusted_mrtd.source_commit,
            "source_tag": trusted_mrtd.source_tag,
            "build_workflow": trusted_mrtd.build_workflow,
            "image_digest": trusted_mrtd.image_digest,
            "image_version": trusted_mrtd.image_version,
            "description": trusted_mrtd.description,
            "attestation_url": trusted_mrtd.attestation_url,
        }

    # Verify Intel TA token if present
    intel_ta_verified = False
    intel_ta_details = None
    intel_ta_claims = None
    if agent.intel_ta_token:
        try:
            ita_result = await verify_attestation_token(agent.intel_ta_token)
            intel_ta_verified = ita_result["verified"]
            intel_ta_details = ita_result.get("details")
            # Extract key claims for UI display
            intel_ta_claims = extract_intel_ta_claims(agent.intel_ta_token)
        except Exception as e:
            intel_ta_details = {"error": str(e)}

    # Note: We do NOT un-verify the agent if the Intel TA token has expired.
    # The token's expiry (typically 5 minutes) is a limitation of the JWT format,
    # not an indication that the attestation is invalid. Once an agent is verified
    # at registration time, it remains verified. The intel_ta_verified field below
    # indicates whether the token can still be cryptographically verified now.

    return {
        "agent_id": agent.agent_id,
        "vm_name": agent.vm_name,
        "mrtd": agent.mrtd,
        "verified": agent.verified,
        "verification_error": agent.verification_error,
        "intel_ta_verified": intel_ta_verified,
        "intel_ta_details": intel_ta_details,
        "intel_ta_claims": intel_ta_claims,
        "github_attestation": github_attestation,
        "hostname": agent.hostname,
        "tunnel_id": agent.tunnel_id,
        "registered_at": agent.registered_at.isoformat(),
    }
