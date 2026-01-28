"""TDX quote verification for EasyEnclave SDK.

This module provides functions to verify TDX quotes from the control plane.
Verification ensures the control plane is running in a TDX trusted execution
environment with a known measurement (MRTD).

Verification options:
1. Local verification - Parse quote and extract measurements
2. Intel Trust Authority - Submit quote to Intel's attestation service
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass


class VerificationError(Exception):
    """Raised when TDX quote verification fails."""

    pass


@dataclass
class TDXMeasurements:
    """TDX measurements extracted from a quote."""

    mrtd: str
    rtmr0: str
    rtmr1: str
    rtmr2: str
    rtmr3: str
    report_data: str | None = None


@dataclass
class VerificationResult:
    """Result of TDX quote verification."""

    verified: bool
    measurements: TDXMeasurements | None = None
    error: str | None = None
    intel_ta_verified: bool = False
    intel_ta_token: str | None = None


def parse_tdx_quote(quote_b64: str) -> TDXMeasurements:
    """Parse a TDX quote to extract measurements.

    Args:
        quote_b64: Base64-encoded TDX quote

    Returns:
        TDXMeasurements with extracted values

    Raises:
        VerificationError: If quote is invalid or too short
    """
    try:
        quote = base64.b64decode(quote_b64)
    except Exception as e:
        raise VerificationError(f"Invalid base64 quote: {e}") from e

    # Minimum TDX quote size (header + TD report)
    if len(quote) < 584:
        raise VerificationError(f"Quote too short: {len(quote)} bytes (need >= 584)")

    # TDX Quote structure:
    # Header: 48 bytes
    # TD Report: 584 bytes starting at offset 48
    td_report_offset = 48

    # MRTD (48 bytes at offset 136 within TD report)
    mrtd = quote[td_report_offset + 136 : td_report_offset + 184].hex()

    # RTMR0-3 (48 bytes each, starting at offset 328)
    rtmr0 = quote[td_report_offset + 328 : td_report_offset + 376].hex()
    rtmr1 = quote[td_report_offset + 376 : td_report_offset + 424].hex()
    rtmr2 = quote[td_report_offset + 424 : td_report_offset + 472].hex()
    rtmr3 = quote[td_report_offset + 472 : td_report_offset + 520].hex()

    # REPORTDATA (64 bytes at offset 520)
    report_data = quote[td_report_offset + 520 : td_report_offset + 584].hex()

    return TDXMeasurements(
        mrtd=mrtd,
        rtmr0=rtmr0,
        rtmr1=rtmr1,
        rtmr2=rtmr2,
        rtmr3=rtmr3,
        report_data=report_data,
    )


def verify_nonce_in_report_data(report_data: str, nonce: str) -> bool:
    """Verify that the nonce is present in the report data.

    Args:
        report_data: Hex-encoded report data from quote
        nonce: Expected nonce string

    Returns:
        True if nonce is present in report data
    """
    if not nonce:
        return True

    try:
        # Report data is padded to 64 bytes with null bytes
        report_bytes = bytes.fromhex(report_data)
        nonce_bytes = nonce.encode()

        # Check if nonce is at the start of report data
        return report_bytes.startswith(nonce_bytes)
    except Exception:
        return False


def verify_quote_local(
    quote_b64: str,
    nonce: str | None = None,
    expected_mrtd: str | None = None,
) -> VerificationResult:
    """Verify a TDX quote locally (without Intel Trust Authority).

    This performs basic verification by parsing the quote and optionally
    checking the MRTD against an expected value. For full cryptographic
    verification, use verify_quote_with_intel_ta().

    Args:
        quote_b64: Base64-encoded TDX quote
        nonce: Expected nonce in report_data (optional)
        expected_mrtd: Expected MRTD value to match (optional)

    Returns:
        VerificationResult with measurements and status
    """
    try:
        measurements = parse_tdx_quote(quote_b64)
    except VerificationError as e:
        return VerificationResult(verified=False, error=str(e))

    # Verify nonce if provided
    if nonce and measurements.report_data:
        if not verify_nonce_in_report_data(measurements.report_data, nonce):
            return VerificationResult(
                verified=False,
                measurements=measurements,
                error="Nonce mismatch in report data",
            )

    # Verify MRTD if expected value provided
    if expected_mrtd:
        if measurements.mrtd != expected_mrtd:
            return VerificationResult(
                verified=False,
                measurements=measurements,
                error=f"MRTD mismatch: got {measurements.mrtd[:16]}... expected {expected_mrtd[:16]}...",
            )

    return VerificationResult(
        verified=True,
        measurements=measurements,
    )


async def verify_quote_with_intel_ta(
    quote_b64: str,
    api_key: str,
    api_url: str = "https://api.trustauthority.intel.com",
    nonce: str | None = None,
    expected_mrtd: str | None = None,
) -> VerificationResult:
    """Verify a TDX quote using Intel Trust Authority.

    This provides full cryptographic verification of the quote through
    Intel's attestation service.

    Args:
        quote_b64: Base64-encoded TDX quote
        api_key: Intel Trust Authority API key
        api_url: Intel Trust Authority API URL
        nonce: Expected nonce in report_data (optional)
        expected_mrtd: Expected MRTD value to match (optional)

    Returns:
        VerificationResult with Intel TA verification status
    """
    import httpx

    # First do local parsing
    try:
        measurements = parse_tdx_quote(quote_b64)
    except VerificationError as e:
        return VerificationResult(verified=False, error=str(e))

    # Verify nonce locally
    if nonce and measurements.report_data:
        if not verify_nonce_in_report_data(measurements.report_data, nonce):
            return VerificationResult(
                verified=False,
                measurements=measurements,
                error="Nonce mismatch in report data",
            )

    # Call Intel Trust Authority
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{api_url}/appraisal/v1/attest",
                headers={
                    "x-api-key": api_key,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                json={"quote": quote_b64},
            )
            response.raise_for_status()
            ita_response = response.json()

            # Extract token
            token = ita_response.get("token")
            if not token:
                return VerificationResult(
                    verified=False,
                    measurements=measurements,
                    error="No token in Intel TA response",
                )

            # Parse JWT to extract verified measurements
            jwt_measurements = _parse_jwt_claims(token)

            # Verify MRTD from JWT matches expected
            if expected_mrtd:
                jwt_mrtd = jwt_measurements.get("mrtd", "")
                if jwt_mrtd != expected_mrtd:
                    return VerificationResult(
                        verified=False,
                        measurements=measurements,
                        intel_ta_verified=True,
                        intel_ta_token=token,
                        error=f"MRTD mismatch: got {jwt_mrtd[:16]}... expected {expected_mrtd[:16]}...",
                    )

            return VerificationResult(
                verified=True,
                measurements=measurements,
                intel_ta_verified=True,
                intel_ta_token=token,
            )

    except httpx.HTTPStatusError as e:
        return VerificationResult(
            verified=False,
            measurements=measurements,
            error=f"Intel TA request failed: HTTP {e.response.status_code}",
        )
    except Exception as e:
        return VerificationResult(
            verified=False,
            measurements=measurements,
            error=f"Intel TA verification error: {e}",
        )


def _parse_jwt_claims(jwt_token: str) -> dict:
    """Parse JWT to extract TDX measurements from claims."""
    parts = jwt_token.split(".")
    if len(parts) != 3:
        return {}

    # Decode payload (middle part)
    payload = parts[1]
    # Add padding if needed
    padding = 4 - len(payload) % 4
    if padding != 4:
        payload += "=" * padding
    # Handle URL-safe base64
    payload = payload.replace("-", "+").replace("_", "/")

    try:
        claims = json.loads(base64.b64decode(payload))
        tdx = claims.get("tdx", {})
        return {
            "mrtd": tdx.get("tdx_mrtd"),
            "rtmr0": tdx.get("tdx_rtmr0"),
            "rtmr1": tdx.get("tdx_rtmr1"),
            "rtmr2": tdx.get("tdx_rtmr2"),
            "rtmr3": tdx.get("tdx_rtmr3"),
            "report_data": tdx.get("tdx_report_data"),
            "attester_tcb_status": tdx.get("attester_tcb_status"),
        }
    except Exception:
        return {}
