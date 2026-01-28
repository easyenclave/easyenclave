"""Intel Trust Authority (ITA) integration for attestation verification."""

from __future__ import annotations

import os
from datetime import datetime

import httpx

ITA_API_URL = os.environ.get("ITA_API_URL", "https://api.trustauthority.intel.com/appraisal/v2")
ITA_API_KEY = os.environ.get("ITA_API_KEY", "")


class ITAVerificationError(Exception):
    """Raised when ITA verification fails."""

    pass


async def verify_attestation_token(token: str) -> dict:
    """
    Verify an Intel Trust Authority attestation token.

    Args:
        token: JWT token from Intel Trust Authority

    Returns:
        dict with verification results including:
        - verified: bool
        - verification_time: datetime
        - details: dict with token claims
        - error: str if verification failed

    Raises:
        ITAVerificationError: If verification request fails
    """
    if not token:
        return {
            "verified": False,
            "verification_time": datetime.utcnow(),
            "details": None,
            "error": "No attestation token provided",
        }

    if not ITA_API_KEY:
        # If no API key, we can't verify but we can decode the token
        return {
            "verified": False,
            "verification_time": datetime.utcnow(),
            "details": {"token_present": True},
            "error": "ITA_API_KEY not configured - cannot verify token",
        }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{ITA_API_URL}/verify",
                headers={
                    "Authorization": f"Bearer {ITA_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={"token": token},
                timeout=30.0,
            )

            if response.status_code == 200:
                result = response.json()
                return {
                    "verified": True,
                    "verification_time": datetime.utcnow(),
                    "details": result,
                    "error": None,
                }
            else:
                return {
                    "verified": False,
                    "verification_time": datetime.utcnow(),
                    "details": None,
                    "error": f"ITA verification failed: {response.status_code} - {response.text}",
                }

    except httpx.TimeoutException:
        return {
            "verified": False,
            "verification_time": datetime.utcnow(),
            "details": None,
            "error": "ITA verification timed out",
        }
    except Exception as e:
        return {
            "verified": False,
            "verification_time": datetime.utcnow(),
            "details": None,
            "error": f"ITA verification error: {str(e)}",
        }


def decode_token_claims(token: str) -> dict | None:
    """
    Decode JWT token claims without verification (for display purposes).

    Args:
        token: JWT token string

    Returns:
        dict of token claims or None if decoding fails
    """
    if not token:
        return None

    try:
        import base64
        import json

        # JWT format: header.payload.signature
        parts = token.split(".")
        if len(parts) != 3:
            return None

        # Decode payload (middle part)
        payload = parts[1]
        # Add padding if needed
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding

        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)

    except Exception:
        return None
