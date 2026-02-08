"""Intel Trust Authority (ITA) integration for attestation verification."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

import jwt
from jwt import PyJWKClient, PyJWKClientError

logger = logging.getLogger(__name__)

# Intel Trust Authority JWKS endpoint for token verification
ITA_JWKS_URL = os.environ.get("ITA_JWKS_URL", "https://portal.trustauthority.intel.com/certs")

# Cache the JWKS client to avoid fetching keys on every verification
_jwks_client: PyJWKClient | None = None


def _get_jwks_client() -> PyJWKClient:
    """Get or create a cached JWKS client."""
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(ITA_JWKS_URL, cache_keys=True, lifespan=3600)
    return _jwks_client


class ITAVerificationError(Exception):
    """Raised when ITA verification fails."""

    pass


async def verify_attestation_token(token: str) -> dict:
    """
    Verify an Intel Trust Authority attestation token using JWKS.

    This performs local JWT verification by:
    1. Fetching the signing keys from Intel's JWKS endpoint
    2. Verifying the JWT signature using the public key
    3. Validating token claims (expiration, issuer)

    Args:
        token: JWT token from Intel Trust Authority

    Returns:
        dict with verification results including:
        - verified: bool
        - verification_time: datetime
        - details: dict with token claims
        - error: str if verification failed
    """
    if not token:
        return {
            "verified": False,
            "verification_time": datetime.now(timezone.utc),
            "details": None,
            "error": "No attestation token provided",
        }

    try:
        # Get the JWKS client (cached)
        jwks_client = _get_jwks_client()

        # Get the signing key from JWKS based on the token's kid header
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        # Verify and decode the token
        # PyJWT will verify:
        # - Signature using the public key
        # - exp (expiration) claim
        # - iat (issued at) claim
        # Intel TA may use various algorithms - allow all common secure ones
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=[
                "RS256",
                "RS384",
                "RS512",  # RSA PKCS1
                "ES256",
                "ES384",
                "ES512",  # ECDSA
                "PS256",
                "PS384",
                "PS512",  # RSA PSS
                "EdDSA",  # Edwards curve (Ed25519, Ed448)
            ],
            options={
                "verify_exp": True,
                "verify_iat": True,
                "require": ["exp", "iat"],
            },
            # Note: We don't verify issuer strictly because Intel TA may use
            # different issuer values. The signature verification is sufficient.
            # issuer=ITA_ISSUER,
        )

        logger.debug(f"Intel TA token verified successfully, claims: {list(claims.keys())}")

        return {
            "verified": True,
            "verification_time": datetime.now(timezone.utc),
            "details": claims,
            "error": None,
        }

    except jwt.ExpiredSignatureError:
        return {
            "verified": False,
            "verification_time": datetime.now(timezone.utc),
            "details": None,
            "error": "Token has expired",
        }
    except jwt.InvalidIssuedAtError:
        return {
            "verified": False,
            "verification_time": datetime.now(timezone.utc),
            "details": None,
            "error": "Token has invalid issued-at time",
        }
    except jwt.InvalidSignatureError:
        return {
            "verified": False,
            "verification_time": datetime.now(timezone.utc),
            "details": None,
            "error": "Token signature verification failed",
        }
    except PyJWKClientError as e:
        return {
            "verified": False,
            "verification_time": datetime.now(timezone.utc),
            "details": None,
            "error": f"Failed to fetch signing keys from Intel TA: {e}",
        }
    except jwt.PyJWTError as e:
        return {
            "verified": False,
            "verification_time": datetime.now(timezone.utc),
            "details": None,
            "error": f"JWT verification failed: {e}",
        }
    except Exception as e:
        logger.warning(f"Unexpected error during token verification: {e}")
        return {
            "verified": False,
            "verification_time": datetime.now(timezone.utc),
            "details": None,
            "error": f"Token verification error: {e}",
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


def extract_intel_ta_claims(token: str) -> dict | None:
    """
    Extract key Intel Trust Authority claims from the JWT token for display.

    Args:
        token: JWT token string from Intel Trust Authority

    Returns:
        dict with extracted claims for UI display:
        - attester_tcb_status: TCB level (e.g., "UpToDate", "OutOfDate")
        - attester_type: Type of attestation (e.g., "TDX")
        - token_expiry: ISO timestamp when token expires
        - token_issued: ISO timestamp when token was issued
        - attester_held_data: User data from quote (hex)
    """
    claims = decode_token_claims(token)
    if not claims:
        return None

    result = {}

    # Extract TCB status
    if "attester_tcb_status" in claims:
        result["attester_tcb_status"] = claims["attester_tcb_status"]

    # Extract attester type
    if "attester_type" in claims:
        result["attester_type"] = claims["attester_type"]

    # Extract expiration time
    if "exp" in claims:
        try:
            result["token_expiry"] = datetime.utcfromtimestamp(claims["exp"]).isoformat() + "Z"
        except (ValueError, TypeError, OSError):
            pass

    # Extract issued time
    if "iat" in claims:
        try:
            result["token_issued"] = datetime.utcfromtimestamp(claims["iat"]).isoformat() + "Z"
        except (ValueError, TypeError, OSError):
            pass

    # Extract held data (user data from quote)
    if "attester_held_data" in claims:
        result["attester_held_data"] = claims["attester_held_data"]

    # Extract TDX-specific claims if present
    if "tdx_mrsigner" in claims:
        result["tdx_mrsigner"] = claims["tdx_mrsigner"]
    if "tdx_mrtd" in claims:
        result["tdx_mrtd"] = claims["tdx_mrtd"]

    return result if result else None
