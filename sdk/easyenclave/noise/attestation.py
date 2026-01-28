"""TDX Attestation with Binding Key Derivation.

This module provides TDX attestation generation with cryptographic binding
to a session key. The binding key is included in the TDX quote's REPORTDATA
field, cryptographically proving that the key belongs to this specific TEE.

Security Flow:
1. Generate ephemeral Ed25519 keypair (binding key)
2. Hash the public key to get 64-byte REPORTDATA
3. Generate TDX quote with REPORTDATA containing the pubkey hash
4. Get Intel Trust Authority attestation token
5. Now the binding key is cryptographically bound to this attestation

When clients verify, they:
1. Check Intel TA token is valid
2. Extract REPORTDATA from the quote
3. Verify REPORTDATA matches hash of binding_pubkey
4. Verify session_binding signature was made by binding_pubkey
5. This proves the session connects to the attested TEE
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

TSM_REPORT_PATH = Path("/sys/kernel/config/tsm/report")


@dataclass
class BindingKeyPair:
    """Ed25519 keypair for session binding.

    This keypair is used to cryptographically bind Noise sessions to
    TDX attestation. The public key hash is included in the TDX quote's
    REPORTDATA field.
    """

    _private_key: Any = field(repr=False)
    _public_key: Any = field(repr=False)

    @classmethod
    def generate(cls) -> BindingKeyPair:
        """Generate new Ed25519 keypair."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return cls(_private_key=private_key, _public_key=public_key)

    def public_bytes(self) -> bytes:
        """Get raw public key bytes (32 bytes)."""
        from cryptography.hazmat.primitives import serialization

        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, data: bytes) -> bytes:
        """Sign data with private key."""
        return self._private_key.sign(data)

    @staticmethod
    def verify(signature: bytes, data: bytes, public_key_bytes: bytes) -> bool:
        """Verify signature using raw public key bytes."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature, data)
            return True
        except Exception:
            return False


def hash_pubkey_for_reportdata(pubkey: bytes) -> bytes:
    """Hash public key to create REPORTDATA.

    REPORTDATA is 64 bytes. We use SHA-512 of the public key
    to fill this completely.
    """
    return hashlib.sha512(pubkey).digest()


def generate_tdx_quote(user_data: bytes | None = None) -> bytes:
    """Generate TDX quote via ConfigFS-TSM interface.

    Args:
        user_data: 64 bytes to include in REPORTDATA field.
                   If None, uses zeros. If shorter, pads with zeros.

    Returns:
        Raw TDX quote bytes

    Raises:
        RuntimeError: If TDX is not available
    """
    if not TSM_REPORT_PATH.exists():
        raise RuntimeError(f"TDX not available: {TSM_REPORT_PATH} does not exist")

    report_id = f"quote_{os.getpid()}_{int(time.time())}"
    report_dir = TSM_REPORT_PATH / report_id

    try:
        report_dir.mkdir()

        # Prepare REPORTDATA (64 bytes)
        if user_data:
            inblob = user_data.ljust(64, b"\0")[:64]
        else:
            inblob = b"\0" * 64
        (report_dir / "inblob").write_bytes(inblob)

        # Read generated quote
        quote = (report_dir / "outblob").read_bytes()
        return quote
    finally:
        if report_dir.exists():
            report_dir.rmdir()


def parse_tdx_quote(quote: bytes) -> dict:
    """Parse TDX quote binary structure to extract measurements.

    Args:
        quote: Raw TDX quote bytes

    Returns:
        Dictionary with extracted measurements
    """
    import struct

    # Minimum TDX quote size (header + TD report)
    if len(quote) < 584:
        return {"error": "Quote too short"}

    # TDX Quote structure:
    # Header: 48 bytes
    # TD Report: 584 bytes starting at offset 48
    td_report_offset = 48

    result = {
        "quote_size": len(quote),
        "version": struct.unpack("<H", quote[0:2])[0],
    }

    # Extract TEE_TCB_SVN (16 bytes at offset 0 of TD Report)
    result["tee_tcb_svn"] = quote[td_report_offset : td_report_offset + 16].hex()

    # MRSEAM (48 bytes at offset 16)
    result["mrseam"] = quote[td_report_offset + 16 : td_report_offset + 64].hex()

    # MRSIGNERSEAM (48 bytes at offset 64)
    result["mrsigner_seam"] = quote[td_report_offset + 64 : td_report_offset + 112].hex()

    # TDATTRIBUTES (8 bytes at offset 120)
    result["td_attributes"] = quote[td_report_offset + 120 : td_report_offset + 128].hex()

    # MRTD (48 bytes at offset 136) - This is the key measurement
    result["mrtd"] = quote[td_report_offset + 136 : td_report_offset + 184].hex()

    # MRCONFIGID (48 bytes at offset 184)
    result["mr_config_id"] = quote[td_report_offset + 184 : td_report_offset + 232].hex()

    # RTMR0-3 (48 bytes each, starting at offset 328)
    for i in range(4):
        offset = td_report_offset + 328 + (i * 48)
        result[f"rtmr{i}"] = quote[offset : offset + 48].hex()

    # REPORTDATA (64 bytes at offset 520)
    result["report_data"] = quote[td_report_offset + 520 : td_report_offset + 584].hex()

    return result


def call_intel_trust_authority(quote_b64: str, api_key: str, api_url: str) -> dict:
    """Submit quote to Intel Trust Authority and get JWT.

    Args:
        quote_b64: Base64-encoded TDX quote
        api_key: Intel Trust Authority API key
        api_url: Intel Trust Authority API URL

    Returns:
        Response dict containing the attestation token
    """
    import requests

    response = requests.post(
        f"{api_url}/appraisal/v1/attest",
        headers={
            "x-api-key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        json={"quote": quote_b64},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def parse_jwt_claims(jwt_token: str) -> dict:
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
    except Exception as e:
        logger.warning(f"Could not parse JWT claims: {e}")
        return {}


@dataclass
class BoundAttestation:
    """TDX attestation with bound key for session binding.

    This is the key security primitive - the binding_key is
    cryptographically bound to this specific TEE instance via
    the REPORTDATA field in the TDX quote.
    """

    binding_key: BindingKeyPair
    quote_b64: str
    measurements: dict
    intel_ta_token: str | None = None
    verified_measurements: dict | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "binding_pubkey": self.binding_key.public_bytes().hex(),
            "quote_b64": self.quote_b64,
            "measurements": self.measurements,
            "intel_ta_token": self.intel_ta_token,
            "verified_measurements": self.verified_measurements,
        }

    def sign_session_hash(self, session_hash: bytes) -> bytes:
        """Sign the Noise session hash to create session binding.

        This proves that the encrypted channel connects to this
        specific attested TEE - the one that generated this quote
        with our binding_pubkey in REPORTDATA.
        """
        return self.binding_key.sign(session_hash)

    def create_session_binding(self, session_hash: bytes) -> dict:
        """Create session binding proof.

        Returns:
            Dict with session_hash, signature, and binding_pubkey
            for client verification
        """
        signature = self.sign_session_hash(session_hash)
        return {
            "session_hash": session_hash.hex(),
            "signature": signature.hex(),
            "binding_pubkey": self.binding_key.public_bytes().hex(),
        }


def generate_bound_attestation(
    intel_api_key: str,
    intel_api_url: str = "https://api.trustauthority.intel.com",
) -> BoundAttestation:
    """Generate TDX attestation with bound key for session binding.

    This is called once at server startup. The binding key is
    then used to sign session hashes, proving E2E encryption
    terminates inside this specific TEE.

    Args:
        intel_api_key: Intel TA API key (required)
        intel_api_url: Intel Trust Authority API URL

    Returns:
        BoundAttestation with key bound to TDX quote

    Raises:
        RuntimeError: If TDX quote generation or Intel TA verification fails
    """
    if not intel_api_key:
        raise RuntimeError("INTEL_API_KEY is required for attestation")

    logger.info("Generating bound attestation...")

    # Step 1: Generate binding keypair
    binding_key = BindingKeyPair.generate()
    pubkey_bytes = binding_key.public_bytes()
    logger.info(f"Generated binding key: {pubkey_bytes.hex()[:16]}...")

    # Step 2: Hash pubkey for REPORTDATA
    reportdata = hash_pubkey_for_reportdata(pubkey_bytes)
    logger.info(f"REPORTDATA (pubkey hash): {reportdata.hex()[:16]}...")

    # Step 3: Generate TDX quote with REPORTDATA
    quote = generate_tdx_quote(user_data=reportdata)
    quote_b64 = base64.b64encode(quote).decode()
    logger.info(f"Generated TDX quote: {len(quote)} bytes")

    # Step 4: Parse local measurements
    measurements = parse_tdx_quote(quote)
    logger.info(f"MRTD: {measurements.get('mrtd', 'unknown')[:16]}...")

    # Step 5: Call Intel TA (required)
    logger.info("Calling Intel Trust Authority...")
    response = call_intel_trust_authority(quote_b64, intel_api_key, intel_api_url)
    intel_ta_token = response.get("token")
    if not intel_ta_token:
        raise RuntimeError("Intel TA did not return attestation token")

    verified_measurements = parse_jwt_claims(intel_ta_token)
    logger.info("Intel TA attestation successful")

    return BoundAttestation(
        binding_key=binding_key,
        quote_b64=quote_b64,
        measurements=measurements,
        intel_ta_token=intel_ta_token,
        verified_measurements=verified_measurements,
    )


def refresh_attestation(
    existing_attestation: BoundAttestation,
    intel_api_key: str,
    intel_api_url: str = "https://api.trustauthority.intel.com",
) -> BoundAttestation:
    """Refresh attestation with a new TDX quote and Intel TA token.

    This reuses the existing binding key but generates a fresh TDX quote
    and gets a new Intel TA token. This is used for continuous attestation.

    Args:
        existing_attestation: The current attestation to refresh
        intel_api_key: Intel TA API key
        intel_api_url: Intel Trust Authority API URL

    Returns:
        New BoundAttestation with fresh quote and token

    Raises:
        RuntimeError: If quote generation or Intel TA verification fails
    """
    if not intel_api_key:
        raise RuntimeError("INTEL_API_KEY is required for attestation refresh")

    logger.info("Refreshing attestation with new TDX quote...")

    # Reuse the existing binding key
    binding_key = existing_attestation.binding_key
    pubkey_bytes = binding_key.public_bytes()

    # Hash pubkey for REPORTDATA (same as initial)
    reportdata = hash_pubkey_for_reportdata(pubkey_bytes)

    # Generate fresh TDX quote
    quote = generate_tdx_quote(user_data=reportdata)
    quote_b64 = base64.b64encode(quote).decode()
    logger.info(f"Generated fresh TDX quote: {len(quote)} bytes")

    # Parse local measurements
    measurements = parse_tdx_quote(quote)
    logger.info(f"MRTD: {measurements.get('mrtd', 'unknown')[:16]}...")

    # Call Intel TA for fresh token
    logger.info("Calling Intel Trust Authority for fresh token...")
    response = call_intel_trust_authority(quote_b64, intel_api_key, intel_api_url)
    intel_ta_token = response.get("token")
    if not intel_ta_token:
        raise RuntimeError("Intel TA did not return attestation token")

    verified_measurements = parse_jwt_claims(intel_ta_token)
    logger.info("Intel TA attestation refresh successful")

    return BoundAttestation(
        binding_key=binding_key,
        quote_b64=quote_b64,
        measurements=measurements,
        intel_ta_token=intel_ta_token,
        verified_measurements=verified_measurements,
    )
