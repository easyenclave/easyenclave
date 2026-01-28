"""EasyEnclave Noise Protocol library for E2E encrypted TEE communication.

This module provides reusable components for building applications with:
- End-to-end encryption via Noise Protocol (NK pattern)
- TDX attestation with session binding
- Cryptographic proof that encrypted channels connect to verified TEEs

Server-side usage:
    from easyenclave.noise import NoiseApp

    app = NoiseApp(title="My Service", intel_api_key_env="INTEL_API_KEY")

    @app.noise_handler("my_action")
    async def handle_my_action(payload: dict) -> dict:
        return {"result": "processed"}

Client-side usage:
    from easyenclave.noise import NoiseClient

    async with NoiseClient("wss://service.example.com/ws/noise") as client:
        attestation = await client.verify()
        print(f"Connected to TEE with MRTD: {attestation.mrtd}")
        response = await client.call("my_action", {"data": "value"})
"""

from .app import NoiseApp
from .attestation import (
    BindingKeyPair,
    BoundAttestation,
    generate_bound_attestation,
    generate_tdx_quote,
    hash_pubkey_for_reportdata,
    parse_tdx_quote,
    refresh_attestation,
)
from .client import (
    AttestationExpiredError,
    NoiseClient,
    VerificationResult,
    verify_intel_ta_token,
)
from .server import (
    NOISE_PROTOCOL,
    NoiseServer,
    NoiseSession,
)

__all__ = [
    # Attestation
    "BindingKeyPair",
    "BoundAttestation",
    "generate_bound_attestation",
    "generate_tdx_quote",
    "hash_pubkey_for_reportdata",
    "parse_tdx_quote",
    "refresh_attestation",
    # Server
    "NOISE_PROTOCOL",
    "NoiseServer",
    "NoiseSession",
    # App
    "NoiseApp",
    # Client
    "AttestationExpiredError",
    "NoiseClient",
    "VerificationResult",
    "verify_intel_ta_token",
]
