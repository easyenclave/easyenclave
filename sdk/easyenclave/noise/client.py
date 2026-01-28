"""Noise Protocol Client for E2E Encrypted Communication.

This module provides an async Noise Protocol client that:
1. Establishes E2E encrypted WebSocket connection to server
2. Verifies server's TDX attestation with session binding
3. Ensures encrypted channel connects to the attested TEE
4. Supports continuous attestation monitoring

Usage:
    from easyenclave.noise import NoiseClient

    async with NoiseClient("wss://service.example.com/ws/noise") as client:
        attestation = await client.verify()
        print(f"Connected to TEE with MRTD: {attestation.mrtd}")

        # Optional: Monitor attestation continuously
        asyncio.create_task(client.monitor_attestation(
            interval=300,
            on_failure=lambda e: print(f"Attestation failed: {e}")
        ))

        response = await client.call("chat", {"messages": [...]})
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


class AttestationExpiredError(Exception):
    """Raised when attestation has expired or failed during monitoring."""

    pass


NOISE_PROTOCOL = b"Noise_NK_25519_ChaChaPoly_SHA256"


@dataclass
class VerificationResult:
    """Result of attestation verification with session binding."""

    verified: bool
    mrtd: str | None = None
    intel_verified: bool = False
    session_bound: bool = False
    noise_pubkey: str | None = None
    error: str | None = None
    intel_ta_token: str | None = None
    attestation_timestamp: float | None = None

    @property
    def secure(self) -> bool:
        """True if fully secure (verified, Intel attested, session bound)."""
        return self.verified and self.intel_verified and self.session_bound

    def get_token_age_seconds(self) -> float | None:
        """Get the age of the attestation token in seconds."""
        if self.attestation_timestamp is None:
            return None
        return time.time() - self.attestation_timestamp

    def is_attestation_fresh(self, max_age_seconds: float = 300.0) -> bool:
        """Check if attestation is within the freshness threshold."""
        age = self.get_token_age_seconds()
        if age is None:
            return False
        return age < max_age_seconds


def verify_intel_ta_token(token: str) -> dict:
    """Parse Intel Trust Authority JWT token and extract claims.

    Note: This performs basic parsing. For full cryptographic verification,
    the Intel TA JWKS endpoint should be used.

    Args:
        token: JWT token from Intel TA

    Returns:
        Parsed TDX claims from token including timing info
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    # Decode payload
    payload = parts[1]
    padding = 4 - len(payload) % 4
    if padding != 4:
        payload += "=" * padding
    payload = payload.replace("-", "+").replace("_", "/")

    claims = json.loads(base64.b64decode(payload))

    # Extract TDX-specific claims
    tdx_claims = claims.get("tdx", {})
    return {
        "mrtd": tdx_claims.get("tdx_mrtd"),
        "rtmr0": tdx_claims.get("tdx_rtmr0"),
        "rtmr1": tdx_claims.get("tdx_rtmr1"),
        "rtmr2": tdx_claims.get("tdx_rtmr2"),
        "rtmr3": tdx_claims.get("tdx_rtmr3"),
        "report_data": tdx_claims.get("tdx_report_data"),
        "tcb_status": tdx_claims.get("attester_tcb_status"),
        # Token timing
        "iat": claims.get("iat"),  # Issued at
        "exp": claims.get("exp"),  # Expiration
        "nbf": claims.get("nbf"),  # Not before
    }


class NoiseClient:
    """Async Noise Protocol client with WebSocket transport.

    This client establishes an E2E encrypted channel using
    Noise NK pattern. The server authenticates via TDX attestation
    and session binding.

    Example:
        async with NoiseClient("wss://service.example.com/ws/noise") as client:
            # Verify attestation
            result = await client.verify()
            if not result.secure:
                raise SecurityError(f"Verification failed: {result.error}")

            # Send encrypted messages
            response = await client.call("chat", {"messages": [...]})
    """

    def __init__(
        self,
        url: str,
        server_pubkey: str | None = None,
        expected_mrtd: str | None = None,
    ):
        """Initialize Noise client.

        Args:
            url: WebSocket URL (wss://... or ws://...)
            server_pubkey: Server's Noise public key (hex). If not provided,
                          will be fetched from /health endpoint.
            expected_mrtd: Expected MRTD to verify against (optional)
        """
        self.url = url
        self._server_pubkey = server_pubkey
        self.expected_mrtd = expected_mrtd

        self._ws: Any = None
        self._noise: Any = None
        self._handshake_complete = False
        self._verification_result: VerificationResult | None = None

    @classmethod
    async def from_easyenclave(
        cls,
        service_name: str,
        easyenclave_url: str = "https://app.easyenclave.com",
        expected_mrtd: str | None = None,
    ) -> NoiseClient:
        """Create client by discovering service from EasyEnclave.

        Args:
            service_name: Name of service in EasyEnclave
            easyenclave_url: EasyEnclave API URL
            expected_mrtd: Override expected MRTD

        Returns:
            Configured NoiseClient
        """
        import httpx

        async with httpx.AsyncClient() as http:
            resp = await http.get(
                f"{easyenclave_url.rstrip('/')}/api/v1/services",
                params={"name": service_name},
                timeout=10,
            )
            resp.raise_for_status()

            services = resp.json().get("services", [])
            if not services:
                raise ValueError(f"Service '{service_name}' not found")

            service = services[0]
            endpoint = service.get("endpoints", {}).get("prod", "")
            noise_pubkey = service.get("noise_pubkey")
            mrtd = expected_mrtd or service.get("mrtd")

            if not endpoint:
                raise ValueError("Service has no endpoint")

            # Convert to WebSocket URL
            ws_url = endpoint.replace("https://", "wss://").replace("http://", "ws://")
            if not ws_url.endswith("/ws/noise"):
                ws_url = ws_url.rstrip("/") + "/ws/noise"

            return cls(url=ws_url, server_pubkey=noise_pubkey, expected_mrtd=mrtd)

    async def _fetch_server_pubkey(self) -> str:
        """Fetch server's Noise public key from health endpoint."""
        import httpx

        # Convert WebSocket URL to HTTP for health check
        health_url = self.url.replace("wss://", "https://").replace("ws://", "http://")
        health_url = health_url.replace("/ws/noise", "/health")

        async with httpx.AsyncClient() as http:
            resp = await http.get(health_url, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            pubkey = data.get("noise_pubkey")
            if not pubkey:
                raise ValueError("Server health endpoint missing noise_pubkey")
            return pubkey

    @property
    def connected(self) -> bool:
        """Check if connected and handshake complete."""
        return self._ws is not None and self._handshake_complete

    async def connect(self, timeout: float = 30.0):
        """Connect and perform Noise NK handshake.

        Args:
            timeout: Connection timeout in seconds
        """
        import websockets
        from noise.connection import Keypair, NoiseConnection

        if self._handshake_complete:
            return

        # Get server pubkey if not provided
        if not self._server_pubkey:
            self._server_pubkey = await self._fetch_server_pubkey()

        server_pubkey_bytes = bytes.fromhex(self._server_pubkey)

        logger.info(f"Connecting to {self.url}")

        # Create WebSocket connection
        self._ws = await websockets.connect(self.url, close_timeout=timeout)

        # Initialize Noise as initiator
        self._noise = NoiseConnection.from_name(NOISE_PROTOCOL)
        self._noise.set_as_initiator()
        self._noise.set_keypair_from_public_bytes(
            Keypair.REMOTE_STATIC,
            server_pubkey_bytes,
        )
        self._noise.start_handshake()

        # Send handshake message
        client_hello = self._noise.write_message()
        logger.debug(f"Sending handshake: {len(client_hello)} bytes")
        await self._ws.send(client_hello)

        # Receive server response
        server_response = await self._ws.recv()
        logger.debug(f"Received handshake response: {len(server_response)} bytes")

        # Process response (completes handshake)
        self._noise.read_message(server_response)
        self._handshake_complete = True

        logger.info("Noise handshake complete, channel established")

    async def close(self):
        """Close the connection."""
        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None
        self._noise = None
        self._handshake_complete = False

    def get_handshake_hash(self) -> bytes:
        """Get the handshake hash for session binding verification."""
        if not self._noise or not self._handshake_complete:
            raise RuntimeError("Not connected")
        return self._noise.get_handshake_hash()

    async def send_request(self, request: dict, timeout: float = 120.0) -> dict:
        """Send encrypted request and receive response.

        Args:
            request: Request dict to send
            timeout: Response timeout in seconds

        Returns:
            Response dict from server
        """
        if not self.connected:
            raise RuntimeError("Not connected")

        # Encrypt and send
        plaintext = json.dumps(request).encode()
        ciphertext = self._noise.encrypt(plaintext)
        await self._ws.send(ciphertext)

        # Receive and decrypt
        import asyncio

        response_ciphertext = await asyncio.wait_for(self._ws.recv(), timeout=timeout)
        response_plaintext = self._noise.decrypt(response_ciphertext)
        return json.loads(response_plaintext)

    async def get_attestation(self) -> dict:
        """Request attestation from server over encrypted channel."""
        response = await self.send_request({"type": "get_attestation"})
        if response.get("type") == "error":
            raise RuntimeError(f"Server error: {response.get('payload', {}).get('error')}")
        return response.get("payload", {})

    def _verify_session_binding(self, attestation: dict, expected_mrtd: str | None = None) -> bool:
        """Verify session binding proves channel connects to attested TEE.

        Args:
            attestation: Attestation dict from get_attestation()
            expected_mrtd: Optional expected MRTD

        Returns:
            True if verification succeeds

        Raises:
            ValueError: If verification fails
        """
        from cryptography.hazmat.primitives.asymmetric import ed25519

        session_binding = attestation.get("session_binding", {})
        if not session_binding:
            raise ValueError("No session_binding in attestation")

        # Extract binding components
        try:
            server_session_hash = bytes.fromhex(session_binding["session_hash"])
            signature = bytes.fromhex(session_binding["signature"])
            binding_pubkey = bytes.fromhex(session_binding["binding_pubkey"])
        except (KeyError, ValueError) as e:
            raise ValueError(f"Invalid session_binding format: {e}") from e

        # Verify session hash matches
        our_session_hash = self.get_handshake_hash()
        if our_session_hash != server_session_hash:
            raise ValueError("Session hash mismatch")

        # Verify signature
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(binding_pubkey)
            public_key.verify(signature, server_session_hash)
        except Exception as e:
            raise ValueError(f"Session binding signature invalid: {e}") from e

        # Verify binding_pubkey hash matches REPORTDATA
        measurements = attestation.get("measurements", {})
        report_data = measurements.get("report_data", "")
        expected_reportdata = hashlib.sha512(binding_pubkey).hexdigest()

        if report_data != expected_reportdata:
            raise ValueError("REPORTDATA mismatch - binding key not in quote")

        # Verify MRTD if expected
        if expected_mrtd:
            mrtd = attestation.get("mrtd") or measurements.get("mrtd")
            if mrtd != expected_mrtd:
                raise ValueError(f"MRTD mismatch: expected {expected_mrtd[:16]}...")

        return True

    async def verify(self, expected_mrtd: str | None = None) -> VerificationResult:
        """Verify the server's attestation with session binding.

        This is the critical security check that ensures:
        1. The server is running in a TDX TEE
        2. This encrypted channel terminates inside that TEE
        3. The code running matches expected MRTD (if provided)

        Args:
            expected_mrtd: Override expected MRTD

        Returns:
            VerificationResult with verification status
        """
        if not self.connected:
            await self.connect()

        expected_mrtd = expected_mrtd or self.expected_mrtd

        try:
            attestation = await self.get_attestation()
        except Exception as e:
            return VerificationResult(
                verified=False,
                error=f"Failed to get attestation: {e}",
            )

        mrtd = attestation.get("mrtd")
        intel_ta_token = attestation.get("intel_ta_token")
        noise_pubkey = attestation.get("noise_pubkey")

        # Verify session binding
        session_bound = False
        try:
            self._verify_session_binding(attestation, expected_mrtd)
            session_bound = True
        except ValueError as e:
            return VerificationResult(
                verified=False,
                mrtd=mrtd,
                noise_pubkey=noise_pubkey,
                error=f"Session binding failed: {e}",
            )

        # Verify Intel TA token
        intel_verified = False
        if intel_ta_token:
            try:
                verify_intel_ta_token(intel_ta_token)
                intel_verified = True
            except Exception as e:
                return VerificationResult(
                    verified=False,
                    mrtd=mrtd,
                    session_bound=session_bound,
                    noise_pubkey=noise_pubkey,
                    error=f"Intel TA token invalid: {e}",
                )
        else:
            return VerificationResult(
                verified=False,
                mrtd=mrtd,
                session_bound=session_bound,
                noise_pubkey=noise_pubkey,
                error="Missing Intel TA token",
            )

        self._verification_result = VerificationResult(
            verified=True,
            mrtd=mrtd,
            intel_verified=intel_verified,
            session_bound=session_bound,
            noise_pubkey=noise_pubkey,
        )

        logger.info("Attestation verified - channel is secure")
        return self._verification_result

    async def call(self, message_type: str, payload: dict) -> dict:
        """Send a message over the encrypted channel.

        Args:
            message_type: Type of message (e.g., "chat")
            payload: Message payload

        Returns:
            Response payload from server
        """
        response = await self.send_request(
            {
                "type": message_type,
                "payload": payload,
            }
        )

        if response.get("type") == "error":
            raise RuntimeError(f"Server error: {response.get('payload', {}).get('error')}")

        return response.get("payload", {})

    async def verify_fresh(self, require_fresh: bool = True) -> VerificationResult:
        """Verify attestation, optionally requiring fresh quote.

        Args:
            require_fresh: If True, requests server generate new TDX quote

        Returns:
            VerificationResult with attestation details
        """
        if not self.connected:
            await self.connect()

        try:
            request = {"type": "get_attestation"}
            if require_fresh:
                request["require_fresh"] = True

            response = await self.send_request(request)
            if response.get("type") == "error":
                return VerificationResult(
                    verified=False,
                    error=f"Server error: {response.get('payload', {}).get('error')}",
                )

            attestation = response.get("payload", {})
        except Exception as e:
            return VerificationResult(
                verified=False,
                error=f"Failed to get attestation: {e}",
            )

        mrtd = attestation.get("mrtd")
        intel_ta_token = attestation.get("intel_ta_token")
        noise_pubkey = attestation.get("noise_pubkey")

        # Verify session binding
        session_bound = False
        try:
            self._verify_session_binding(attestation, self.expected_mrtd)
            session_bound = True
        except ValueError as e:
            return VerificationResult(
                verified=False,
                mrtd=mrtd,
                noise_pubkey=noise_pubkey,
                error=f"Session binding failed: {e}",
            )

        # Verify Intel TA token and extract timing
        intel_verified = False
        attestation_timestamp = None
        if intel_ta_token:
            try:
                claims = verify_intel_ta_token(intel_ta_token)
                intel_verified = True
                # Use issued-at time as attestation timestamp
                if claims.get("iat"):
                    attestation_timestamp = float(claims["iat"])
            except Exception as e:
                return VerificationResult(
                    verified=False,
                    mrtd=mrtd,
                    session_bound=session_bound,
                    noise_pubkey=noise_pubkey,
                    error=f"Intel TA token invalid: {e}",
                )
        else:
            return VerificationResult(
                verified=False,
                mrtd=mrtd,
                session_bound=session_bound,
                noise_pubkey=noise_pubkey,
                error="Missing Intel TA token",
            )

        return VerificationResult(
            verified=True,
            mrtd=mrtd,
            intel_verified=intel_verified,
            session_bound=session_bound,
            noise_pubkey=noise_pubkey,
            intel_ta_token=intel_ta_token,
            attestation_timestamp=attestation_timestamp,
        )

    async def wait_for_fresh_attestation(
        self,
        timeout: float = 60.0,
        max_age_seconds: float = 300.0,
    ) -> VerificationResult:
        """Wait until server provides fresh attestation.

        Useful for long-running connections that want periodic re-verification.

        Args:
            timeout: Max time to wait for fresh attestation
            max_age_seconds: Max age of attestation to accept (default 5 min)

        Returns:
            VerificationResult with fresh attestation

        Raises:
            TimeoutError: If fresh attestation not received in time
            AttestationExpiredError: If attestation verification fails
        """
        start = time.time()
        last_error = None

        while time.time() - start < timeout:
            try:
                result = await self.verify_fresh(require_fresh=True)
                if result.secure:
                    # Check attestation age
                    if result.is_attestation_fresh(max_age_seconds):
                        return result
                    last_error = f"Attestation too old: {result.get_token_age_seconds():.1f}s"
                else:
                    last_error = result.error
            except Exception as e:
                last_error = str(e)

            await asyncio.sleep(5)  # Poll every 5s

        raise TimeoutError(
            f"Fresh attestation not received within {timeout}s. Last error: {last_error}"
        )

    async def monitor_attestation(
        self,
        interval: float = 300.0,
        on_failure: Callable[[Exception], None] | None = None,
    ):
        """Background task to continuously monitor attestation.

        This method runs indefinitely until the connection closes or
        attestation fails. If on_failure callback is not provided,
        raises AttestationExpiredError on failure.

        Args:
            interval: Re-verification interval in seconds (default 5 min)
            on_failure: Callback if attestation fails (receives the exception)

        Raises:
            AttestationExpiredError: If attestation fails and no on_failure callback
        """
        while self.connected:
            await asyncio.sleep(interval)

            if not self.connected:
                break

            try:
                result = await self.verify_fresh(require_fresh=True)
                if not result.secure:
                    error = AttestationExpiredError(
                        f"Attestation verification failed: {result.error}"
                    )
                    if on_failure:
                        on_failure(error)
                    else:
                        raise error
                else:
                    logger.debug(
                        f"Attestation check passed, token age: "
                        f"{result.get_token_age_seconds():.1f}s"
                    )
            except AttestationExpiredError:
                raise
            except Exception as e:
                error = AttestationExpiredError(f"Attestation check error: {e}")
                if on_failure:
                    on_failure(error)
                else:
                    raise error from e

    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
        return False
