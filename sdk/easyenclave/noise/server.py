"""Noise Protocol Server for E2E Encrypted Communication.

This module implements a Noise Protocol server that provides:
1. E2E encryption terminating INSIDE the TEE (not at the host)
2. Session binding to TDX attestation (proving the channel connects to verified TEE)
3. WebSocket transport for Noise messages

Noise Pattern: NK (No client auth, Known server key)
- Client knows server's static public key (from EasyEnclave discovery)
- Server authenticates via attestation binding, not Noise auth
- Perfect for anonymous clients connecting to verified services

Security Properties:
- Forward secrecy (ephemeral keys per session)
- Identity hiding (server identity hidden from passive observers)
- Channel binding (session hash proves which TEE owns the channel)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Awaitable, Any

if TYPE_CHECKING:
    from .attestation import BoundAttestation

logger = logging.getLogger(__name__)

# Noise protocol pattern
NOISE_PROTOCOL = b"Noise_NK_25519_ChaChaPoly_SHA256"


@dataclass
class NoiseSession:
    """Active Noise session with a client.

    Wraps the NoiseConnection and provides methods for
    encrypted communication after handshake completes.
    """

    _noise: Any  # NoiseConnection
    handshake_complete: bool = False

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data for sending to client."""
        if not self.handshake_complete:
            raise RuntimeError("Handshake not complete")
        return self._noise.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data received from client."""
        if not self.handshake_complete:
            raise RuntimeError("Handshake not complete")
        return self._noise.decrypt(ciphertext)

    def get_handshake_hash(self) -> bytes:
        """Get the handshake hash for channel binding.

        This is unique to this session and can be signed
        by the binding key to prove the TEE owns this channel.
        """
        return self._noise.get_handshake_hash()

    def send_json(self, data: dict) -> bytes:
        """Encrypt and return JSON message."""
        plaintext = json.dumps(data).encode()
        return self.encrypt(plaintext)

    def recv_json(self, ciphertext: bytes) -> dict:
        """Decrypt and parse JSON message."""
        plaintext = self.decrypt(ciphertext)
        return json.loads(plaintext)


class NoiseServer:
    """Noise Protocol server with TDX attestation binding.

    This server:
    1. Generates a static keypair (published via EasyEnclave)
    2. Handles Noise NK handshakes with clients
    3. Signs session hashes with the attestation binding key
    4. Provides E2E encrypted message transport
    5. Supports attestation refresh for continuous attestation

    Usage:
        server = NoiseServer(attestation)
        pubkey = server.get_public_key()  # Publish this

        # On WebSocket connection:
        session, response = server.handshake(client_hello)
        await websocket.send_bytes(response)

        # Handle messages:
        ciphertext = await websocket.receive_bytes()
        request = session.recv_json(ciphertext)
        response = handle_request(request, session, server)
        await websocket.send_bytes(session.send_json(response))
    """

    def __init__(
        self,
        attestation: BoundAttestation,
        intel_api_key: str | None = None,
        intel_api_url: str = "https://api.trustauthority.intel.com",
    ):
        """Initialize Noise server with attestation binding.

        Args:
            attestation: BoundAttestation from attestation.generate_bound_attestation()
            intel_api_key: Intel API key for attestation refresh (optional)
            intel_api_url: Intel Trust Authority API URL
        """
        from noise.connection import Keypair

        self.attestation = attestation
        self._intel_api_key = intel_api_key
        self._intel_api_url = intel_api_url

        # Generate static Noise keypair
        self._keypair = Keypair.generate()
        logger.info(f"Noise server initialized with pubkey: {self.get_public_key()[:16]}...")

    def get_public_key(self) -> str:
        """Get hex-encoded public key for client configuration."""
        return self._keypair.public_bytes.hex()

    def get_public_key_bytes(self) -> bytes:
        """Get raw public key bytes."""
        return self._keypair.public_bytes

    def handshake(self, client_hello: bytes) -> tuple[NoiseSession, bytes]:
        """Perform Noise NK handshake with client.

        Args:
            client_hello: Initial handshake message from client

        Returns:
            Tuple of (NoiseSession, server_response_bytes)
        """
        from noise.connection import NoiseConnection, Keypair

        # Initialize Noise connection as responder
        noise = NoiseConnection.from_name(NOISE_PROTOCOL)
        noise.set_as_responder()
        noise.set_keypair_from_private_bytes(
            Keypair.STATIC,
            self._keypair.private_bytes,
        )
        noise.start_handshake()

        # Process client hello
        noise.read_message(client_hello)

        # Generate server response (completes NK handshake)
        server_response = noise.write_message()

        session = NoiseSession(_noise=noise, handshake_complete=True)
        logger.info("Noise handshake completed")

        return session, server_response

    def refresh_attestation(self) -> bool:
        """Refresh the attestation with a new TDX quote and Intel TA token.

        This is used for continuous attestation - it generates a fresh quote
        while reusing the same binding key.

        Returns:
            True if refresh successful, False otherwise

        Raises:
            RuntimeError: If intel_api_key is not configured
        """
        if not self._intel_api_key:
            raise RuntimeError("Intel API key not configured for attestation refresh")

        from .attestation import refresh_attestation

        try:
            self.attestation = refresh_attestation(
                existing_attestation=self.attestation,
                intel_api_key=self._intel_api_key,
                intel_api_url=self._intel_api_url,
            )
            logger.info("Attestation refreshed successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to refresh attestation: {e}")
            raise

    def create_attestation_response(
        self,
        session: NoiseSession,
        require_fresh: bool = False,
    ) -> dict:
        """Create attestation response with session binding.

        This binds the encrypted Noise channel to the TDX attestation:
        - session_hash is unique to this Noise session
        - signature proves this TEE (with the attested code) owns the channel
        - binding_pubkey hash is in the TDX quote's REPORTDATA

        Args:
            session: Active Noise session
            require_fresh: If True, refresh attestation before responding

        Returns:
            Attestation response dict for client verification
        """
        # Refresh attestation if requested and API key is available
        if require_fresh:
            if self._intel_api_key:
                try:
                    self.refresh_attestation()
                except Exception as e:
                    return {
                        "type": "error",
                        "payload": {"error": f"Failed to refresh attestation: {e}"},
                    }
            else:
                logger.warning("Fresh attestation requested but intel_api_key not configured")

        session_hash = session.get_handshake_hash()
        session_binding = self.attestation.create_session_binding(session_hash)

        return {
            "type": "attestation",
            "payload": {
                "quote_b64": self.attestation.quote_b64,
                "intel_ta_token": self.attestation.intel_ta_token,
                "mrtd": self.attestation.measurements.get("mrtd"),
                "measurements": self.attestation.measurements,
                "session_binding": session_binding,
                "noise_pubkey": self.get_public_key(),
            },
        }


# Type alias for message handlers
MessageHandler = Callable[[dict], Awaitable[dict]]


async def handle_noise_message(
    request: dict,
    session: NoiseSession,
    server: NoiseServer,
    handlers: dict[str, MessageHandler] | None = None,
) -> dict:
    """Handle a decrypted message from client.

    Args:
        request: Decrypted JSON request
        session: Active Noise session
        server: NoiseServer instance
        handlers: Dict of message type -> async handler function

    Returns:
        Response dict to encrypt and send
    """
    msg_type = request.get("type")
    handlers = handlers or {}

    if msg_type == "get_attestation":
        # Check if client is requesting fresh attestation
        require_fresh = request.get("require_fresh", False)
        return server.create_attestation_response(session, require_fresh=require_fresh)

    elif msg_type == "ping":
        return {"type": "pong", "payload": {}}

    elif msg_type in handlers:
        payload = request.get("payload", {})
        try:
            result = await handlers[msg_type](payload)
            return {"type": f"{msg_type}_response", "payload": result}
        except Exception as e:
            logger.exception(f"Handler error for {msg_type}")
            return {"type": "error", "payload": {"error": str(e)}}

    else:
        return {
            "type": "error",
            "payload": {"error": f"Unknown message type: {msg_type}"},
        }
