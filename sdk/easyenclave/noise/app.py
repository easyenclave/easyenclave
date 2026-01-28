"""NoiseApp - FastAPI application with built-in Noise Protocol support.

This module provides a FastAPI subclass that automatically handles:
- TDX attestation generation on startup
- Noise Protocol WebSocket endpoint at /ws/noise
- Health endpoint with noise_pubkey
- Attestation info endpoint
- Handler registration for encrypted messages

Usage:
    from easyenclave.noise import NoiseApp

    app = NoiseApp(
        title="My Service",
        intel_api_key_env="INTEL_API_KEY",
    )

    @app.noise_handler("chat")
    async def handle_chat(payload: dict) -> dict:
        # Your business logic here
        return {"response": "Hello!"}

    # The app automatically provides:
    # - GET /health - Health check with noise_pubkey
    # - GET /attestation - Attestation info
    # - WebSocket /ws/noise - Noise Protocol endpoint
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from .attestation import BoundAttestation, generate_bound_attestation
from .server import NoiseServer, NoiseSession, handle_noise_message

logger = logging.getLogger(__name__)


class NoiseApp(FastAPI):
    """FastAPI application with built-in Noise Protocol E2E encryption.

    This class extends FastAPI to provide:
    1. Automatic TDX attestation on startup
    2. Built-in /ws/noise WebSocket endpoint
    3. Handler registration via @app.noise_handler decorator
    4. Health and attestation endpoints

    Example:
        app = NoiseApp(title="My Service", intel_api_key_env="INTEL_API_KEY")

        @app.noise_handler("my_action")
        async def handle_my_action(payload: dict) -> dict:
            return {"result": "done"}
    """

    def __init__(
        self,
        title: str = "Noise Service",
        intel_api_key: str | None = None,
        intel_api_key_env: str = "INTEL_API_KEY",
        intel_api_url: str = "https://api.trustauthority.intel.com",
        **kwargs,
    ):
        """Initialize NoiseApp.

        Args:
            title: Service title for FastAPI docs
            intel_api_key: Intel Trust Authority API key (or use env)
            intel_api_key_env: Environment variable name for Intel API key
            intel_api_url: Intel Trust Authority API URL
            **kwargs: Additional FastAPI arguments
        """
        self._intel_api_key = intel_api_key
        self._intel_api_key_env = intel_api_key_env
        self._intel_api_url = intel_api_url

        # Noise state (initialized on startup)
        self._noise_server: NoiseServer | None = None
        self._attestation: BoundAttestation | None = None

        # Registered message handlers
        self._noise_handlers: dict[str, Callable[[dict], Awaitable[dict]]] = {}

        # Create lifespan context manager
        @asynccontextmanager
        async def lifespan(app: NoiseApp):
            await app._initialize_noise()
            yield

        # Initialize FastAPI with our lifespan
        super().__init__(
            title=title,
            description="E2E encrypted service via Noise Protocol",
            lifespan=lifespan,
            **kwargs,
        )

        # Register built-in endpoints
        self._register_endpoints()

    def _get_intel_api_key(self) -> str:
        """Get Intel API key from configured sources."""
        if self._intel_api_key:
            return self._intel_api_key

        key = os.getenv(self._intel_api_key_env)
        if key:
            return key

        # Try config file locations
        config_paths = ["/share/config.json", "/app/config.json"]
        for path in config_paths:
            try:
                with open(path) as f:
                    config = json.load(f)
                    key = config.get("intel_api_key")
                    if key:
                        logger.info(f"Loaded intel_api_key from {path}")
                        return key
            except Exception:
                continue

        raise RuntimeError(
            f"Intel API key not found. Set {self._intel_api_key_env} env var "
            "or mount config.json to /share"
        )

    async def _initialize_noise(self):
        """Initialize Noise server and TDX attestation."""
        intel_api_key = self._get_intel_api_key()

        self._attestation = generate_bound_attestation(
            intel_api_key=intel_api_key,
            intel_api_url=self._intel_api_url,
        )
        logger.info("TDX attestation generated successfully")

        # Pass intel_api_key to enable attestation refresh for continuous attestation
        self._noise_server = NoiseServer(
            self._attestation,
            intel_api_key=intel_api_key,
            intel_api_url=self._intel_api_url,
        )
        logger.info(f"Noise server ready, pubkey: {self._noise_server.get_public_key()[:32]}...")

    def _register_endpoints(self):
        """Register built-in HTTP and WebSocket endpoints."""

        @self.get("/health")
        async def health():
            """Health check endpoint."""
            return {
                "status": "healthy" if self._noise_server else "starting",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "noise_ready": self._noise_server is not None,
                "noise_pubkey": self._noise_server.get_public_key() if self._noise_server else None,
            }

        @self.get("/attestation")
        async def attestation():
            """Get attestation info (for discovery)."""
            if not self._attestation:
                return {"error": "Attestation not ready"}

            return {
                "service": self.title,
                "tee_type": "TDX",
                "noise_pubkey": self._noise_server.get_public_key() if self._noise_server else None,
                "mrtd": self._attestation.measurements.get("mrtd"),
                "binding_pubkey": self._attestation.binding_key.public_bytes().hex(),
                "has_intel_token": self._attestation.intel_ta_token is not None,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        @self.post("/attestation/refresh")
        async def refresh_attestation():
            """Refresh TDX attestation with new quote and Intel TA token.

            This endpoint is called by the control plane for continuous attestation.
            It generates a fresh TDX quote and obtains a new Intel TA token.

            Returns:
                Fresh attestation info including intel_ta_token
            """
            if not self._noise_server:
                return {"error": "Noise server not ready"}

            try:
                self._noise_server.refresh_attestation()
                # Update our cached attestation reference
                self._attestation = self._noise_server.attestation

                return {
                    "service": self.title,
                    "tee_type": "TDX",
                    "mrtd": self._attestation.measurements.get("mrtd"),
                    "intel_ta_token": self._attestation.intel_ta_token,
                    "binding_pubkey": self._attestation.binding_key.public_bytes().hex(),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "refreshed": True,
                }
            except Exception as e:
                logger.error(f"Failed to refresh attestation: {e}")
                return {"error": str(e), "refreshed": False}

        @self.websocket("/ws/noise")
        async def noise_websocket(websocket: WebSocket):
            """WebSocket endpoint for Noise Protocol E2E encrypted communication."""
            if not self._noise_server:
                await websocket.close(code=1011, reason="Server not ready")
                return

            await websocket.accept()
            session: NoiseSession | None = None

            try:
                # Receive handshake from client
                client_hello = await websocket.receive_bytes()
                logger.info(f"Received Noise handshake: {len(client_hello)} bytes")

                # Complete handshake
                session, server_response = self._noise_server.handshake(client_hello)
                await websocket.send_bytes(server_response)
                logger.info("Noise handshake complete, channel established")

                # Handle encrypted messages
                while True:
                    ciphertext = await websocket.receive_bytes()
                    request = session.recv_json(ciphertext)
                    logger.debug(f"Received request type: {request.get('type')}")

                    response = await handle_noise_message(
                        request=request,
                        session=session,
                        server=self._noise_server,
                        handlers=self._noise_handlers,
                    )

                    await websocket.send_bytes(session.send_json(response))

            except WebSocketDisconnect:
                logger.info("Client disconnected")
            except Exception as e:
                logger.exception(f"Noise session error: {e}")
                try:
                    if session and session.handshake_complete:
                        error_response = {"type": "error", "payload": {"error": str(e)}}
                        await websocket.send_bytes(session.send_json(error_response))
                except Exception:
                    pass
                await websocket.close(code=1011, reason=str(e))

    def noise_handler(
        self, message_type: str
    ) -> Callable[[Callable[[dict], Awaitable[dict]]], Callable[[dict], Awaitable[dict]]]:
        """Decorator to register a handler for a Noise message type.

        Example:
            @app.noise_handler("chat")
            async def handle_chat(payload: dict) -> dict:
                messages = payload.get("messages", [])
                # Process messages...
                return {"response": "Hello!"}

        Args:
            message_type: The message type to handle (e.g., "chat")

        Returns:
            Decorator function
        """

        def decorator(func: Callable[[dict], Awaitable[dict]]) -> Callable[[dict], Awaitable[dict]]:
            self._noise_handlers[message_type] = func
            logger.info(f"Registered Noise handler for '{message_type}'")
            return func

        return decorator

    @property
    def noise_server(self) -> NoiseServer | None:
        """Get the Noise server instance (for advanced usage)."""
        return self._noise_server

    @property
    def attestation(self) -> BoundAttestation | None:
        """Get the attestation instance (for advanced usage)."""
        return self._attestation
